using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Identity;

namespace TheKrystalShip.KGSM.Auth.Cluster.Tests;

/// <summary>
/// One member acting on another for somebody who is not signed in to it.
/// </summary>
/// <remarks>
/// Every branch here is a way somebody is either let in wrongly or locked out wrongly, so each refusal
/// is pinned rather than the success alone. The property the whole scheme rests on — that a caller
/// asserts who and never what — is only observable as the absence of any input that could raise a
/// tier, so the tier the resolver returns is asserted against the store on every passing case.
/// </remarks>
public class MemberActingResolverTests
{
    private const string Handle = "discord:245717107596197888";

    [Fact]
    public async Task A_member_acts_for_a_person_at_the_tier_this_member_holds_for_them()
    {
        MemberActingResult result = await Resolve(person: Person(KgsmTier.Operator));

        Assert.True(result.Succeeded);
        Assert.Equal(MemberActingRefusal.None, result.Refusal);
        Assert.Equal(Handle, result.Handle);
        Assert.Equal("hotrod-assistant", result.ActingMember);
        Assert.Equal(KgsmTier.Operator, result.Person!.Tier);
    }

    [Fact]
    public async Task The_tier_comes_from_this_members_own_accounts()
    {
        // The same caller, the same handle, a different store: nothing the caller sends can move this.
        MemberActingResult viewer = await Resolve(person: Person(KgsmTier.Viewer));
        MemberActingResult admin = await Resolve(person: Person(KgsmTier.Admin));

        Assert.Equal(KgsmTier.Viewer, viewer.Person!.Tier);
        Assert.Equal(KgsmTier.Admin, admin.Person!.Tier);
    }

    [Fact]
    public async Task A_call_with_no_member_token_is_not_a_member()
    {
        MemberActingResult result = await Resolve(person: Person(), token: null);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.NoToken, result.Refusal);
    }

    [Fact]
    public async Task A_token_this_member_cannot_validate_is_refused()
    {
        MemberActingResult result = await Resolve(person: Person(), validates: false);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.TokenNotValid, result.Refusal);
    }

    [Fact]
    public async Task A_disabled_member_may_act_for_nobody()
    {
        // The one local override to the shared-secret trust boundary: a good token is not enough.
        MemberActingResult result = await Resolve(person: Person(), memberEnabled: false);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.MemberDisabled, result.Refusal);
        // Named even in refusal, so an operator has something to look at rather than a bare rejection.
        Assert.Equal("hotrod-assistant", result.ActingMember);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("245717107596197888")]
    public async Task An_unqualified_handle_names_nobody(string handle)
    {
        // A bare subject is the shape the old relay sent, and reading one as a provider's would
        // attribute a person to whichever provider the receiver happened to assume.
        MemberActingResult result = await Resolve(person: Person(), handle: handle);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.HandleNotQualified, result.Refusal);
    }

    [Fact]
    public async Task A_person_this_member_has_never_heard_of_is_refused_rather_than_invented()
    {
        MemberActingResult result = await Resolve(person: null);

        Assert.False(result.Succeeded);
        // Its own reason, because this is what a username collision looks like from the far end and it
        // has to be findable in a log without matching on a sentence.
        Assert.Equal(MemberActingRefusal.NoSuchAccount, result.Refusal);
        Assert.Equal("hotrod-assistant", result.ActingMember);
        Assert.Equal(Handle, result.Handle);
    }

    [Fact]
    public async Task A_disabled_account_cannot_be_acted_for()
    {
        MemberActingResult result = await Resolve(person: Person(status: UserStatus.Disabled));

        Assert.False(result.Succeeded);
        // Distinct from a disabled MEMBER: one is a person, the other is a machine, and a log that
        // could not tell them apart would send somebody looking in the wrong place.
        Assert.Equal(MemberActingRefusal.AccountDisabled, result.Refusal);
    }

    [Fact]
    public async Task An_unreadable_store_refuses_and_says_so_rather_than_denying_the_person()
    {
        // An outage is not a denial: the refusal names the store, so nobody is told they lost
        // authority they still hold.
        MemberActingResult result = await Resolve(person: null, storeAvailable: false);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.AccountsUnavailable, result.Refusal);
        Assert.NotEqual(MemberActingRefusal.NoSuchAccount, result.Refusal);
    }

    private static KgsmUser Person(
        KgsmTier tier = KgsmTier.Viewer, UserStatus status = UserStatus.Active) =>
        new("usr_1", "haru", "Haru", tier, TierSource.Granted, status,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);

    // A real store on a real file rather than a stub: what this resolver asks of it — that a handle
    // finds exactly the account it was linked to — is enforced by the schema, and a double would
    // assert the code around that and not the thing itself.
    private static async Task<MemberActingResult> Resolve(
        KgsmUser? person, string? handle = Handle, string? token = "member-token",
        bool validates = true, bool memberEnabled = true, bool storeAvailable = true)
    {
        using var accounts = new Accounts(storeAvailable);
        if (person is not null) await accounts.SeedAsync(person, Handle);

        return await new MemberActingResolver(
                new Tokens(validates), new Gate(memberEnabled), accounts)
            .ResolveAsync(handle, token);
    }

    private sealed class Tokens(bool validates) : IClusterTokenService
    {
        public MintedClusterToken Mint() => throw new NotSupportedException();

        public Task<ClusterPrincipal?> ValidateAsync(string token) =>
            Task.FromResult(validates ? new ClusterPrincipal("hotrod-assistant") : null);
    }

    private sealed class Gate(bool enabled) : IClusterMemberGate
    {
        public Task<bool> IsEnabledAsync(string memberId) => Task.FromResult(enabled);
    }

    private sealed class Accounts : IMemberAccounts, IDisposable
    {
        private readonly string _directory;
        private readonly SqliteUserStore? _store;

        public Accounts(bool available)
        {
            _directory = Path.Combine(Path.GetTempPath(), "kgsm-acting-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
            if (available)
                _store = new SqliteUserStore(new UserStoreOptions
                {
                    Path = Path.Combine(_directory, "users.db"),
                    BusyTimeout = TimeSpan.FromSeconds(5),
                });
        }

        public IUserStore? Store => _store;

        public string? UnavailableReason => _store is null ? "the account store is unavailable" : null;

        public async Task SeedAsync(KgsmUser person, string handle)
        {
            if (_store is null) return;
            await _store.CreateAsync(person);
            await _store.AddCredentialAsync(new UserCredential(
                "cred_1", person.UserId, CredentialKind.Identity, handle,
                null, null, DateTimeOffset.UnixEpoch, null));
        }

        public void Dispose()
        {
            try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
        }
    }
}
