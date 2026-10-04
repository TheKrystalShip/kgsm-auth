using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Identity;

namespace TheKrystalShip.Auth.Cluster.Tests;

/// <summary>
/// One member acting on another for somebody who is not signed in to it, resolved against the second
/// member's own replica.
/// </summary>
/// <remarks>
/// Every branch here is a way somebody is either let in wrongly or locked out wrongly, so each refusal
/// is pinned rather than the success alone. The property the scheme rests on — that a caller asserts
/// who and never what — is observable as the resolver answering with an account id and nothing else:
/// what that account may do is evaluated afterwards from the same replica.
/// </remarks>
public sealed class MemberActingAccountResolverTests : IDisposable
{
    private const string Handle = "discord:245717107596197888";
    private const string Caller = "hotrod-assistant";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "kgsm-acting-" + Guid.NewGuid().ToString("N"));
    private readonly string _path;

    public MemberActingAccountResolverTests()
    {
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "users.db");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task A_member_acts_for_a_person_this_member_holds_an_account_for()
    {
        MemberActingAccount result = await Resolve(person: "active");

        Assert.True(result.Succeeded);
        Assert.Equal(MemberActingRefusal.None, result.Refusal);
        Assert.Equal("usr_haru", result.AccountId);
        Assert.Equal(Handle, result.Handle);
        Assert.Equal(Caller, result.ActingMember);
    }

    [Fact]
    public async Task A_call_with_no_member_token_is_not_a_member()
    {
        MemberActingAccount result = await Resolve(person: "active", token: null);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.NoToken, result.Refusal);
    }

    [Fact]
    public async Task A_token_this_member_cannot_validate_is_refused()
    {
        MemberActingAccount result = await Resolve(person: "active", validates: false);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.TokenNotValid, result.Refusal);
    }

    [Fact]
    public async Task A_disabled_member_may_act_for_nobody()
    {
        // The one local override to the shared-secret trust boundary: a good token is not enough.
        MemberActingAccount result = await Resolve(person: "active", memberEnabled: false);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.MemberDisabled, result.Refusal);
        // Named even in refusal, so an operator has something to look at rather than a bare rejection.
        Assert.Equal(Caller, result.ActingMember);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("245717107596197888")]
    public async Task An_unqualified_handle_names_nobody(string handle)
    {
        // Reading a bare subject as some provider's would attribute a person to whichever provider the
        // receiver happened to assume.
        MemberActingAccount result = await Resolve(person: "active", handle: handle);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.HandleNotQualified, result.Refusal);
    }

    [Fact]
    public async Task A_person_this_member_has_never_heard_of_is_refused_rather_than_invented()
    {
        MemberActingAccount result = await Resolve(person: null);

        Assert.False(result.Succeeded);
        // Its own reason, because this is what a username collision looks like from the far end and it
        // has to be findable in a log without matching on a sentence.
        Assert.Equal(MemberActingRefusal.NoSuchAccount, result.Refusal);
        Assert.Equal(Caller, result.ActingMember);
        Assert.Equal(Handle, result.Handle);
    }

    [Fact]
    public async Task A_disabled_account_cannot_be_acted_for()
    {
        MemberActingAccount result = await Resolve(person: "disabled");

        Assert.False(result.Succeeded);
        // Distinct from a disabled MEMBER: one is a person, the other is a machine, and a log that could
        // not tell them apart would send somebody looking in the wrong place.
        Assert.Equal(MemberActingRefusal.AccountDisabled, result.Refusal);
    }

    [Fact]
    public async Task An_unreadable_replica_refuses_and_says_so_rather_than_denying_the_person()
    {
        // An outage is not a denial: the refusal names the replica, so nobody is told they lost access
        // they still hold.
        MemberActingAccount result = await Resolve(person: null, replicaAvailable: false);

        Assert.False(result.Succeeded);
        Assert.Equal(MemberActingRefusal.AccountsUnavailable, result.Refusal);
    }

    [Fact]
    public async Task A_member_acts_as_its_own_service_account_and_nobody_elses()
    {
        MemberActingAccount own = await Resolve(person: "active", handle: "svc:reactor@" + Caller);
        MemberActingAccount borrowed = await Resolve(person: "active", handle: "svc:reactor@walter");

        Assert.Equal("usr_svc_mine", own.AccountId);
        Assert.Equal(MemberActingRefusal.ServiceNotTheCallers, borrowed.Refusal);
    }

    // A real replica on a real file rather than a stub: that a handle finds exactly the account it was
    // linked to is enforced by the schema, and a double would assert the code around that instead.
    private async Task<MemberActingAccount> Resolve(
        string? person, string? handle = Handle, string? token = "member-token",
        bool validates = true, bool memberEnabled = true, bool replicaAvailable = true)
    {
        SqliteAuthorityStore store = new(new UserStoreOptions { Path = _path });
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (person is not null)
        {
            await store.ApplyAsync(new AccountRecord("usr_haru", "haru", "Haru", "admitted", "person", person, now, now,
                [new ReplicatedIdentity(Handle, null)], null, [], 2), now);
        }

        await store.ApplyAsync(new AccountRecord("usr_svc_mine", "reactor@" + Caller, "reactor", "admitted", "service", "active",
            now, now, [], new ServiceRecord("reactor", Caller), [], 3), now);
        await store.ApplyAsync(new AccountRecord("usr_svc_walter", "reactor@walter", "reactor", "admitted", "service", "active",
            now, now, [], new ServiceRecord("reactor", "walter"), [], 4), now);

        IReplicatedAuthority authority = replicaAvailable
            ? new AuthorityReplicaFile(_path, NullLogger<AuthorityReplicaFile>.Instance)
            : new Unavailable();

        return await new MemberActingAccountResolver(new Tokens(validates), new Gate(memberEnabled), authority)
            .ResolveAsync(handle, token, await store.LoadAsync());
    }

    private sealed class Tokens(bool validates) : IClusterTokenService
    {
        public MintedClusterToken Mint() => throw new NotSupportedException();

        public Task<ClusterPrincipal?> ValidateAsync(string token) =>
            Task.FromResult(validates ? new ClusterPrincipal(Caller) : null);
    }

    private sealed class Gate(bool enabled) : IClusterMemberGate
    {
        public Task<bool> IsEnabledAsync(string memberId) => Task.FromResult(enabled);
    }

    private sealed class Unavailable : IReplicatedAuthority
    {
        public SqliteAuthorityStore? Replica => null;

        public string? UnavailableReason => "the authority replica is unavailable";
    }
}
