using Microsoft.Data.Sqlite;

using TheKrystalShip.Auth.Access;

namespace TheKrystalShip.Auth.Users.Tests;

/// <summary>
/// People's accounts at schema version 2, through the account store every sign-in door reads: the same
/// answers the version 1 store gives, with every change to an account versioned and owed to the cluster.
/// </summary>
public sealed class AuthorityAccountStoreTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 9, 26, 12, 0, 0, TimeSpan.Zero);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "kgsm-account-store-" + Guid.NewGuid().ToString("N"));
    private readonly SqliteAuthorityStore _store;

    public AuthorityAccountStoreTests()
    {
        _store = new SqliteAuthorityStore(new UserStoreOptions { Path = Path.Combine(_dir, "users.db") });
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

    private static KgsmUser Person(string username, UserStatus status = UserStatus.Active, AccountOrigin origin = AccountOrigin.Admitted) =>
        new(UserIds.NewUserId(), username, username, origin, status, Now, Now);

    private async Task<IReadOnlyList<AuthorityAnnouncement>> OwedAsync() => await _store.PendingAnnouncementsAsync();

    private async Task ClearOwedAsync()
    {
        foreach (AuthorityAnnouncement owed in await _store.PendingAnnouncementsAsync())
            await _store.ClearAnnouncementAsync(owed.Key, owed.Version);
    }

    [Fact]
    public async Task AnAccountReadsBackWithItsOrigin()
    {
        KgsmUser alice = Person("alice");
        KgsmUser bob = Person("bob", UserStatus.Pending, AccountOrigin.Arrived);
        await _store.CreateAsync(alice);
        await _store.CreateAsync(bob);

        KgsmUser read = (await _store.FindByUsernameAsync("ALICE"))!;
        Assert.Equal(alice.UserId, read.UserId);
        Assert.Equal(AccountOrigin.Admitted, read.Origin);
        Assert.Equal(AccountOrigin.Arrived, (await _store.FindByIdAsync(bob.UserId))!.Origin);
        Assert.Equal(UserStatus.Pending, (await _store.FindByIdAsync(bob.UserId))!.Status);
        Assert.Equal(AccountKind.Person, (await _store.LoadAsync()).Accounts[alice.UserId].Kind);
    }

    [Fact]
    public async Task ATakenUsernameIsRefusedAsOne()
    {
        await _store.CreateAsync(Person("alice"));

        await Assert.ThrowsAsync<DuplicateUsernameException>(() => _store.CreateAsync(Person("Alice")));
    }

    [Fact]
    public async Task ServiceAccountsAreNotPeople()
    {
        await _store.DeclareRequirementsAsync(new ServiceIdentity("reactor", "walter"), anchor: false,
            [new DeclaredRequirement("kgsm:server.restart", ScopeKind.Instance, null)], Now);
        await _store.CreateAsync(Person("alice"));

        Assert.Equal(["alice"], (await _store.ListAsync()).Select(u => u.Username));
        Assert.Null(await _store.FindByUsernameAsync("reactor@walter"));
    }

    [Fact]
    public async Task CreatingAndChangingAnAccountIsOwedToTheCluster()
    {
        KgsmUser alice = Person("alice", UserStatus.Pending);
        await _store.CreateAsync(alice);
        Assert.Contains(await OwedAsync(), a => a.Key == AuthorityRecordKey.Account(alice.UserId));

        await ClearOwedAsync();
        long before = await _store.VersionAsync();
        Assert.True(await _store.UpdateAsync(alice with { Status = UserStatus.Active, Updated = Now.AddMinutes(1) }));

        Assert.Equal(before + 1, await _store.VersionAsync());
        AuthorityAnnouncement owed = Assert.Single(await OwedAsync());
        Assert.Equal("active", (await _store.ReadAccountRecordAsync(alice.UserId))!.Status);
        Assert.Equal(owed.Version, (await _store.ReadAccountRecordAsync(alice.UserId))!.Version);
    }

    [Fact]
    public async Task AnUpdateToNobodyChangesNothing()
    {
        long before = await _store.VersionAsync();

        Assert.False(await _store.UpdateAsync(Person("ghost")));
        Assert.Equal(before, await _store.VersionAsync());
    }

    [Fact]
    public async Task AttachingAHandleIsOwed_SettingASecretIsNot()
    {
        KgsmUser alice = Person("alice");
        await _store.CreateAsync(alice);
        await ClearOwedAsync();

        UserCredential password = new("cred_pw", alice.UserId, CredentialKind.Password, UserCredentials.LocalHandle(alice.UserId),
            "hash", null, Now, null);
        await _store.AddCredentialAsync(password);
        Assert.Single(await OwedAsync());
        Assert.Equal(alice.UserId, (await _store.FindByCredentialAsync(password.Handle))!.UserId);
        await ClearOwedAsync();

        long before = await _store.VersionAsync();
        Assert.True(await _store.SetCredentialSecretAsync("cred_pw", "hash2"));
        await _store.TouchCredentialAsync("cred_pw", Now);

        Assert.Equal(before, await _store.VersionAsync());
        Assert.Empty(await OwedAsync());
        Assert.Equal("hash2", (await _store.FindCredentialAsync(password.Handle))!.Secret);
    }

    [Fact]
    public async Task AHandleHeldByAnotherAccountIsRefused_AndRemovingOneIsOwed()
    {
        KgsmUser alice = Person("alice");
        KgsmUser bob = Person("bob");
        await _store.CreateAsync(alice);
        await _store.CreateAsync(bob);
        await _store.AddCredentialAsync(new UserCredential("c1", alice.UserId, CredentialKind.Identity, "discord:1", null, "a", Now, null));

        await Assert.ThrowsAsync<DuplicateCredentialException>(() =>
            _store.AddCredentialAsync(new UserCredential("c2", bob.UserId, CredentialKind.Identity, "discord:1", null, "b", Now, null)));

        await ClearOwedAsync();
        Assert.True(await _store.RemoveCredentialAsync("c1"));
        Assert.False(await _store.RemoveCredentialAsync("c1"));
        Assert.Equal(AuthorityRecordKey.Account(alice.UserId), Assert.Single(await OwedAsync()).Key);
    }

    [Fact]
    public async Task FailedSignInsLockWithoutMovingTheAuthority()
    {
        KgsmUser alice = Person("alice");
        await _store.CreateAsync(alice);
        long before = await _store.VersionAsync();
        LockoutPolicy policy = LockoutPolicy.Default;

        LoginLockout standing = LoginLockout.Clear;
        for (int i = 0; i < 10; i++)
            standing = await _store.RecordFailureAsync(alice.UserId, policy, Now);

        Assert.True(standing.IsLocked(Now));
        Assert.Equal(standing.FailedCount, (await _store.GetLockoutAsync(alice.UserId, policy, Now)).FailedCount);
        Assert.Equal(before, await _store.VersionAsync());

        await _store.ClearLockoutAsync(alice.UserId);
        Assert.False((await _store.GetLockoutAsync(alice.UserId, policy, Now)).IsLocked(Now));
    }

    [Fact]
    public async Task TheSystemsDeletionTakesAssignmentsAndIsOwedAsARemoval()
    {
        KgsmUser alice = Person("alice");
        await _store.CreateAsync(alice);
        await _store.GrantOwnerLocallyAsync("alice", "local:test", Now);
        await ClearOwedAsync();

        Assert.True(await _store.DeleteAsync(alice.UserId));

        Assert.Null(await _store.FindByIdAsync(alice.UserId));
        IReadOnlyList<AuthorityAnnouncement> owed = await OwedAsync();
        Assert.Contains(owed, a => a.Key == AuthorityRecordKey.Account(alice.UserId) && a.Removed);
        Assert.Contains(owed, a => a.Key.Kind == AuthorityRecordKind.Assignment && a.Removed);
    }

    [Fact]
    public async Task APasswordSignInWorksAgainstTheVersionTwoStore()
    {
        IUserPasswordHasher hasher = new IdentityPasswordHasher();
        KgsmUser alice = Person("alice");
        await _store.CreateAsync(alice);
        await _store.AddCredentialAsync(new UserCredential("cred_pw", alice.UserId, CredentialKind.Password,
            UserCredentials.LocalHandle(alice.UserId), hasher.Hash("correct horse battery"), null, Now, null));

        LocalSignInService signIn = new(_store, hasher);

        Assert.Equal(LocalSignInOutcome.Success, (await signIn.SignInAsync("alice", "correct horse battery", Now)).Outcome);
        Assert.Equal(LocalSignInOutcome.InvalidCredentials, (await signIn.SignInAsync("alice", "wrong", Now)).Outcome);
    }

    [Fact]
    public async Task AnArrivingIdentityIsProvisionedPendingAndArrived()
    {
        IdentityLinkService links = new(_store);

        LinkResult result = await links.ResolveOrProvisionAsync(
            new KgsmIdentity("discord", "42", "haru", "Haru", null, []), Now, new PendingPolicy(25, TimeSpan.FromDays(14)));

        Assert.Equal(LinkOutcome.Provisioned, result.Outcome);
        KgsmUser user = (await _store.FindByCredentialAsync("discord:42"))!;
        Assert.Equal(UserStatus.Pending, user.Status);
        Assert.Equal(AccountOrigin.Arrived, user.Origin);
        Assert.Equal(AccountStatus.Pending, (await _store.LoadAsync()).Accounts[user.UserId].Status);
    }
}
