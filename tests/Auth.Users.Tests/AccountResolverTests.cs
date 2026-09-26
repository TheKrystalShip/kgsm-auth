namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// The account a verified identity proves, and where it stands — the question every sign-in and every
/// session renewal asks before anything about access is.
/// </summary>
public class AccountResolverTests
{
    private static KgsmIdentity Discord(string id) =>
        new(KgsmActorProvider.Discord, id, "haru", "Haru", null, []);

    [Fact]
    public async Task ALinkedIdentityResolvesToItsAccount()
    {
        using TempStore temp = new();
        AccountResolver accounts = new(temp.Store);

        KgsmUser user = Make.User("haru");
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1234"));

        AccountAnswer answer = await accounts.ResolveAsync(Discord("1234"), default);
        Assert.Equal(AccountOutcome.Ok, answer.Outcome);
        Assert.Equal(user.UserId, answer.User!.UserId);
    }

    [Fact]
    public async Task AnIdentityLinkedToNobodyIsAStranger()
    {
        // Not an error. Membership of a group somewhere else is not a fact about this host, so an
        // unlinked subject is a stranger however privileged they are elsewhere.
        using TempStore temp = new();
        AccountResolver accounts = new(temp.Store);

        Assert.Equal(AccountOutcome.NoAccount, (await accounts.ResolveAsync(Discord("9999"), default)).Outcome);
        Assert.Null(await accounts.FindAsync(Discord("9999"), default));
    }

    [Fact]
    public async Task ALocalIdentityResolvesEvenWithNoCredentialRowBehindIt()
    {
        // Its subject IS the account id, so an account whose password has been removed — or which
        // never had one — is still the account it is.
        using TempStore temp = new();
        AccountResolver accounts = new(temp.Store);

        KgsmUser user = Make.User("haru");
        await temp.Store.CreateAsync(user);

        Assert.Equal(user.UserId, (await accounts.ResolveAsync(user.AsIdentity(), default)).User!.UserId);
    }

    [Fact]
    public async Task TheSameSubjectAtTwoProvidersIsTwoDifferentPeople()
    {
        using TempStore temp = new();
        AccountResolver accounts = new(temp.Store);

        KgsmUser user = Make.User("haru");
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1234"));

        KgsmIdentity discord = Discord("1234");
        KgsmIdentity github = discord with { Provider = "github" };

        Assert.Equal(AccountOutcome.Ok, (await accounts.ResolveAsync(discord, default)).Outcome);
        Assert.Equal(AccountOutcome.NoAccount, (await accounts.ResolveAsync(github, default)).Outcome);
    }

    [Fact]
    public async Task TheThreeAnswersAreThreeAnswers()
    {
        // A surface acts differently on each: only a disabled account is a reason to end a live
        // session, and a pending one authenticates holding nothing so a surface can say why.
        using TempStore temp = new();
        AccountResolver accounts = new(temp.Store);

        KgsmUser active = Make.User("haru");
        KgsmUser pending = Make.User("wout", UserStatus.Pending);
        KgsmUser disabled = Make.User("dams", UserStatus.Disabled);
        foreach (KgsmUser user in new[] { active, pending, disabled })
            await temp.Store.CreateAsync(user);

        Assert.Equal(AccountOutcome.Ok, (await accounts.ResolveAsync(active.AsIdentity(), default)).Outcome);
        Assert.Equal(AccountOutcome.Ok, (await accounts.ResolveAsync(pending.AsIdentity(), default)).Outcome);
        Assert.Equal(AccountOutcome.Disabled, (await accounts.ResolveAsync(disabled.AsIdentity(), default)).Outcome);
        Assert.Equal(AccountOutcome.NoAccount, (await accounts.ResolveAsync(Discord("9999"), default)).Outcome);
    }

    [Fact]
    public async Task AStoreThatCannotBeReadIsAnOutageAndNotAStranger()
    {
        // Reporting "we could not ask" as "there is no account" signs an Owner out mid-incident.
        AccountResolver accounts = new(new BrokenStore());

        KgsmAuthProviderException e = await Assert.ThrowsAsync<KgsmAuthProviderException>(
            () => accounts.ResolveAsync(Discord("1234"), default));

        Assert.IsType<IOException>(e.InnerException);
    }

    [Fact]
    public async Task AnAnswerIsCachedForItsTtlAndDroppingItReReadsTheStore()
    {
        // The TTL is how long a switched-off account is still found usable, so what it buys and what
        // it costs are the same fact and both are pinned here.
        using TempStore temp = new();
        AccountResolver accounts = new(temp.Store, TimeSpan.FromMinutes(5));

        KgsmUser user = Make.User("haru");
        await temp.Store.CreateAsync(user);
        Assert.Equal(AccountOutcome.Ok, (await accounts.ResolveAsync(user.AsIdentity(), default)).Outcome);

        await temp.Store.UpdateAsync(user with { Status = UserStatus.Disabled });
        Assert.Equal(AccountOutcome.Ok, (await accounts.ResolveAsync(user.AsIdentity(), default)).Outcome);

        accounts.Forget(user.AsIdentity().Handle);
        Assert.Equal(AccountOutcome.Disabled, (await accounts.ResolveAsync(user.AsIdentity(), default)).Outcome);
    }

    [Fact]
    public async Task AnExpiredEntryIsReReadWithoutAnyoneDroppingIt()
    {
        using TempStore temp = new();
        AccountResolver accounts = new(temp.Store, TimeSpan.FromMilliseconds(30));

        KgsmUser user = Make.User("haru");
        await temp.Store.CreateAsync(user);
        await accounts.ResolveAsync(user.AsIdentity(), default);

        await temp.Store.UpdateAsync(user with { Status = UserStatus.Disabled });
        await Task.Delay(80);

        Assert.Equal(AccountOutcome.Disabled, (await accounts.ResolveAsync(user.AsIdentity(), default)).Outcome);
    }

    [Fact]
    public async Task AnOutageIsNeverCachedAsAnAnswer()
    {
        // Caching a failure turns a moment of unavailability into a full-TTL lockout.
        AccountResolver accounts = new(new BrokenStore(), TimeSpan.FromMinutes(5));

        await Assert.ThrowsAsync<KgsmAuthProviderException>(() => accounts.ResolveAsync(Discord("1234"), default));
        await Assert.ThrowsAsync<KgsmAuthProviderException>(() => accounts.ResolveAsync(Discord("1234"), default));
    }

    /// <summary>A store whose file is gone.</summary>
    private sealed class BrokenStore : IUserStore
    {
        private static Exception Gone() => new IOException("The user store is unreadable.");

        public Task<KgsmUser?> FindByIdAsync(string userId, CancellationToken ct = default) => throw Gone();
        public Task<KgsmUser?> FindByUsernameAsync(string username, CancellationToken ct = default) => throw Gone();
        public Task<KgsmUser?> FindByCredentialAsync(string handle, CancellationToken ct = default) => throw Gone();
        public Task<IReadOnlyList<KgsmUser>> ListAsync(CancellationToken ct = default) => throw Gone();
        public Task CreateAsync(KgsmUser user, CancellationToken ct = default) => throw Gone();
        public Task<bool> UpdateAsync(KgsmUser user, CancellationToken ct = default) => throw Gone();
        public Task<bool> DeleteAsync(string userId, CancellationToken ct = default) => throw Gone();
        public Task<IReadOnlyList<UserCredential>> ListCredentialsAsync(string userId, CancellationToken ct = default) => throw Gone();
        public Task<UserCredential?> FindCredentialAsync(string handle, CancellationToken ct = default) => throw Gone();
        public Task AddCredentialAsync(UserCredential credential, CancellationToken ct = default) => throw Gone();
        public Task<bool> SetCredentialSecretAsync(string credentialId, string secret, CancellationToken ct = default) => throw Gone();
        public Task TouchCredentialAsync(string credentialId, DateTimeOffset when, CancellationToken ct = default) => throw Gone();
        public Task<bool> RemoveCredentialAsync(string credentialId, CancellationToken ct = default) => throw Gone();
        public Task<LoginLockout> GetLockoutAsync(string userId, LockoutPolicy policy, DateTimeOffset now, CancellationToken ct = default) => throw Gone();
        public Task<LoginLockout> RecordFailureAsync(string userId, LockoutPolicy policy, DateTimeOffset now, CancellationToken ct = default) => throw Gone();
        public Task ClearLockoutAsync(string userId, CancellationToken ct = default) => throw Gone();
    }
}
