namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// Authority from the store — the single answer to "what may this verified person do here".
/// </summary>
public class UserStoreAuthorityTests
{
    private static KgsmIdentity Discord(string id) =>
        new(KgsmActorProvider.Discord, id, "haru", "Haru", null, []);

    [Fact]
    public async Task ALinkedIdentityHoldsWhatItsAccountHolds()
    {
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store);

        KgsmUser user = Make.User("haru", KgsmTier.Operator);
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1234"));

        Assert.Equal(KgsmTier.Operator, await authority.ResolveTierAsync(Discord("1234"), default));
    }

    [Fact]
    public async Task AnIdentityLinkedToNobodyHoldsNothing()
    {
        // Not an error and not a floor. Membership of a group somewhere else is not a fact about
        // this host, so an unlinked subject is a stranger however privileged they are elsewhere.
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store);

        Assert.Equal(KgsmTier.None, await authority.ResolveTierAsync(Discord("9999"), default));
        Assert.Null(await authority.FindAsync(Discord("9999"), default));
    }

    [Theory]
    [InlineData(UserStatus.Pending)]
    [InlineData(UserStatus.Disabled)]
    public async Task AnAccountThatIsNotActiveHoldsNothingHoweverItIsProved(UserStatus status)
    {
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store);

        KgsmUser user = Make.User("haru", KgsmTier.Admin, status);
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1234"));

        Assert.Equal(KgsmTier.None, await authority.ResolveTierAsync(Discord("1234"), default));
        Assert.Equal(KgsmTier.None, await authority.ResolveTierAsync(user.AsIdentity(), default));
    }

    [Fact]
    public async Task ALocalIdentityResolvesEvenWithNoCredentialRowBehindIt()
    {
        // Its subject IS the account id, so an account whose password has been removed — or which
        // never had one — still holds the tier it holds.
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store);

        KgsmUser user = Make.User("haru", KgsmTier.Admin);
        await temp.Store.CreateAsync(user);

        Assert.Equal(KgsmTier.Admin, await authority.ResolveTierAsync(user.AsIdentity(), default));
    }

    [Fact]
    public async Task TheSameSubjectAtTwoProvidersIsTwoDifferentPeople()
    {
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store);

        KgsmUser admin = Make.User("haru", KgsmTier.Admin);
        await temp.Store.CreateAsync(admin);
        await temp.Store.AddCredentialAsync(Make.Identity(admin.UserId, "discord:1234"));

        KgsmIdentity elsewhere = new(KgsmActorProvider.Discord, "1234", "haru", "Haru", null, []);
        KgsmIdentity github = elsewhere with { Provider = "github" };

        Assert.Equal(KgsmTier.Admin, await authority.ResolveTierAsync(elsewhere, default));
        Assert.Equal(KgsmTier.None, await authority.ResolveTierAsync(github, default));
    }

    [Fact]
    public async Task AStoreThatCannotBeReadIsAnOutageAndNotADenial()
    {
        // The security analogue of never fabricating a status: reporting "we could not ask" as
        // "you have no access" demotes an admin in the middle of an incident.
        UserStoreAuthority authority = new(new BrokenStore());

        KgsmAuthProviderException e = await Assert.ThrowsAsync<KgsmAuthProviderException>(
            () => authority.ResolveTierAsync(Discord("1234"), default));

        Assert.IsType<IOException>(e.InnerException);
    }

    [Fact]
    public async Task TheThreeAnswersAreThreeAnswers()
    {
        // A surface acts differently on each: only a disabled account is a reason to end a live
        // session, and a pending one authenticates at no tier so the panel can say why.
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store);

        KgsmUser active = Make.User("haru", KgsmTier.Operator);
        KgsmUser pending = Make.User("wout", KgsmTier.Admin, UserStatus.Pending);
        KgsmUser disabled = Make.User("dams", KgsmTier.Admin, UserStatus.Disabled);
        foreach (KgsmUser user in new[] { active, pending, disabled })
            await temp.Store.CreateAsync(user);

        Assert.Equal(AuthorityOutcome.Ok, (await authority.ResolveAsync(active.AsIdentity(), default)).Outcome);
        Assert.Equal(AuthorityOutcome.Ok, (await authority.ResolveAsync(pending.AsIdentity(), default)).Outcome);
        Assert.Equal(KgsmTier.None, (await authority.ResolveAsync(pending.AsIdentity(), default)).Tier);
        Assert.Equal(AuthorityOutcome.Disabled, (await authority.ResolveAsync(disabled.AsIdentity(), default)).Outcome);
        Assert.Equal(AuthorityOutcome.NoAccount, (await authority.ResolveAsync(Discord("9999"), default)).Outcome);
    }

    [Fact]
    public async Task AnAnswerIsCachedForItsTtlAndDroppingItReReadsTheStore()
    {
        // The TTL is the staleness bound on a demotion, so what it buys and what it costs are the
        // same fact and both are pinned here.
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store, TimeSpan.FromMinutes(5));

        KgsmUser user = Make.User("haru", KgsmTier.Admin);
        await temp.Store.CreateAsync(user);
        Assert.Equal(KgsmTier.Admin, await authority.ResolveTierAsync(user.AsIdentity(), default));

        await temp.Store.UpdateAsync(user with { Tier = KgsmTier.Viewer });
        Assert.Equal(KgsmTier.Admin, await authority.ResolveTierAsync(user.AsIdentity(), default));

        authority.Forget(user.AsIdentity().Handle);
        Assert.Equal(KgsmTier.Viewer, await authority.ResolveTierAsync(user.AsIdentity(), default));
    }

    [Fact]
    public async Task WithNoTtlEveryQuestionIsAskedAgain()
    {
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store);

        KgsmUser user = Make.User("haru", KgsmTier.Admin);
        await temp.Store.CreateAsync(user);
        Assert.Equal(KgsmTier.Admin, await authority.ResolveTierAsync(user.AsIdentity(), default));

        await temp.Store.UpdateAsync(user with { Tier = KgsmTier.Viewer });

        Assert.Equal(KgsmTier.Viewer, await authority.ResolveTierAsync(user.AsIdentity(), default));
    }

    [Fact]
    public async Task AnExpiredEntryIsReReadWithoutAnyoneDroppingIt()
    {
        using TempStore temp = new();
        UserStoreAuthority authority = new(temp.Store, TimeSpan.FromMilliseconds(30));

        KgsmUser user = Make.User("haru", KgsmTier.Admin);
        await temp.Store.CreateAsync(user);
        Assert.Equal(KgsmTier.Admin, await authority.ResolveTierAsync(user.AsIdentity(), default));

        await temp.Store.UpdateAsync(user with { Tier = KgsmTier.Viewer });
        await Task.Delay(80);

        Assert.Equal(KgsmTier.Viewer, await authority.ResolveTierAsync(user.AsIdentity(), default));
    }

    [Fact]
    public async Task AnOutageIsNeverCachedAsAnAnswer()
    {
        // Caching a failure turns a moment of unavailability into a full-TTL lockout for whoever
        // really does hold the role.
        UserStoreAuthority authority = new(new BrokenStore(), TimeSpan.FromMinutes(5));

        await Assert.ThrowsAsync<KgsmAuthProviderException>(
            () => authority.ResolveTierAsync(Discord("1234"), default));
        await Assert.ThrowsAsync<KgsmAuthProviderException>(
            () => authority.ResolveTierAsync(Discord("1234"), default));
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
