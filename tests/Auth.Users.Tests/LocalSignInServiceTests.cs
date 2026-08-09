namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// Signing in with a KGSM password — the path that must work with no external provider configured
/// at all, which is the whole point of the account store existing.
/// </summary>
public class LocalSignInServiceTests
{
    private const string Password = "correct-horse-battery-staple";

    private static (TempStore Temp, LocalSignInService SignIn) Build(
        IUserPasswordHasher? hasher = null, LockoutPolicy? lockout = null)
    {
        TempStore temp = new();
        LocalSignInService signIn = new(
            temp.Store, hasher ?? new IdentityPasswordHasher(),
            new UserStoreAuthority(temp.Store), lockout);

        return (temp, signIn);
    }

    private static async Task<KgsmUser> Enrol(
        TempStore temp, LocalSignInService signIn, KgsmUser user, string password = Password)
    {
        await temp.Store.CreateAsync(user);
        await signIn.SetPasswordAsync(user.UserId, password, Make.Now);
        return user;
    }

    [Fact]
    public async Task TheRightPasswordSignsInWithTheTierOnTheRecord()
    {
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        KgsmUser user = await Enrol(temp, signIn, Make.User("haru", KgsmTier.Admin));
        LocalSignInResult result = await signIn.SignInAsync("haru", Password, Make.Now);

        Assert.Equal(LocalSignInOutcome.Success, result.Outcome);
        Assert.Equal(KgsmTier.Admin, result.Principal!.Tier);
        Assert.Equal(KgsmActorProvider.Local, result.Principal.Identity.Provider);
        Assert.Equal(user.UserId, result.Principal.Identity.Subject);
        Assert.Equal("local:haru", result.Principal.Identity.ActorString);
    }

    [Fact]
    public async Task AUsernameIsAcceptedInAnyCasing()
    {
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        await Enrol(temp, signIn, Make.User("Haru"));

        Assert.Equal(
            LocalSignInOutcome.Success,
            (await signIn.SignInAsync("HARU", Password, Make.Now)).Outcome);
    }

    [Fact]
    public async Task AnAccountAwaitingApprovalSignsInAndHoldsNothing()
    {
        // Not a denial: it is what lets a surface say "awaiting approval" rather than showing
        // someone who just proved who they are a bare 403.
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        await Enrol(temp, signIn, Make.User("haru", KgsmTier.Admin, UserStatus.Pending));
        LocalSignInResult result = await signIn.SignInAsync("haru", Password, Make.Now);

        Assert.Equal(LocalSignInOutcome.Success, result.Outcome);
        Assert.Equal(KgsmTier.None, result.Principal!.Tier);
        Assert.Equal(UserStatus.Pending, result.User!.Status);
    }

    [Fact]
    public async Task ADisabledAccountIsToldSoOnlyOnceThePasswordIsRight()
    {
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        await Enrol(temp, signIn, Make.User("haru", KgsmTier.Admin, UserStatus.Disabled));

        LocalSignInResult result = await signIn.SignInAsync("haru", Password, Make.Now);

        Assert.Equal(LocalSignInOutcome.Disabled, result.Outcome);
        Assert.Null(result.Principal);
        Assert.Equal(UserStatus.Disabled, result.User!.Status);
    }

    [Fact]
    public async Task ADisabledAccountIsIndistinguishableFromNoAccountWithoutThePassword()
    {
        // Otherwise anyone who guesses a username learns it names a real account — the oracle the
        // single InvalidCredentials outcome exists to close, reopened for exactly the accounts most
        // worth knowing about.
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        await Enrol(temp, signIn, Make.User("haru", KgsmTier.Admin, UserStatus.Disabled));

        Assert.Equal(
            LocalSignInOutcome.InvalidCredentials,
            (await signIn.SignInAsync("haru", "guess", Make.Now)).Outcome);
        Assert.Equal(
            LocalSignInOutcome.InvalidCredentials,
            (await signIn.SignInAsync("nobody", "guess", Make.Now)).Outcome);
    }

    [Fact]
    public async Task AnUnknownUsernameAndAWrongPasswordAreTheSameAnswer()
    {
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        await Enrol(temp, signIn, Make.User("haru"));

        Assert.Equal(
            LocalSignInOutcome.InvalidCredentials,
            (await signIn.SignInAsync("nobody", Password, Make.Now)).Outcome);
        Assert.Equal(
            LocalSignInOutcome.InvalidCredentials,
            (await signIn.SignInAsync("haru", "wrong", Make.Now)).Outcome);
    }

    [Fact]
    public async Task AnUnknownUsernameStillCostsAHashVerification()
    {
        // The username oracle the single outcome closes off reopens as a stopwatch otherwise: a real
        // account runs a deliberately slow derivation and a missing one returns at once.
        RecordingHasher hasher = new();
        (TempStore temp, LocalSignInService signIn) = Build(hasher);
        using TempStore _ = temp;

        hasher.Verifications = 0;
        await signIn.SignInAsync("nobody", Password, Make.Now);

        Assert.Equal(1, hasher.Verifications);
    }

    [Fact]
    public async Task AnAccountWithNoPasswordCannotBeSignedIntoWithOne()
    {
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        KgsmUser user = Make.User("haru");
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1234"));

        Assert.Equal(
            LocalSignInOutcome.InvalidCredentials,
            (await signIn.SignInAsync("haru", Password, Make.Now)).Outcome);
    }

    [Fact]
    public async Task EnoughWrongPasswordsLockTheAccountAndTheRightOneStillFails()
    {
        LockoutPolicy policy = LockoutPolicy.Default;
        (TempStore temp, LocalSignInService signIn) = Build(lockout: policy);
        using TempStore _ = temp;

        await Enrol(temp, signIn, Make.User("haru"));

        for (int i = 0; i <= policy.Threshold; i++)
            await signIn.SignInAsync("haru", "wrong", Make.Now);

        LocalSignInResult locked = await signIn.SignInAsync("haru", Password, Make.Now);

        Assert.Equal(LocalSignInOutcome.LockedOut, locked.Outcome);
        Assert.Equal(Make.Now + policy.BaseDelay, locked.RetryAfter);
    }

    [Fact]
    public async Task TheLockLiftsOnItsOwnAndTheRightPasswordWorksAgain()
    {
        LockoutPolicy policy = LockoutPolicy.Default;
        (TempStore temp, LocalSignInService signIn) = Build(lockout: policy);
        using TempStore _ = temp;

        await Enrol(temp, signIn, Make.User("haru"));
        for (int i = 0; i <= policy.Threshold; i++)
            await signIn.SignInAsync("haru", "wrong", Make.Now);

        DateTimeOffset after = Make.Now + policy.BaseDelay + TimeSpan.FromSeconds(1);

        Assert.Equal(
            LocalSignInOutcome.Success,
            (await signIn.SignInAsync("haru", Password, after)).Outcome);
    }

    [Fact]
    public async Task ASuccessfulSignInForgetsTheFailuresBeforeIt()
    {
        LockoutPolicy policy = LockoutPolicy.Default;
        (TempStore temp, LocalSignInService signIn) = Build(lockout: policy);
        using TempStore _ = temp;

        KgsmUser user = await Enrol(temp, signIn, Make.User("haru"));

        for (int i = 0; i < policy.Threshold; i++)
            await signIn.SignInAsync("haru", "wrong", Make.Now);

        await signIn.SignInAsync("haru", Password, Make.Now);

        Assert.Equal(
            LoginLockout.Clear,
            await temp.Store.GetLockoutAsync(user.UserId, policy, Make.Now));
    }

    [Fact]
    public async Task ASignInStampsTheCredentialItUsed()
    {
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        KgsmUser user = await Enrol(temp, signIn, Make.User("haru"));
        await signIn.SignInAsync("haru", Password, Make.Now.AddDays(3));

        UserCredential credential =
            (await temp.Store.FindCredentialAsync(UserCredentials.LocalHandle(user.UserId)))!;

        Assert.Equal(Make.Now.AddDays(3), credential.LastUsed);
    }

    [Fact]
    public async Task APasswordStoredUnderAnOlderFormatIsRehashedOnUse()
    {
        // The migration path that means changing the hash format never needs a forced reset: the one
        // moment the plaintext is in hand is the moment it is re-derived.
        RehashingHasher hasher = new();
        (TempStore temp, LocalSignInService signIn) = Build(hasher);
        using TempStore _ = temp;

        KgsmUser user = await Enrol(temp, signIn, Make.User("haru"));
        string before =
            (await temp.Store.FindCredentialAsync(UserCredentials.LocalHandle(user.UserId)))!.Secret!;

        hasher.NeedsRehash = true;
        Assert.Equal(
            LocalSignInOutcome.Success,
            (await signIn.SignInAsync("haru", Password, Make.Now)).Outcome);

        string after =
            (await temp.Store.FindCredentialAsync(UserCredentials.LocalHandle(user.UserId)))!.Secret!;

        Assert.NotEqual(before, after);
    }

    [Fact]
    public async Task SettingAPasswordTwiceReplacesItRatherThanAddingASecond()
    {
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        KgsmUser user = await Enrol(temp, signIn, Make.User("haru"));
        await signIn.SetPasswordAsync(user.UserId, "a-new-one", Make.Now);

        Assert.Single(await temp.Store.ListCredentialsAsync(user.UserId));
        Assert.Equal(
            LocalSignInOutcome.InvalidCredentials,
            (await signIn.SignInAsync("haru", Password, Make.Now)).Outcome);
        Assert.Equal(
            LocalSignInOutcome.Success,
            (await signIn.SignInAsync("haru", "a-new-one", Make.Now)).Outcome);
    }

    [Fact]
    public async Task AnAdminResettingAPasswordLiftsTheLockoutWithIt()
    {
        LockoutPolicy policy = LockoutPolicy.Default;
        (TempStore temp, LocalSignInService signIn) = Build(lockout: policy);
        using TempStore _ = temp;

        KgsmUser user = await Enrol(temp, signIn, Make.User("haru"));
        for (int i = 0; i <= policy.Threshold; i++)
            await signIn.SignInAsync("haru", "wrong", Make.Now);

        await signIn.SetPasswordAsync(user.UserId, "a-new-one", Make.Now);

        Assert.Equal(
            LocalSignInOutcome.Success,
            (await signIn.SignInAsync("haru", "a-new-one", Make.Now)).Outcome);
    }

    [Fact]
    public async Task AMissingPasswordFieldIsAWrongPasswordAndNotAnError()
    {
        (TempStore temp, LocalSignInService signIn) = Build();
        using TempStore _ = temp;

        await Enrol(temp, signIn, Make.User("haru"));

        Assert.Equal(
            LocalSignInOutcome.InvalidCredentials,
            (await signIn.SignInAsync("haru", null, Make.Now)).Outcome);
        Assert.Equal(
            LocalSignInOutcome.InvalidCredentials,
            (await signIn.SignInAsync(null, null, Make.Now)).Outcome);
    }

    /// <summary>A real hasher that counts how often it was asked to check something.</summary>
    private sealed class RecordingHasher : IUserPasswordHasher
    {
        private readonly IdentityPasswordHasher _inner = new();

        public int Verifications { get; set; }

        public string Hash(string password) => _inner.Hash(password);

        public PasswordVerification Verify(string hash, string password)
        {
            Verifications++;
            return _inner.Verify(hash, password);
        }
    }

    /// <summary>A real hasher that can be told to report its output stale.</summary>
    private sealed class RehashingHasher : IUserPasswordHasher
    {
        private readonly IdentityPasswordHasher _inner = new();

        public bool NeedsRehash { get; set; }

        public string Hash(string password) => _inner.Hash(password);

        public PasswordVerification Verify(string hash, string password)
        {
            PasswordVerification result = _inner.Verify(hash, password);
            return result == PasswordVerification.Success && NeedsRehash
                ? PasswordVerification.SuccessRehashNeeded
                : result;
        }
    }
}
