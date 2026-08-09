namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// What the store guarantees to two services sharing one file.
/// </summary>
public class SqliteUserStoreTests
{
    // ── the file itself ───────────────────────────────────────────────────────────────────────

    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    [Fact]
    public void TheStoreFileIsOwnerOnly()
    {
        if (OperatingSystem.IsWindows())
            return;

        using TempStore temp = new();
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(temp.Path_));
    }

    [Fact]
    public async Task TheWalAndSharedMemoryFilesAreOwnerOnlyToo()
    {
        // They carry the same pages as the database. Setting the mode after WAL was enabled would
        // leave these two world-readable, which is the whole reason the store chmods first.
        if (OperatingSystem.IsWindows())
            return;

        using TempStore temp = new();
        await temp.Store.CreateAsync(Make.User());

        foreach (string sidecar in new[] { temp.Path_ + "-wal", temp.Path_ + "-shm" })
        {
            if (File.Exists(sidecar))
                Assert.Equal(OwnerOnly, File.GetUnixFileMode(sidecar));
        }
    }

    [Fact]
    public void AFreshFileIsStampedWithTheSchemaVersionThisBuildWrites()
    {
        using TempStore temp = new();

        // Opening it again is the assertion: a second service reads the stamp and agrees.
        SqliteUserStore second = temp.OpenAgain();
        Assert.NotNull(second);
    }

    [Fact]
    public void AFileFromANewerBuildIsRefusedRatherThanHalfRead()
    {
        using TempStore temp = new();
        temp.Raw($"UPDATE schema_meta SET value = '{UserSchema.Version + 1}' WHERE key = 'schema_version';");

        UserStoreSchemaException e = Assert.Throws<UserStoreSchemaException>(() => temp.OpenAgain());
        Assert.Contains("newer", e.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnUnreadableSchemaVersionIsRefused()
    {
        using TempStore temp = new();
        temp.Raw("UPDATE schema_meta SET value = 'banana' WHERE key = 'schema_version';");

        Assert.Throws<UserStoreSchemaException>(() => temp.OpenAgain());
    }

    // ── accounts ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AnAccountComesBackAsItWentIn()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User("haru", KgsmTier.Admin, UserStatus.Pending, TierSource.Derived);

        await temp.Store.CreateAsync(user);
        KgsmUser? found = await temp.Store.FindByIdAsync(user.UserId);

        Assert.NotNull(found);
        Assert.Equal(user.Username, found.Username);
        Assert.Equal(KgsmTier.Admin, found.Tier);
        Assert.Equal(UserStatus.Pending, found.Status);
        Assert.Equal(TierSource.Derived, found.TierSource);
        Assert.Equal(user.Created, found.Created);
    }

    [Fact]
    public async Task AUsernameIsMatchedWithoutRegardToCase()
    {
        using TempStore temp = new();
        await temp.Store.CreateAsync(Make.User("Haru"));

        Assert.NotNull(await temp.Store.FindByUsernameAsync("haru"));
        Assert.NotNull(await temp.Store.FindByUsernameAsync("HARU"));
    }

    [Fact]
    public async Task TwoAccountsCannotShareAUsernameInAnyCasing()
    {
        using TempStore temp = new();
        await temp.Store.CreateAsync(Make.User("haru"));

        DuplicateUsernameException e = await Assert.ThrowsAsync<DuplicateUsernameException>(
            () => temp.Store.CreateAsync(Make.User("HaRu")));

        Assert.Equal("HaRu", e.Username);
    }

    [Fact]
    public async Task RenamingOntoAnotherAccountsUsernameIsRefused()
    {
        using TempStore temp = new();
        KgsmUser first = Make.User("haru");
        KgsmUser second = Make.User("kaito");
        await temp.Store.CreateAsync(first);
        await temp.Store.CreateAsync(second);

        await Assert.ThrowsAsync<DuplicateUsernameException>(
            () => temp.Store.UpdateAsync(second with { Username = "haru" }));
    }

    [Fact]
    public async Task AnUpdateWritesTheTierTheStatusAndTheProvenance()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User("haru", KgsmTier.Viewer, UserStatus.Pending, TierSource.Derived);
        await temp.Store.CreateAsync(user);

        bool updated = await temp.Store.UpdateAsync(user with
        {
            Tier = KgsmTier.Admin,
            Status = UserStatus.Active,
            TierSource = TierSource.Granted,
            Updated = Make.Now.AddHours(1),
        });

        Assert.True(updated);
        KgsmUser found = (await temp.Store.FindByIdAsync(user.UserId))!;
        Assert.Equal(KgsmTier.Admin, found.Tier);
        Assert.Equal(UserStatus.Active, found.Status);
        Assert.Equal(TierSource.Granted, found.TierSource);
    }

    [Fact]
    public async Task UpdatingAnAccountThatIsNotThereSaysSo()
    {
        using TempStore temp = new();
        Assert.False(await temp.Store.UpdateAsync(Make.User()));
    }

    [Fact]
    public async Task AccountsAreListedOldestFirst()
    {
        using TempStore temp = new();
        await temp.Store.CreateAsync(Make.User("first") with { Created = Make.Now });
        await temp.Store.CreateAsync(Make.User("second") with { Created = Make.Now.AddMinutes(1) });

        IReadOnlyList<KgsmUser> all = await temp.Store.ListAsync();
        Assert.Equal(["first", "second"], all.Select(u => u.Username));
    }

    // ── credentials ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AnIdentityLinkedToOneAccountCannotBeRePointedAtAnother()
    {
        // The takeover this closes: were the second link to succeed, whoever controls that Discord
        // account would inherit whatever the second account may do.
        using TempStore temp = new();
        KgsmUser haru = Make.User("haru");
        KgsmUser kaito = Make.User("kaito");
        await temp.Store.CreateAsync(haru);
        await temp.Store.CreateAsync(kaito);

        await temp.Store.AddCredentialAsync(Make.Identity(haru.UserId, "discord:1234"));

        DuplicateCredentialException e = await Assert.ThrowsAsync<DuplicateCredentialException>(
            () => temp.Store.AddCredentialAsync(Make.Identity(kaito.UserId, "discord:1234")));

        Assert.Equal("discord:1234", e.Handle);
        Assert.Equal(haru.UserId, (await temp.Store.FindByCredentialAsync("discord:1234"))!.UserId);
    }

    [Fact]
    public async Task TheSameSubjectAtTwoProvidersIsTwoDifferentCredentials()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);

        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1234"));
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "github:1234"));

        Assert.Equal(2, (await temp.Store.ListCredentialsAsync(user.UserId)).Count);
    }

    [Fact]
    public async Task AnIdentityNobodyHasLinkedBelongsToNobody()
    {
        using TempStore temp = new();
        await temp.Store.CreateAsync(Make.User());

        Assert.Null(await temp.Store.FindByCredentialAsync("discord:999"));
    }

    [Fact]
    public async Task ErasingAnAccountTakesItsCredentialsWithIt()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1234"));

        Assert.True(await temp.Store.DeleteAsync(user.UserId));
        Assert.Null(await temp.Store.FindCredentialAsync("discord:1234"));
    }

    [Fact]
    public async Task ACredentialsSecretAndLastUseCanBeWrittenBack()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);

        UserCredential credential = new(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Password,
            UserCredentials.LocalHandle(user.UserId), "hash-v1", null, Make.Now, null);

        await temp.Store.AddCredentialAsync(credential);
        Assert.True(await temp.Store.SetCredentialSecretAsync(credential.CredentialId, "hash-v2"));
        await temp.Store.TouchCredentialAsync(credential.CredentialId, Make.Now.AddDays(1));

        UserCredential found = (await temp.Store.FindCredentialAsync(credential.Handle))!;
        Assert.Equal("hash-v2", found.Secret);
        Assert.Equal(Make.Now.AddDays(1), found.LastUsed);
        Assert.Equal(CredentialKind.Password, found.Kind);
    }

    [Fact]
    public async Task RemovingACredentialThatIsNotThereSaysSo()
    {
        using TempStore temp = new();
        Assert.False(await temp.Store.RemoveCredentialAsync("crd_nothing"));
    }

    // ── lockout ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task FailuresUnderTheThresholdCostNothing()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        LockoutPolicy policy = LockoutPolicy.Default;

        for (int i = 0; i < policy.Threshold; i++)
        {
            LoginLockout standing = await temp.Store.RecordFailureAsync(user.UserId, policy, Make.Now);
            Assert.False(standing.IsLocked(Make.Now));
        }
    }

    [Fact]
    public async Task TheFailureAfterTheThresholdLocksTheAccount()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        LockoutPolicy policy = LockoutPolicy.Default;

        LoginLockout standing = LoginLockout.Clear;
        for (int i = 0; i <= policy.Threshold; i++)
            standing = await temp.Store.RecordFailureAsync(user.UserId, policy, Make.Now);

        Assert.True(standing.IsLocked(Make.Now));
        Assert.Equal(Make.Now + policy.BaseDelay, standing.LockedUntil);
    }

    [Fact]
    public async Task ARunThatGoesQuietForTheWindowStartsOver()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        LockoutPolicy policy = LockoutPolicy.Default;

        for (int i = 0; i <= policy.Threshold; i++)
            await temp.Store.RecordFailureAsync(user.UserId, policy, Make.Now);

        DateTimeOffset later = Make.Now + policy.FailureWindow + TimeSpan.FromMinutes(1);
        LoginLockout fresh = await temp.Store.RecordFailureAsync(user.UserId, policy, later);

        Assert.Equal(1, fresh.FailedCount);
        Assert.False(fresh.IsLocked(later));
    }

    [Fact]
    public async Task AnEarnedLockoutIsHonouredEvenAfterTheFailureWindowLapses()
    {
        // Otherwise waiting out the counting window — which is longer than any lockout — would be
        // the cheapest way through a lock, and the lock would mean nothing.
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);

        LockoutPolicy policy = new(
            Threshold: 1, BaseDelay: TimeSpan.FromHours(2), MaxDelay: TimeSpan.FromHours(2),
            FailureWindow: TimeSpan.FromMinutes(10));

        await temp.Store.RecordFailureAsync(user.UserId, policy, Make.Now);
        await temp.Store.RecordFailureAsync(user.UserId, policy, Make.Now);

        DateTimeOffset afterWindow = Make.Now + TimeSpan.FromMinutes(30);
        LoginLockout standing = await temp.Store.GetLockoutAsync(user.UserId, policy, afterWindow);

        Assert.Equal(0, standing.FailedCount);
        Assert.True(standing.IsLocked(afterWindow));
    }

    [Fact]
    public async Task ClearingForgetsTheRun()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        LockoutPolicy policy = LockoutPolicy.Default;

        for (int i = 0; i <= policy.Threshold; i++)
            await temp.Store.RecordFailureAsync(user.UserId, policy, Make.Now);

        await temp.Store.ClearLockoutAsync(user.UserId);

        LoginLockout standing = await temp.Store.GetLockoutAsync(user.UserId, policy, Make.Now);
        Assert.Equal(LoginLockout.Clear, standing);
    }

    [Fact]
    public async Task AnAccountWithNothingAgainstItIsClear()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);

        Assert.Equal(
            LoginLockout.Clear,
            await temp.Store.GetLockoutAsync(user.UserId, LockoutPolicy.Default, Make.Now));
    }

    // ── two services, one file ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task WhatOneServiceWritesTheOtherReads()
    {
        using TempStore temp = new();
        SqliteUserStore other = temp.OpenAgain();

        KgsmUser user = Make.User("haru", KgsmTier.Admin);
        await temp.Store.CreateAsync(user);
        await other.AddCredentialAsync(Make.Identity(user.UserId, "discord:1234"));

        KgsmUser? seenByFirst = await temp.Store.FindByCredentialAsync("discord:1234");
        KgsmUser? seenBySecond = await other.FindByIdAsync(user.UserId);

        Assert.Equal(user.UserId, seenByFirst?.UserId);
        Assert.Equal(KgsmTier.Admin, seenBySecond?.Tier);
    }

    [Fact]
    public async Task ConcurrentWritersBothLandRatherThanOneFailing()
    {
        // The busy timeout is what makes this pass. Without it the loser of the race gets
        // SQLITE_BUSY immediately, and one of the two services drops a write it was told succeeded.
        using TempStore temp = new();
        SqliteUserStore other = temp.OpenAgain();

        await Task.WhenAll(
            Task.Run(async () =>
            {
                for (int i = 0; i < 25; i++)
                    await temp.Store.CreateAsync(Make.User($"first{i}"));
            }),
            Task.Run(async () =>
            {
                for (int i = 0; i < 25; i++)
                    await other.CreateAsync(Make.User($"second{i}"));
            }));

        Assert.Equal(50, (await temp.Store.ListAsync()).Count);
    }
}
