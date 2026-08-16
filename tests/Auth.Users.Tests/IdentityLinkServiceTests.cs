namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// Bringing a verified external identity to the store: what it resolves to, what gets created for
/// it, and the two refusals — an identity already spoken for, and a host already holding as many
/// unapproved accounts as it will.
/// </summary>
public sealed class IdentityLinkServiceTests
{
    private static KgsmIdentity Discord(string subject = "1001", string username = "haru", string? display = null) =>
        new(KgsmActorProvider.Discord, subject, username, display ?? username, AvatarUrl: null, Scopes: []);

    [Fact]
    public async Task AnIdentityNobodyClaimsProvisionsAPendingAccountAtNoTier()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);

        LinkResult result = await linking.ResolveOrProvisionAsync(
            Discord(), Make.Now, PendingPolicy.Default);

        Assert.Equal(LinkOutcome.Provisioned, result.Outcome);
        Assert.Equal(UserStatus.Pending, result.User!.Status);
        Assert.Equal(KgsmTier.None, result.User.Tier);
        Assert.Equal(KgsmTier.None, result.User.EffectiveTier);
        // Seeded, not chosen by anyone — which is what a drift report reads.
        Assert.Equal(TierSource.Derived, result.User.TierSource);
    }

    [Fact]
    public async Task TheSameIdentityResolvesToTheSameAccountAndWritesNothingTheSecondTime()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);

        LinkResult first = await linking.ResolveOrProvisionAsync(Discord(), Make.Now, PendingPolicy.Default);
        LinkResult second = await linking.ResolveOrProvisionAsync(Discord(), Make.Now, PendingPolicy.Default);

        Assert.Equal(LinkOutcome.Provisioned, first.Outcome);
        Assert.Equal(LinkOutcome.Existing, second.Outcome);
        Assert.Equal(first.User!.UserId, second.User!.UserId);
        Assert.Single(await temp.Store.ListAsync());
    }

    [Fact]
    public async Task AProvisionedAccountKeepsTheProvidersDisplayNameAndItsUsernameFitsTheCharset()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);

        LinkResult result = await linking.ResolveOrProvisionAsync(
            Discord(username: "Haru Ω Iwata", display: "Haru Ω Iwata"), Make.Now, PendingPolicy.Default);

        Assert.Equal("Haru Ω Iwata", result.User!.DisplayName);
        Assert.True(Usernames.IsValid(result.User.Username));
        Assert.Equal("Haru--Iwata", result.User.Username);
    }

    [Fact]
    public async Task AUsernameAlreadyTakenGetsASuffixRatherThanFailing()
    {
        using TempStore temp = new();
        await temp.Store.CreateAsync(Make.User(username: "haru"));
        IdentityLinkService linking = new(temp.Store);

        LinkResult result = await linking.ResolveOrProvisionAsync(Discord(), Make.Now, PendingPolicy.Default);

        Assert.Equal("haru-2", result.User!.Username);
    }

    [Fact]
    public async Task AnIdentityWhoseNameSurvivesNothingGetsTheUniqueFallbackForm()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);

        LinkResult result = await linking.ResolveOrProvisionAsync(
            Discord(subject: "1001", username: "Ωμ", display: "Ωμ"), Make.Now, PendingPolicy.Default);

        Assert.Equal("discord-1001", result.User!.Username);
    }

    [Fact]
    public async Task ProvisioningStopsAtTheCap()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);
        PendingPolicy policy = new(Cap: 2, Ttl: TimeSpan.FromDays(14));

        await linking.ResolveOrProvisionAsync(Discord("1"), Make.Now, policy);
        await linking.ResolveOrProvisionAsync(Discord("2"), Make.Now, policy);
        LinkResult third = await linking.ResolveOrProvisionAsync(Discord("3"), Make.Now, policy);

        Assert.Equal(LinkOutcome.PendingCapReached, third.Outcome);
        Assert.Null(third.User);
        Assert.Equal(2, await linking.CountPendingAsync());
    }

    [Fact]
    public async Task TheCapCountsOnlyUnapprovedAccounts()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);
        PendingPolicy policy = new(Cap: 1, Ttl: TimeSpan.FromDays(14));

        LinkResult first = await linking.ResolveOrProvisionAsync(Discord("1"), Make.Now, policy);
        await temp.Store.UpdateAsync(first.User! with { Status = UserStatus.Active });

        LinkResult second = await linking.ResolveOrProvisionAsync(Discord("2"), Make.Now, policy);

        Assert.Equal(LinkOutcome.Provisioned, second.Outcome);
    }

    [Fact]
    public async Task AnUnapprovedArrivalOlderThanTheTtlIsSweptSoTheCapCannotBecomeALockout()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);
        PendingPolicy policy = new(Cap: 1, Ttl: TimeSpan.FromDays(14));

        await linking.ResolveOrProvisionAsync(Discord("1"), Make.Now, policy);
        LinkResult later = await linking.ResolveOrProvisionAsync(
            Discord("2"), Make.Now.AddDays(15), policy);

        Assert.Equal(LinkOutcome.Provisioned, later.Outcome);
        Assert.Single(await temp.Store.ListAsync());
        Assert.Null(await temp.Store.FindByCredentialAsync("discord:1"));
    }

    /// <summary>
    /// Somebody who registers themselves holds a password, and is still an arrival nobody has
    /// looked at. Sparing it would let self-registrations pile up against the cap until the host
    /// refuses every new one — which from outside is indistinguishable from a host that is closed.
    /// </summary>
    [Fact]
    public async Task ExpiryTakesASelfRegisteredAccountEvenThoughItHoldsAPassword()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);
        LocalSignInService signIn = new(temp.Store, new IdentityPasswordHasher(), new UserStoreAuthority(temp.Store));

        LinkResult arrival = await linking.ResolveOrProvisionAsync(
            Discord("1"), Make.Now, PendingPolicy.Default);
        await signIn.SetPasswordAsync(arrival.User!.UserId, "a-real-password", Make.Now);

        int removed = await linking.ExpirePendingAsync(PendingPolicy.Default, Make.Now.AddDays(90));

        Assert.Equal(1, removed);
        Assert.Null(await temp.Store.FindByIdAsync(arrival.User.UserId));
    }

    /// <summary>
    /// An admin creating an account is deliberate work, and provenance is what says so: the tier
    /// was granted rather than derived. It waits as long as it waits.
    /// </summary>
    [Fact]
    public async Task ExpiryNeverTakesAnAccountAnAdminMadeByHand()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);

        LinkResult made = await linking.ProvisionAsync(
            Discord("1"), KgsmTier.Viewer, TierSource.Granted, UserStatus.Pending, Make.Now);

        int removed = await linking.ExpirePendingAsync(PendingPolicy.Default, Make.Now.AddDays(90));

        Assert.Equal(0, removed);
        Assert.NotNull(await temp.Store.FindByIdAsync(made.User!.UserId));
    }

    [Fact]
    public async Task ExpiryNeverTakesAnApprovedOrDisabledAccount()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);

        LinkResult approved = await linking.ResolveOrProvisionAsync(Discord("1"), Make.Now, PendingPolicy.Default);
        await temp.Store.UpdateAsync(approved.User! with { Status = UserStatus.Active });
        LinkResult disabled = await linking.ResolveOrProvisionAsync(Discord("2"), Make.Now, PendingPolicy.Default);
        await temp.Store.UpdateAsync(disabled.User! with { Status = UserStatus.Disabled });

        int removed = await linking.ExpirePendingAsync(PendingPolicy.Default, Make.Now.AddDays(90));

        Assert.Equal(0, removed);
        Assert.Equal(2, (await temp.Store.ListAsync()).Count);
    }

    [Fact]
    public async Task SeedingProvisionsAnActiveAccountAtTheTierItIsGiven()
    {
        using TempStore temp = new();
        IdentityLinkService linking = new(temp.Store);

        LinkResult result = await linking.ProvisionAsync(
            Discord(), KgsmTier.Operator, TierSource.Derived, UserStatus.Active, Make.Now);

        Assert.Equal(LinkOutcome.Provisioned, result.Outcome);
        Assert.Equal(KgsmTier.Operator, result.User!.EffectiveTier);
        Assert.Equal(UserStatus.Active, result.User.Status);

        // And the identity now proves it, which is the whole point of a seed.
        UserStoreAuthority authority = new(temp.Store);
        Assert.Equal(KgsmTier.Operator, await authority.ResolveTierAsync(Discord(), CancellationToken.None));
    }

    [Fact]
    public async Task LinkingToAnAccountAttachesTheIdentityToIt()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User(username: "haru", tier: KgsmTier.Admin);
        await temp.Store.CreateAsync(user);
        IdentityLinkService linking = new(temp.Store);

        LinkResult result = await linking.LinkAsync(user.UserId, Discord(), Make.Now);

        Assert.Equal(LinkOutcome.Provisioned, result.Outcome);
        KgsmUser? proved = await temp.Store.FindByCredentialAsync("discord:1001");
        Assert.Equal(user.UserId, proved!.UserId);
    }

    [Fact]
    public async Task AnIdentityAlreadyAttachedElsewhereIsNeverRepointed()
    {
        using TempStore temp = new();
        KgsmUser mine = Make.User(username: "haru");
        KgsmUser theirs = Make.User(username: "wout");
        await temp.Store.CreateAsync(mine);
        await temp.Store.CreateAsync(theirs);
        IdentityLinkService linking = new(temp.Store);
        await linking.LinkAsync(mine.UserId, Discord(), Make.Now);

        LinkResult result = await linking.LinkAsync(theirs.UserId, Discord(), Make.Now);

        Assert.Equal(LinkOutcome.AlreadyLinked, result.Outcome);
        Assert.Equal(mine.UserId, (await temp.Store.FindByCredentialAsync("discord:1001"))!.UserId);
    }

    [Fact]
    public async Task LinkingTheSameIdentityToTheSameAccountTwiceIsNotAnError()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        IdentityLinkService linking = new(temp.Store);
        await linking.LinkAsync(user.UserId, Discord(), Make.Now);

        LinkResult again = await linking.LinkAsync(user.UserId, Discord(), Make.Now);

        Assert.Equal(LinkOutcome.Existing, again.Outcome);
        Assert.Single(await temp.Store.ListCredentialsAsync(user.UserId));
    }

    // ── Unlinking ────────────────────────────────────────────────────────────

    [Fact]
    public async Task DetachingOneOfTwoCredentialsLeavesTheOtherAndTheAccount()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "local:" + user.UserId));
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1001"));
        UserCredential discord = (await temp.Store.FindCredentialAsync("discord:1001"))!;
        IdentityLinkService linking = new(temp.Store);

        UnlinkOutcome outcome = await linking.UnlinkAsync(user.UserId, discord.CredentialId);

        Assert.Equal(UnlinkOutcome.Unlinked, outcome);
        Assert.Single(await temp.Store.ListCredentialsAsync(user.UserId));
        Assert.NotNull(await temp.Store.FindByIdAsync(user.UserId));
    }

    [Fact]
    public async Task TheLastCredentialIsRefused_NotSilentlyLeavingAnAccountNobodyCanSignInTo()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:1001"));
        UserCredential only = (await temp.Store.FindCredentialAsync("discord:1001"))!;
        IdentityLinkService linking = new(temp.Store);

        UnlinkOutcome outcome = await linking.UnlinkAsync(user.UserId, only.CredentialId);

        Assert.Equal(UnlinkOutcome.LastCredential, outcome);
        Assert.Single(await temp.Store.ListCredentialsAsync(user.UserId));
    }

    [Fact]
    public async Task SomebodyElsesCredentialIsNotFound_AndStays()
    {
        // The id is the whole of what a caller supplies. Unscoped, one copied from another account's
        // record would detach a stranger's identity — so the account it is on decides, and "not yours"
        // and "not real" are one answer.
        using TempStore temp = new();
        KgsmUser mine = Make.User("haru");
        KgsmUser theirs = Make.User("kaito");
        await temp.Store.CreateAsync(mine);
        await temp.Store.CreateAsync(theirs);
        await temp.Store.AddCredentialAsync(Make.Identity(theirs.UserId, "discord:2002"));
        await temp.Store.AddCredentialAsync(Make.Identity(theirs.UserId, "local:" + theirs.UserId));
        UserCredential theirDiscord = (await temp.Store.FindCredentialAsync("discord:2002"))!;
        IdentityLinkService linking = new(temp.Store);

        UnlinkOutcome outcome = await linking.UnlinkAsync(mine.UserId, theirDiscord.CredentialId);

        Assert.Equal(UnlinkOutcome.NotFound, outcome);
        Assert.Equal(2, (await temp.Store.ListCredentialsAsync(theirs.UserId)).Count);
    }
}

/// <summary>
/// <see cref="Usernames.Sanitize"/> — the only place a username is not typed by a person.
/// </summary>
public sealed class UsernameSanitizeTests
{
    [Theory]
    [InlineData("haru", "haru")]
    [InlineData("  haru  ", "haru")]
    [InlineData("Haru.Iwata", "Haru.Iwata")]
    [InlineData("haru iwata", "haru-iwata")]
    [InlineData("haru!!!", "haru")]
    [InlineData("...haru", "haru")]
    [InlineData("haru...", "haru")]
    [InlineData("héllo", "hllo")]
    public void AUsableNameSurvives(string proposed, string expected) =>
        Assert.Equal(expected, Usernames.Sanitize(proposed));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("!!!")]
    [InlineData("ab")]          // shorter than a username may be
    [InlineData("Ωμ")]
    public void NothingUsableIsNullRatherThanAnInventedName(string? proposed) =>
        Assert.Null(Usernames.Sanitize(proposed));

    [Fact]
    public void ALongNameIsClampedAndStaysValid()
    {
        string? sanitized = Usernames.Sanitize(new string('a', 80));

        Assert.Equal(Usernames.MaxLength, sanitized!.Length);
        Assert.True(Usernames.IsValid(sanitized));
    }
}
