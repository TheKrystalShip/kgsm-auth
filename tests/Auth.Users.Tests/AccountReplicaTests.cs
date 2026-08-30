namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// What a member's own copy of the cluster's accounts is, and what it deliberately is not.
/// </summary>
/// <remarks>
/// A replica answers "who is this and what may they do". It cannot answer "is this their password",
/// and that is the point rather than a gap: signing in happens on the member holding the accounts, so
/// a compromised replica reads what its tier allows and cannot let anybody in.
/// </remarks>
public class AccountReplicaTests
{
    private static readonly DateTimeOffset Now = Make.Now;

    private static (AccountReplica Replica, IAccountVersions Versions) Replica(TempStore temp)
    {
        var versions = new SqliteAccountVersions(temp.Options);
        return (new AccountReplica(temp.Store, versions), versions);
    }

    private static AccountChange Change(
        KgsmUser user, long version, params ReplicatedIdentity[] identities) =>
        new(
            new ReplicatedAccount(
                user.UserId, user.Username, user.DisplayName,
                KgsmTiers.ToWire(user.Tier), TierSources.ToWire(user.TierSource),
                UserStatuses.ToWire(user.Status), user.Created, user.Updated, identities),
            version);

    // ── what travels ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NoPasswordTravelsWithAnAccount()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Password,
            UserCredentials.LocalHandle(user.UserId), "a-real-hash", null, Now, null));
        await temp.Store.AddCredentialAsync(Make.Identity(user.UserId, "discord:123", "haru#1"));

        ReplicatedAccount travelling = ReplicatedAccount.From(
            user, await temp.Store.ListCredentialsAsync(user.UserId));

        // Both handles are carried, because a session names its holder by one of them and a member
        // that lacks it cannot say who it has just verified. Neither secret is, so there is nothing
        // on the wire a member could authenticate anybody with — which is the whole property, and it
        // is about the hash rather than about which handles appear.
        Assert.Equal(
            ["discord:123", UserCredentials.LocalHandle(user.UserId)],
            travelling.Identities.Select(i => i.Handle).Order());
        Assert.DoesNotContain("a-real-hash", string.Join("|", travelling.Identities.Select(i => i.Handle + i.Label)));
    }

    /// <summary>
    /// A person who signs in with a KGSM password is named by the handle of that password —
    /// <c>local:&lt;user id&gt;</c> — and that handle is what a session's subject carries. It has to reach
    /// every member, or a session the cluster's anchor minted resolves to nobody everywhere else: the
    /// signature verifies, the account is there, and nothing joins the two.
    /// </summary>
    /// <remarks>
    /// The secret still does not travel, which is the property that matters. A handle is the name of a
    /// fact and a hash is evidence for it, and only the second one lets somebody in.
    /// </remarks>
    [Fact]
    public async Task TheHandleOfAPasswordTravelsEvenThoughThePasswordDoesNot()
    {
        using TempStore temp = new();
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Password,
            UserCredentials.LocalHandle(user.UserId), "a-real-hash", null, Now, null));

        ReplicatedAccount travelling = ReplicatedAccount.From(
            user, await temp.Store.ListCredentialsAsync(user.UserId));

        Assert.Contains(UserCredentials.LocalHandle(user.UserId), travelling.Identities.Select(i => i.Handle));
        Assert.DoesNotContain("a-real-hash", string.Join("|", travelling.Identities.Select(i => i.Handle + i.Label)));
    }

    /// <summary>
    /// The same fact from the receiving end: a member that took the account can resolve the person
    /// its session names, and still cannot verify a password for them.
    /// </summary>
    [Fact]
    public async Task AMemberThatTookAPasswordAccountCanResolveWhoTheSessionNames()
    {
        using TempStore source = new();
        KgsmUser user = Make.User(tier: KgsmTier.Admin);
        await source.Store.CreateAsync(user);
        await source.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Password,
            UserCredentials.LocalHandle(user.UserId), "a-real-hash", null, Now, null));

        var change = new AccountChange(
            ReplicatedAccount.From(user, await source.Store.ListCredentialsAsync(user.UserId)), 1);

        using TempStore member = new();
        (AccountReplica replica, _) = Replica(member);
        Assert.Equal(ReplicationOutcome.Applied, await replica.ApplyAsync(change, Now));

        // What a session minted by the anchor carries as its subject.
        string subject = UserCredentials.LocalHandle(user.UserId);

        KgsmUser? resolved = await member.Store.FindByCredentialAsync(subject);
        Assert.NotNull(resolved);
        Assert.Equal(KgsmTier.Admin, resolved.Tier);

        // And it still holds nothing anybody could sign in with.
        IReadOnlyList<UserCredential> held = await member.Store.ListCredentialsAsync(user.UserId);
        Assert.All(held, c => Assert.Null(c.Secret));
        Assert.DoesNotContain(held, c => c.Kind == CredentialKind.Password);
    }

    // ── applying ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AnAccountThisMemberHasNeverSeenIsCreated()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User(tier: KgsmTier.Admin);

        Assert.Equal(ReplicationOutcome.Applied, await replica.ApplyAsync(Change(user, 1), Now));

        KgsmUser? landed = await temp.Store.FindByIdAsync(user.UserId);
        Assert.NotNull(landed);
        Assert.Equal(KgsmTier.Admin, landed.Tier);
    }

    [Fact]
    public async Task AnAccountItAlreadyHoldsIsUpdated()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User(tier: KgsmTier.Admin);
        await replica.ApplyAsync(Change(user, 1), Now);

        await replica.ApplyAsync(Change(user with { Tier = KgsmTier.Viewer }, 2), Now);

        Assert.Equal(KgsmTier.Viewer, (await temp.Store.FindByIdAsync(user.UserId))!.Tier);
    }

    [Fact]
    public async Task TheSameChangeDeliveredTwiceIsAppliedOnce()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User();

        Assert.Equal(ReplicationOutcome.Applied, await replica.ApplyAsync(Change(user, 1), Now));

        // At-least-once delivery makes this the ordinary case, not an edge one.
        Assert.Equal(ReplicationOutcome.Stale, await replica.ApplyAsync(Change(user, 1), Now));
    }

    [Fact]
    public async Task ADisableIsNotUndoneByATierIssuedBeforeIt()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User(tier: KgsmTier.Admin);
        await replica.ApplyAsync(Change(user, 1), Now);

        // The disable is newer and arrives first. The promotion is older and arrives second — which
        // is the exact sequence that, unordered, hands an admin back to somebody just switched off.
        await replica.ApplyAsync(Change(user with { Status = UserStatus.Disabled }, 7), Now);
        Assert.Equal(
            ReplicationOutcome.Stale,
            await replica.ApplyAsync(Change(user with { Tier = KgsmTier.Admin }, 6), Now));

        KgsmUser? held = await temp.Store.FindByIdAsync(user.UserId);
        Assert.Equal(UserStatus.Disabled, held!.Status);
        Assert.Equal(KgsmTier.None, held.EffectiveTier);
    }

    // ── removal ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ARemovedAccountIsNotResurrectedByAnEarlierChange()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User();
        await replica.ApplyAsync(Change(user, 1), Now);

        Assert.Equal(ReplicationOutcome.Applied, await replica.RemoveAsync(new AccountRemoval(user.UserId, 5), Now));
        Assert.Null(await temp.Store.FindByIdAsync(user.UserId));

        // The version row outlived the account, so this is refused rather than re-creating somebody.
        Assert.Equal(ReplicationOutcome.Stale, await replica.ApplyAsync(Change(user, 4), Now));
        Assert.Null(await temp.Store.FindByIdAsync(user.UserId));
    }

    [Fact]
    public async Task ARemovalIsRecordedEvenForAnAccountThisMemberNeverHeld()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);

        // A member that missed the creation still has to record the removal, or a change predating
        // it would arrive later and create somebody who is gone.
        Assert.Equal(
            ReplicationOutcome.Applied,
            await replica.RemoveAsync(new AccountRemoval("usr_never_seen", 9), Now));
        Assert.Equal(
            ReplicationOutcome.Stale,
            await replica.ApplyAsync(Change(Make.User(userId: "usr_never_seen"), 8), Now));
    }

    // ── identities ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ExternalIdentitiesArriveSoAuthorityResolvesLocally()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User();

        await replica.ApplyAsync(Change(user, 1, new ReplicatedIdentity("discord:123", "haru")), Now);

        // This is what lets a member answer "who is discord:123" without asking anybody.
        KgsmUser? byIdentity = await temp.Store.FindByCredentialAsync("discord:123");
        Assert.Equal(user.UserId, byIdentity?.UserId);
    }

    [Fact]
    public async Task AnIdentityTheWriterDroppedIsDroppedHereToo()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User();
        await replica.ApplyAsync(Change(user, 1, new ReplicatedIdentity("discord:123", null)), Now);

        await replica.ApplyAsync(Change(user, 2), Now);

        // Disconnecting an account has to travel, or the identity keeps resolving to it here.
        Assert.Null(await temp.Store.FindByCredentialAsync("discord:123"));
    }

    [Fact]
    public async Task APasswordThisMachineAlreadyHeldIsNotTouched()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        await temp.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Password,
            UserCredentials.LocalHandle(user.UserId), "local-hash", null, Now, null));

        await replica.ApplyAsync(Change(user with { Tier = KgsmTier.Viewer }, 1), Now);

        // Replication carries no password, so it must not be read as "this account has none" and
        // erase one this machine had before it joined.
        UserCredential? password =
            await temp.Store.FindCredentialAsync(UserCredentials.LocalHandle(user.UserId));
        Assert.Equal("local-hash", password?.Secret);
    }

    // ── refusals ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AUsernameAnotherLocalAccountHoldsIsReportedRatherThanMerged()
    {
        using TempStore temp = new();
        (AccountReplica replica, IAccountVersions versions) = Replica(temp);
        await temp.Store.CreateAsync(Make.User(username: "haru"));

        // A different account, same name — the adoption case, where a machine had its own accounts
        // before it joined. Merging on a shared username is the documented account-takeover route.
        KgsmUser arriving = Make.User(username: "haru");
        Assert.Equal(ReplicationOutcome.UsernameConflict, await replica.ApplyAsync(Change(arriving, 1), Now));

        Assert.Null(await temp.Store.FindByIdAsync(arriving.UserId));

        // And the version is NOT advanced, so a snapshot or a redelivery can still resolve it once
        // the conflict is dealt with — rather than the account being permanently skipped.
        Assert.Equal(0, await versions.CurrentAsync(arriving.UserId));
    }

    [Fact]
    public async Task ASnapshotReportsWhatItCouldNotTake()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        await temp.Store.CreateAsync(Make.User(username: "taken"));

        KgsmUser fine = Make.User(username: "arrives");
        KgsmUser clashing = Make.User(username: "taken");

        IReadOnlyList<AccountChange> refused = await replica.ApplySnapshotAsync(
            new AccountSnapshot([Change(fine, 1), Change(clashing, 1)]), Now);

        // One conflict does not stop the rest landing, and the one that did not land is named
        // rather than counted.
        Assert.NotNull(await temp.Store.FindByIdAsync(fine.UserId));
        Assert.Equal([clashing.UserId], refused.Select(r => r.Account.UserId));
    }

    [Fact]
    public async Task AnUnknownTierFromANewerMemberResolvesToNothing()
    {
        using TempStore temp = new();
        (AccountReplica replica, _) = Replica(temp);
        KgsmUser user = Make.User();

        var arriving = new AccountChange(
            new ReplicatedAccount(
                user.UserId, user.Username, user.DisplayName,
                Tier: "superuser", TierSource: "granted", Status: "active",
                user.Created, user.Updated, []),
            1);

        await replica.ApplyAsync(arriving, Now);

        // Fail-closed, the same rule the store applies to every value it parses: a tier this build
        // has never heard of grants nothing rather than throwing and wedging a queue.
        Assert.Equal(KgsmTier.None, (await temp.Store.FindByIdAsync(user.UserId))!.Tier);
    }
}
