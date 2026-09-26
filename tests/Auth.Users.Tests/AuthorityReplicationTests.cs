using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;

namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// The authority moving from the anchor's store to a replica: what a write owes, each record applied on
/// its own version in any order, the snapshot a member builds from, and the staleness bound.
/// </summary>
public sealed class AuthorityReplicationTests : IDisposable
{
    private const string Start = "kgsm:server.start";
    private const string Console = "kgsm:server.console.read";

    private static readonly AccessScope Terraria = AccessScope.ForInstance("walter", "terraria", "9f3c");
    private static readonly TimeSpan Bound = TimeSpan.FromMinutes(5);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "kgsm-replication-" + Guid.NewGuid().ToString("N"));
    private readonly SqliteAuthorityStore _anchor;
    private readonly SqliteAuthorityStore _replica;
    private readonly string _anchorPath;
    private readonly DateTimeOffset _now = new(2026, 9, 26, 12, 0, 0, TimeSpan.Zero);

    public AuthorityReplicationTests()
    {
        _anchorPath = Path.Combine(_directory, "anchor.db");
        _anchor = new SqliteAuthorityStore(new UserStoreOptions { Path = _anchorPath });
        _replica = new SqliteAuthorityStore(new UserStoreOptions { Path = Path.Combine(_directory, "replica.db") });
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────────────────────

    private string Person(string username)
    {
        string id = UserIds.NewUserId();
        using SqliteConnection connection = new($"Data Source={_anchorPath};Foreign Keys=True");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"""
             INSERT INTO users (user_id, username, username_key, display_name, origin, kind, status, created_utc, updated_utc)
             VALUES ('{id}', '{username}', '{username}', '{username}', 'admitted', 'person', 'active',
                     '2026-09-26T12:00:00.0000000+00:00', '2026-09-26T12:00:00.0000000+00:00');
             INSERT INTO credentials (credential_id, user_id, kind, handle, secret, label, created_utc)
             VALUES ('cred_{id}', '{id}', 'password', 'local:{id}', 'hash', NULL, '2026-09-26T12:00:00.0000000+00:00');
             """;
        command.ExecuteNonQuery();
        return id;
    }

    /// <summary>
    /// A catalog, an Owner, and a person holding a role that starts servers on Terraria. With
    /// <paramref name="join"/>, the replica takes a snapshot once the accounts exist, the way a member
    /// joining does, and everything after it reaches the replica only through what the anchor owes.
    /// </summary>
    private async Task<(string Owner, string Alice, string Role, string Assignment)> SeedAsync(bool join = true)
    {
        await _anchor.ReplaceCatalogAsync(
        [
            .. AuthActions.Declared,
            new CatalogAction(Start, "Start servers", ActionEffect.Execute, ScopeKind.Instance),
            new CatalogAction(Console, "Read consoles", ActionEffect.Read, ScopeKind.Instance),
        ], _now);

        string owner = Person("owner");
        await _anchor.GrantOwnerLocallyAsync("owner", "local:heisen", _now);
        string alice = Person("alice");

        if (join)
        {
            // An hour ago, so a test that wants the replica current confirms it itself.
            DateTimeOffset joined = _now - TimeSpan.FromHours(1);
            await _replica.ApplySnapshotAsync(await _anchor.ExportAsync(Bound, joined), joined);
            await DrainAsync();
        }

        string permission = (await Edit(owner, new CreatePermission("Run servers"))).CreatedId!;
        await Edit(owner, new SetPermissionActions(permission, new HashSet<string> { Start, Console }));
        string role = (await Edit(owner, new CreateRole("Server manager"))).CreatedId!;
        await Edit(owner, new SetRolePermissions(role, new HashSet<string> { permission }));
        string assignment = (await Edit(owner, new Assign(alice, role, Terraria))).CreatedId!;

        return (owner, alice, role, assignment);
    }

    private async Task<AuthorityWrite> Edit(string actor, AuthorityEdit edit) =>
        await _anchor.ApplyAsync(actor, edit, await _anchor.VersionAsync(), _now);

    /// <summary>What the anchor owes, as the messages the broadcast would send, and the owed rows cleared.</summary>
    private async Task<List<Func<Task<AuthorityApplyOutcome>>>> DrainAsync() =>
        [.. (await DrainKeyedAsync()).Select(s => s.Send)];

    private async Task<List<(AuthorityRecordKey Key, Func<Task<AuthorityApplyOutcome>> Send)>> DrainKeyedAsync()
    {
        List<(AuthorityRecordKey, Func<Task<AuthorityApplyOutcome>>)> sends = [];
        foreach (AuthorityAnnouncement owed in await _anchor.PendingAnnouncementsAsync())
        {
            sends.Add((owed.Key, await MessageAsync(owed)));
            await _anchor.ClearAnnouncementAsync(owed.Key, owed.Version);
        }

        return sends;
    }

    private async Task<Func<Task<AuthorityApplyOutcome>>> MessageAsync(AuthorityAnnouncement owed)
    {
        if (owed.Removed)
            return () => _replica.RemoveAsync(owed.Key, owed.Version, _now);

        switch (owed.Key.Kind)
        {
            case AuthorityRecordKind.Account:
                AccountRecord account = (await _anchor.ReadAccountRecordAsync(owed.Key.Id))!;
                return () => _replica.ApplyAsync(account, _now);
            case AuthorityRecordKind.Role:
                RoleRecord role = (await _anchor.ReadRoleRecordAsync(owed.Key.Id))!;
                return () => _replica.ApplyAsync(role, _now);
            case AuthorityRecordKind.Permission:
                PermissionRecord permission = (await _anchor.ReadPermissionRecordAsync(owed.Key.Id))!;
                return () => _replica.ApplyAsync(permission, _now);
            case AuthorityRecordKind.Assignment:
                AssignmentRecord assignment = (await _anchor.ReadAssignmentRecordAsync(owed.Key.Id))!;
                return () => _replica.ApplyAsync(assignment, _now);
            default:
                CatalogRecord catalog = await _anchor.ReadCatalogRecordAsync();
                return () => _replica.ApplyAsync(catalog, _now);
        }
    }

    private async Task DeliverAsync(IEnumerable<Func<Task<AuthorityApplyOutcome>>> sends)
    {
        foreach (Func<Task<AuthorityApplyOutcome>> send in sends)
            await send();
    }

    private async Task ConfirmAsync() =>
        Assert.True(await _replica.ConfirmAsync(
            new AuthorityCurrent(await _anchor.VersionAsync(), (int)Bound.TotalSeconds, AccessContract.Version, _now), _now));

    private AccessEvaluator Evaluator(AuthoritySnapshot snapshot, DateTimeOffset at) =>
        new(snapshot, new FixedClock(at));

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    // ── what a write owes ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task EveryRecordAWriteTouches_IsOwedAtItsVersion_AndClearingLeavesALaterOne()
    {
        (string owner, _, string role, _) = await SeedAsync();
        await DrainAsync();

        AuthorityWrite renamed = await Edit(owner, new RenameRole(role, "Operators"));
        AuthorityAnnouncement owed = Assert.Single(await _anchor.PendingAnnouncementsAsync());
        Assert.Equal(AuthorityRecordKey.Role(role), owed.Key);
        Assert.Equal(renamed.Version, owed.Version);
        Assert.False(owed.Removed);

        await _anchor.ClearAnnouncementAsync(owed.Key, owed.Version - 1);
        Assert.Single(await _anchor.PendingAnnouncementsAsync());

        await _anchor.ClearAnnouncementAsync(owed.Key, owed.Version);
        Assert.Empty(await _anchor.PendingAnnouncementsAsync());
    }

    [Fact]
    public async Task DeletingARole_OwesTheRoleAndEachAssignmentAsRemovals()
    {
        (string owner, _, string role, string assignment) = await SeedAsync();
        await DrainAsync();

        await Edit(owner, new DeleteRole(role));

        IReadOnlyList<AuthorityAnnouncement> owed = await _anchor.PendingAnnouncementsAsync();
        Assert.Contains(new AuthorityAnnouncement(AuthorityRecordKey.Role(role), await _anchor.VersionAsync(), true), owed);
        Assert.Contains(new AuthorityAnnouncement(AuthorityRecordKey.Assignment(assignment), await _anchor.VersionAsync(), true), owed);
    }

    [Fact]
    public async Task AReportChangingNothing_OwesNothing()
    {
        await SeedAsync();
        await DrainAsync();

        await _anchor.ReplaceCatalogAsync((await _anchor.LoadAsync()).Catalog.Values.ToList(), _now);

        Assert.Empty(await _anchor.PendingAnnouncementsAsync());
    }

    [Fact]
    public async Task ACreatedServiceAccount_IsOwedWithItsRequirements()
    {
        await SeedAsync();
        await DrainAsync();

        await _anchor.DeclareRequirementsAsync(
            new ServiceIdentity("reactor", "walter"), anchor: false,
            [new DeclaredRequirement(Start, ScopeKind.Instance, "restart on crash")], _now);

        AuthorityAnnouncement owed = Assert.Single(await _anchor.PendingAnnouncementsAsync());
        AccountRecord account = (await _anchor.ReadAccountRecordAsync(owed.Key.Id))!;
        Assert.Equal(new ServiceRecord("reactor", "walter"), account.Service);
        RequirementRecord requirement = Assert.Single(account.Requirements);
        Assert.Equal(Start, requirement.Action);
        Assert.Equal("node:walter", requirement.Grant);
    }

    [Fact]
    public async Task AnAccountTravels_WithItsHandles_AndNeverASecret()
    {
        (_, string alice, _, _) = await SeedAsync();

        AccountRecord record = (await _anchor.ReadAccountRecordAsync(alice))!;
        ReplicatedIdentity identity = Assert.Single(record.Identities);
        Assert.Equal($"local:{alice}", identity.Handle);
        Assert.Null(identity.Label);

        await _replica.ApplyAsync(record, _now);
        Assert.Equal(alice, await _replica.FindAccountIdByHandleAsync($"local:{alice}"));

        using SqliteConnection connection = new($"Data Source={Path.Combine(_directory, "replica.db")}");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM credentials WHERE secret IS NOT NULL;";
        Assert.Equal(0L, command.ExecuteScalar());
    }

    // ── applying, in any order ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AReplicaFollowingTheStream_AnswersAsTheAnchorDoes()
    {
        (_, string alice, _, _) = await SeedAsync();
        await DeliverAsync(await DrainAsync());
        await ConfirmAsync();

        AccessEvaluator replica = Evaluator(await _replica.LoadAsync(await Freshness()), _now);
        Assert.True(replica.Allows(alice, Start, Terraria).Allowed);
        Assert.False(replica.Allows(alice, Start, AccessScope.ForInstance("walter", "valheim", "1111")).Allowed);
    }

    [Fact]
    public async Task ARoleChangedArrivingAfterItsRemoval_IsIgnored()
    {
        (string owner, string alice, string role, _) = await SeedAsync();
        await DeliverAsync(await DrainAsync());

        await Edit(owner, new RenameRole(role, "Operators"));
        List<Func<Task<AuthorityApplyOutcome>>> renamed = await DrainAsync();
        await Edit(owner, new DeleteRole(role));
        List<Func<Task<AuthorityApplyOutcome>>> removed = await DrainAsync();

        await DeliverAsync(removed);
        Assert.Equal(AuthorityApplyOutcome.Stale, await Assert.Single(renamed)());

        AuthoritySnapshot snapshot = await _replica.LoadAsync();
        Assert.False(snapshot.Roles.ContainsKey(role));
        Assert.Empty(snapshot.AssignmentsOf(alice));
    }

    [Fact]
    public async Task AnAssignmentArrivingBeforeItsRole_GrantsFromTheMomentTheRoleArrives()
    {
        (_, string alice, string role, _) = await SeedAsync();

        // Owed oldest first; delivered newest first, so the assignment lands before its role.
        List<Func<Task<AuthorityApplyOutcome>>> sends = await DrainAsync();
        sends.Reverse();

        Assert.Equal(AuthorityApplyOutcome.Applied, await sends[0]());
        await ConfirmAsync();
        AuthoritySnapshot early = await _replica.LoadAsync(await Freshness());
        Assert.Single(early.AssignmentsOf(alice));
        Assert.False(early.Roles.ContainsKey(role));
        Assert.False(Evaluator(early, _now).Allows(alice, Start, Terraria).Allowed);

        foreach (Func<Task<AuthorityApplyOutcome>> send in sends.Skip(1))
            Assert.Equal(AuthorityApplyOutcome.Applied, await send());

        Assert.True(Evaluator(await _replica.LoadAsync(await Freshness()), _now).Allows(alice, Start, Terraria).Allowed);
    }

    [Fact]
    public async Task TheSameChangeDeliveredTwice_AppliesOnce()
    {
        await SeedAsync();
        List<Func<Task<AuthorityApplyOutcome>>> sends = await DrainAsync();

        await DeliverAsync(sends);
        long generation = await _replica.GenerationAsync();

        foreach (Func<Task<AuthorityApplyOutcome>> send in sends)
            Assert.Equal(AuthorityApplyOutcome.Stale, await send());

        Assert.Equal(generation, await _replica.GenerationAsync());
    }

    [Fact]
    public async Task ARemovedAccount_TakesItsAssignmentsWithIt_AndALateGrantCannotReturnThem()
    {
        (string owner, string alice, _, string assignment) = await SeedAsync();
        List<Func<Task<AuthorityApplyOutcome>>> seeded = await DrainAsync();
        await DeliverAsync(seeded);

        await Edit(owner, new DeleteAccount(alice));
        foreach (AuthorityAnnouncement owed in await _anchor.PendingAnnouncementsAsync())
        {
            if (owed.Key.Kind == AuthorityRecordKind.Account)
                await (await MessageAsync(owed))();
        }

        Assert.Empty((await _replica.LoadAsync()).AssignmentsOf(alice));

        AssignmentRecord late = new(assignment, alice, BuiltInRoles.EveryoneId, Terraria.ToString(), owner, _now, 2);
        Assert.Equal(AuthorityApplyOutcome.Stale, await _replica.ApplyAsync(late, _now));
    }

    [Fact]
    public async Task ANameStillHeldByAnotherRecord_DefersTheChange()
    {
        (string owner, _, string role, _) = await SeedAsync();
        await DeliverAsync(await DrainAsync());

        // "Server manager" is renamed away and a new role takes the name; the new role arrives first.
        await Edit(owner, new RenameRole(role, "Operators"));
        List<Func<Task<AuthorityApplyOutcome>>> renamed = await DrainAsync();
        string created = (await Edit(owner, new CreateRole("Server manager"))).CreatedId!;
        Func<Task<AuthorityApplyOutcome>> newRole =
            (await DrainKeyedAsync()).Single(s => s.Key == AuthorityRecordKey.Role(created)).Send;

        Assert.Equal(AuthorityApplyOutcome.Deferred, await newRole());

        await DeliverAsync(renamed);
        Assert.Equal(AuthorityApplyOutcome.Applied, await newRole());
    }

    // ── the snapshot ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ASnapshot_BuildsAReplicaFromNothing_AndConfirmsIt()
    {
        (_, string alice, _, _) = await SeedAsync(join: false);

        AuthorityReplicaSnapshot snapshot = await _anchor.ExportAsync(Bound, _now);
        Assert.Equal(0, await _replica.ApplySnapshotAsync(snapshot, _now));

        ReplicaState state = await _replica.ReplicaStateAsync();
        Assert.Equal(snapshot.Version, state.Version);
        Assert.True(state.Freshness.IsCurrent(_now));
        Assert.True(Evaluator(await _replica.LoadAsync(state.Freshness), _now).Allows(alice, Start, Terraria).Allowed);
    }

    [Fact]
    public async Task ASnapshot_RemovesWhatTheAnchorNoLongerHolds_AndKeepsWhatArrivedAfterIt()
    {
        (string owner, string alice, string role, _) = await SeedAsync();
        await DeliverAsync(await DrainAsync());

        // The role is deleted and the replica misses the removal; a later assignment reaches it first.
        await Edit(owner, new DeleteRole(role));
        await DrainAsync();
        AuthorityReplicaSnapshot snapshot = await _anchor.ExportAsync(Bound, _now);

        string viewers = (await Edit(owner, new CreateRole("Viewers"))).CreatedId!;
        string later = (await Edit(owner, new Assign(alice, viewers, Terraria))).CreatedId!;
        await DeliverAsync(await DrainAsync());

        await _replica.ApplySnapshotAsync(snapshot, _now);

        AuthoritySnapshot held = await _replica.LoadAsync();
        Assert.False(held.Roles.ContainsKey(role));
        Assert.True(held.Roles.ContainsKey(viewers));
        Assert.Equal(later, Assert.Single(held.AssignmentsOf(alice)).AssignmentId);
    }

    // ── staleness ─────────────────────────────────────────────────────────────────────────────

    private async Task<AuthorityFreshness> Freshness() => (await _replica.ReplicaStateAsync()).Freshness;

    [Fact]
    public async Task AReplicaPastTheBound_RefusesAWriteAndServesARead_OwnerIncluded()
    {
        (string owner, string alice, _, _) = await SeedAsync();
        await _replica.ApplySnapshotAsync(await _anchor.ExportAsync(Bound, _now), _now);
        AuthoritySnapshot snapshot = await _replica.LoadAsync(await Freshness());

        DateTimeOffset within = _now + Bound;
        Assert.True(Evaluator(snapshot, within).Allows(owner, Start, Terraria).Allowed);

        AccessEvaluator past = Evaluator(snapshot, within + TimeSpan.FromSeconds(1));
        Assert.Equal(DenyReason.Stale, past.Allows(owner, Start, Terraria).Reason);
        Assert.Equal(DenyReason.Stale, past.Allows(alice, Start, Terraria).Reason);
        Assert.True(past.Allows(owner, Console, Terraria).Allowed);
        Assert.True(past.Allows(alice, Console, Terraria).Allowed);
    }

    [Fact]
    public async Task AReplicaNeverConfirmed_IsStale()
    {
        (string owner, _, _, _) = await SeedAsync(join: false);
        await DeliverAsync(await DrainAsync());
        await _replica.ApplyAsync((await _anchor.ReadAccountRecordAsync(owner))!, _now);

        Assert.Equal(DenyReason.Stale,
            Evaluator(await _replica.LoadAsync(await Freshness()), _now).Allows(owner, Start, Terraria).Reason);
    }

    [Fact]
    public async Task AHeartbeatAheadOfTheReplica_DoesNotConfirmIt()
    {
        await SeedAsync();
        long version = await _anchor.VersionAsync();

        Assert.False(await _replica.ConfirmAsync(new AuthorityCurrent(version, 300, AccessContract.Version, _now), _now));
        Assert.False((await Freshness()).IsCurrent(_now));
    }

    [Fact]
    public async Task ALateHeartbeat_ConfirmsTheMomentItWasSent()
    {
        await SeedAsync();
        await DeliverAsync(await DrainAsync());

        DateTimeOffset sent = _now - TimeSpan.FromMinutes(10);
        Assert.True(await _replica.ConfirmAsync(new AuthorityCurrent(await _anchor.VersionAsync(), 300, AccessContract.Version, sent), _now));
        Assert.False((await Freshness()).IsCurrent(_now));
    }

    [Fact]
    public async Task AHeartbeat_CarriesTheBoundAndTheMinimumContract()
    {
        await SeedAsync();
        await DeliverAsync(await DrainAsync());

        await _replica.ConfirmAsync(new AuthorityCurrent(await _anchor.VersionAsync(), 60, AccessContract.Version + 1, _now), _now);
        ReplicaState state = await _replica.ReplicaStateAsync();

        Assert.Equal(TimeSpan.FromSeconds(60), state.Freshness.Bound);
        Assert.Equal(AccessContract.Version + 1, state.MinimumContractVersion);
    }

    // ── the cache ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TheSource_KeepsItsSnapshotUntilSomethingChanges_AndSeesTheChangeOnTheNextCall()
    {
        (string owner, string alice, string role, _) = await SeedAsync();
        await DeliverAsync(await DrainAsync());
        await ConfirmAsync();

        AuthoritySource source = new(_replica, AuthorityStanding.Replica, new FixedClock(_now));
        AuthoritySnapshot first = await source.CurrentAsync();
        Assert.Same(first, await source.CurrentAsync());
        Assert.True((await source.EvaluatorAsync()).Allows(alice, Start, Terraria).Allowed);

        await Edit(owner, new SetRolePermissions(role, new HashSet<string>()));
        await DeliverAsync(await DrainAsync());

        Assert.NotSame(first, await source.CurrentAsync());
        Assert.False((await source.EvaluatorAsync()).Allows(alice, Start, Terraria).Allowed);
    }

    [Fact]
    public async Task TheSource_LaysANewConfirmationOverTheSnapshotWithoutReloadingIt()
    {
        await SeedAsync();
        await DeliverAsync(await DrainAsync());

        AuthoritySource source = new(_replica, AuthorityStanding.Replica, new FixedClock(_now));
        AuthoritySnapshot stale = await source.CurrentAsync();
        Assert.False(stale.Freshness.IsCurrent(_now));

        await ConfirmAsync();
        AuthoritySnapshot current = await source.CurrentAsync();

        Assert.True(current.Freshness.IsCurrent(_now));
        Assert.Same(stale.Roles, current.Roles);
    }

    [Fact]
    public async Task TheAnchorsSource_IsAlwaysCurrent()
    {
        (string owner, _, _, _) = await SeedAsync();

        AuthoritySource source = new(_anchor, AuthorityStanding.Anchor, new FixedClock(_now + TimeSpan.FromDays(30)));
        Assert.True((await source.EvaluatorAsync()).Allows(owner, Start, Terraria).Allowed);
    }
}
