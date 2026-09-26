using System.Text.Json;

using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Cluster;
using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// The catalog over a real cluster: an auth anchor and two nodes on real ports, reporting across the
/// bus, one node going quiet and the other being removed.
/// </summary>
/// <remarks>
/// In the anchor's collection because the journal's state root is a process environment variable.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class CatalogBusTests : IAsyncLifetime
{
    private BusCluster _cluster = null!;
    private BusMember _anchor = null!;
    private BusMember _walter = null!;
    private BusMember _jessie = null!;

    public async Task InitializeAsync()
    {
        _cluster = await BusCluster.StartAsync("walter", "jessie");
        _anchor = _cluster.Anchor;
        _walter = _cluster["walter"];
        _jessie = _cluster["jessie"];
    }

    public async Task DisposeAsync() => await _cluster.DisposeAsync();

    // ── helpers ───────────────────────────────────────────────────────────────────────────────

    private SqliteAuthorityStore Store => _cluster.Store;

    private static void Write(BusMember node, string file, string component, string? version, params (string Id, string Effect, string Scope)[] actions) =>
        File.WriteAllText(Path.Combine(node.Manifests, file), JsonSerializer.Serialize(
            new ActionManifest(1, component, version,
                [.. actions.Select(a => new ManifestAction(a.Id, a.Id, a.Effect, a.Scope, null))],
                component == "reactor" ? [new ManifestRequirement("kgsm:server.restart", "instance", "restart a crashed server")] : []),
            AccessJsonContext.Default.ActionManifest));

    private static void Engine(BusMember node) =>
        Write(node, "kgsm.json", "kgsm", "3.18.0", ("server.start", "execute", "instance"), ("server.restart", "execute", "instance"));

    /// <summary>Wait for the anchor to see what the bus is carrying to it.</summary>
    private static Task EventuallyAsync(Func<Task<bool>> condition, string what) =>
        BusCluster.EventuallyAsync(condition, what);

    private async Task<string[]> CatalogIdsAsync() => [.. (await Store.CatalogAsync()).Select(e => e.Action.Id)];

    private string Person(string username)
    {
        string id = UserIds.NewUserId();
        using SqliteConnection connection = new($"Data Source={_anchor.Resolve<AnchorOptions>().UserStorePath}");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"""
             INSERT INTO users (user_id, username, username_key, display_name, origin, kind, status, created_utc, updated_utc)
             VALUES ('{id}', '{username}', '{username}', '{username}', 'admitted', 'person', 'active', '2026-09-26T00:00:00Z', '2026-09-26T00:00:00Z');
             """;
        command.ExecuteNonQuery();
        return id;
    }

    private async Task ReportBothAsync()
    {
        Assert.True(await _walter.Resolve<AuthorityReporter>().ReportIfDueAsync(default));
        Assert.True(await _jessie.Resolve<AuthorityReporter>().ReportIfDueAsync(default));
    }

    // ── the catalog ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TwoNodesAtDifferentVersionsAddUpToOneCatalog()
    {
        Engine(_walter);
        Engine(_jessie);
        Write(_walter, "reactor.json", "reactor", "0.4.0", ("rules.write", "write", "node"), ("rules.legacy", "read", "node"));
        Write(_jessie, "reactor.json", "reactor", "0.5.0", ("rules.write", "write", "node"), ("rules.read", "read", "node"));

        await ReportBothAsync();
        await EventuallyAsync(async () => (await CatalogIdsAsync()).Length == 5, "both reports");

        IReadOnlyList<CatalogEntry> catalog = await Store.CatalogAsync();
        Assert.Equal(
            ["kgsm:server.restart", "kgsm:server.start", "reactor:rules.legacy", "reactor:rules.read", "reactor:rules.write"],
            catalog.Select(e => e.Action.Id));
        Assert.Equal(
            [new ActionDeclaration("jessie", "0.5.0"), new ActionDeclaration("walter", "0.4.0")],
            catalog.Single(e => e.Action.Id == "reactor:rules.write").DeclaredBy);

        // Each node's reactor is a service of its own, approved on its own node.
        AuthoritySnapshot s = await Store.LoadAsync();
        Assert.Equal(["jessie", "walter"], s.Accounts.Values.Where(a => a.Service?.Component == "reactor").Select(a => a.Service!.Member).Order());
        string walterReactor = s.Accounts.Values.Single(a => a.Service == new ServiceIdentity("reactor", "walter")).AccountId;
        AccessEvaluator evaluator = new(s);
        Assert.True(evaluator.Allows(walterReactor, "kgsm:server.restart", AccessScope.ForInstance("walter", "terraria", "aaaa")).Allowed);
        Assert.False(evaluator.Allows(walterReactor, "kgsm:server.restart", AccessScope.ForInstance("jessie", "terraria", "bbbb")).Allowed);
    }

    [Fact]
    public async Task AnOfflineNodeKeepsItsActionsAndARemovedOneLosesThoseOnlyItDeclared()
    {
        Engine(_walter);
        Engine(_jessie);
        Write(_walter, "reactor.json", "reactor", "0.4.0", ("rules.write", "write", "node"), ("rules.legacy", "read", "node"));
        Write(_jessie, "reactor.json", "reactor", "0.5.0", ("rules.write", "write", "node"), ("rules.read", "read", "node"));
        await ReportBothAsync();
        await EventuallyAsync(async () => (await CatalogIdsAsync()).Length == 5, "both reports");

        // Jessie goes quiet. Its report stands: a node down for a week keeps every action it declared.
        await _jessie.DisposeAsync();
        await _anchor.Resolve<MemberDepartureWorker>().SweepAsync(default);
        Assert.Contains("reactor:rules.read", await CatalogIdsAsync());

        // Walter is removed from the cluster. What only it declared leaves; what jessie also declares stays.
        MembersStore roster = _anchor.Resolve<MembersStore>();
        MemberRow walter = (await roster.GetByMemberIdAsync("walter", default))!;
        await roster.MarkLeftAsync(walter.Id, DateTimeOffset.UtcNow, default);
        await _anchor.Resolve<MemberDepartureWorker>().SweepAsync(default);

        string[] catalog = await CatalogIdsAsync();
        Assert.DoesNotContain("reactor:rules.legacy", catalog);
        Assert.Contains("reactor:rules.write", catalog);
        Assert.Contains("reactor:rules.read", catalog);
        Assert.DoesNotContain((await Store.LoadAsync()).Accounts.Values, a => a.Service?.Member == "walter");
        Assert.Equal(["jessie"], await Store.ReportingMembersAsync());
    }

    [Fact]
    public async Task AChangedManifestIsReportedAgainAndAnUnchangedOneIsNot()
    {
        Engine(_walter);
        AuthorityReporter reporter = _walter.Resolve<AuthorityReporter>();
        Assert.True(await reporter.ReportIfDueAsync(default));
        Assert.False(await reporter.ReportIfDueAsync(default));

        Write(_walter, "reactor.json", "reactor", "0.4.0", ("rules.write", "write", "node"));
        Assert.True(await reporter.ReportIfDueAsync(default));

        await EventuallyAsync(async () => (await CatalogIdsAsync()).Contains("reactor:rules.write"), "the changed report");
    }

    // ── instances ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AnUninstallTakesItsGrantsAndAReinstallUnderTheSameNameGetsNone()
    {
        Engine(_walter);
        await _walter.Resolve<AuthorityReporter>().ReportIfDueAsync(default);
        await EventuallyAsync(async () => (await CatalogIdsAsync()).Length == 2, "the engine's report");

        string owner = Person("owner");
        await Store.GrantOwnerLocallyAsync("owner", "local:test", DateTimeOffset.UtcNow);
        string alice = Person("alice");
        string permission = (await Store.ApplyAsync(owner, new CreatePermission("Run"), await Store.VersionAsync(), DateTimeOffset.UtcNow)).CreatedId!;
        await Store.ApplyAsync(owner, new SetPermissionActions(permission, new HashSet<string> { "kgsm:server.start" }), await Store.VersionAsync(), DateTimeOffset.UtcNow);
        string role = (await Store.ApplyAsync(owner, new CreateRole("Runner"), await Store.VersionAsync(), DateTimeOffset.UtcNow)).CreatedId!;
        await Store.ApplyAsync(owner, new SetRolePermissions(role, new HashSet<string> { permission }), await Store.VersionAsync(), DateTimeOffset.UtcNow);

        AccessScope first = AccessScope.ForInstance("walter", "terraria", "aaaa1111aaaa1111");
        AccessScope second = AccessScope.ForInstance("walter", "terraria", "bbbb2222bbbb2222");
        await Store.ApplyAsync(owner, new Assign(alice, role, first), await Store.VersionAsync(), DateTimeOffset.UtcNow);
        Assert.True(new AccessEvaluator(await Store.LoadAsync()).Allows(alice, "kgsm:server.start", first).Allowed);

        // Terraria is uninstalled on walter, and installed again under the same name.
        Assert.True(await _walter.Resolve<AuthorityReporter>().ReportUninstalledAsync("terraria", "aaaa1111aaaa1111", default));
        await EventuallyAsync(async () => (await Store.LoadAsync()).AssignmentsOf(alice).Count == 0, "the uninstall");

        AccessEvaluator evaluator = new(await Store.LoadAsync());
        Assert.False(evaluator.Allows(alice, "kgsm:server.start", first).Allowed);
        Assert.False(evaluator.Allows(alice, "kgsm:server.start", second).Allowed);

        // A grant on the new install is not taken by a late message about the old one.
        await Store.ApplyAsync(owner, new Assign(alice, role, second), await Store.VersionAsync(), DateTimeOffset.UtcNow);
        await _walter.Resolve<AuthorityReporter>().ReportUninstalledAsync("terraria", "aaaa1111aaaa1111", default);
        await SentinelAsync(owner, alice, role);

        Assert.True(new AccessEvaluator(await Store.LoadAsync()).Allows(alice, "kgsm:server.start", second).Allowed);
    }

    /// <summary>
    /// A grant on a throwaway install, and its uninstall sent after whatever the test sent before. The
    /// drainer sends to a reachable member in the order messages were queued, so the anchor having taken
    /// this one shows the earlier one landed, where a delay would show nothing.
    /// </summary>
    private async Task SentinelAsync(string owner, string account, string role)
    {
        AccessScope sentinel = AccessScope.ForInstance("walter", "sentinel", "ffff0000ffff0000");
        await Store.ApplyAsync(owner, new Assign(account, role, sentinel), await Store.VersionAsync(), DateTimeOffset.UtcNow);
        await _walter.Resolve<AuthorityReporter>().ReportUninstalledAsync("sentinel", "ffff0000ffff0000", default);
        await EventuallyAsync(
            async () => !(await Store.LoadAsync()).AssignmentsOf(account).Any(a => a.Scope == sentinel), "the sentinel's uninstall");
    }

    [Fact]
    public async Task ANodeSpeaksOnlyForItsOwnInstances()
    {
        Engine(_walter);
        await _walter.Resolve<AuthorityReporter>().ReportIfDueAsync(default);
        await EventuallyAsync(async () => (await CatalogIdsAsync()).Length == 2, "the engine's report");

        string owner = Person("owner");
        await Store.GrantOwnerLocallyAsync("owner", "local:test", DateTimeOffset.UtcNow);
        string alice = Person("alice");
        AccessScope onJessie = AccessScope.ForInstance("jessie", "terraria", "cccc3333cccc3333");
        await Store.ApplyAsync(owner, new Assign(alice, BuiltInRoles.OwnerId, AccessScope.Cluster), await Store.VersionAsync(), DateTimeOffset.UtcNow);
        string role = (await Store.ApplyAsync(owner, new CreateRole("Anything"), await Store.VersionAsync(), DateTimeOffset.UtcNow)).CreatedId!;
        await Store.ApplyAsync(owner, new Assign(alice, role, onJessie), await Store.VersionAsync(), DateTimeOffset.UtcNow);

        // Walter names jessie's install's nonce: the anchor reads it as walter's instance, which it is not.
        await _walter.Resolve<AuthorityReporter>().ReportUninstalledAsync("terraria", "cccc3333cccc3333", default);
        await SentinelAsync(owner, alice, role);

        Assert.Contains((await Store.LoadAsync()).AssignmentsOf(alice), a => a.Scope == onJessie);
    }
}
