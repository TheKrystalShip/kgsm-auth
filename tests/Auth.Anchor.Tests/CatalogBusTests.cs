using System.Text.Json;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Cluster;
using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;
using TheKrystalShip.KGSM.Extensions;

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
    private const string Secret = "catalog-bus-secret";
    private const string AnchorId = "auth-anchor";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "kgsm-catalog-bus-" + Guid.NewGuid().ToString("N"));
    private readonly string? _stateRoot = Environment.GetEnvironmentVariable(JournalServiceCollectionExtensions.StateRootVariable);
    private readonly List<Member> _members = [];

    private Member _anchor = null!;
    private Member _walter = null!;
    private Member _jessie = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_root);
        Environment.SetEnvironmentVariable(JournalServiceCollectionExtensions.StateRootVariable, Path.Combine(_root, "state"));

        _anchor = await StartAsync(AnchorId, MemberKind.Anchor);
        _walter = await StartAsync("walter", MemberKind.Node);
        _jessie = await StartAsync("jessie", MemberKind.Node);

        foreach (Member node in new[] { _walter, _jessie })
        {
            MemberAddResult joined = await _anchor.Resolve<MemberHandshakeService>().AddMemberAsync(node.Url, null, default);
            Assert.Equal(MemberAddOutcome.Added, joined.Outcome);
        }

        // Who holds the accounts is gossiped in a deployment; here each member is told directly, so
        // nothing waits on a round.
        foreach (Member member in _members)
            await member.Resolve<ClusterStateStore>().TryClaimAsync(ClusterCapability.Auth, AnchorId, default);
    }

    public async Task DisposeAsync()
    {
        foreach (Member member in _members)
            await member.DisposeAsync();

        Environment.SetEnvironmentVariable(JournalServiceCollectionExtensions.StateRootVariable, _stateRoot);
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    // ── the members ───────────────────────────────────────────────────────────────────────────

    private sealed class Member(WebApplication app, string id, string url, string manifests) : IAsyncDisposable
    {
        private bool _stopped;

        public string Id { get; } = id;
        public string Url { get; } = url;
        public string Manifests { get; } = manifests;

        public T Resolve<T>() where T : notnull => app.Services.GetRequiredService<T>();

        public async ValueTask DisposeAsync()
        {
            if (_stopped)
                return;

            _stopped = true;
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    /// <summary>
    /// One member on a real port. The anchor carries the store and the intake; a node carries a reporter
    /// over a directory of manifests, the way <c>/var/lib/kgsm/leaves/actions</c> is.
    /// </summary>
    private async Task<Member> StartAsync(string id, string kind)
    {
        string dir = Path.Combine(_root, id);
        string manifests = Path.Combine(dir, "actions");
        Directory.CreateDirectory(manifests);

        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        foreach (string client in new[]
                 {
                     GossipWorker.HttpClientName, MemberHandshakeService.HttpClientName,
                     MemberLatencyPoller.HttpClientName, OutboxDrainer.HttpClientName,
                 })
        {
            builder.Services.AddHttpClient(client).ConfigurePrimaryHttpMessageHandler(() => new LanResolvingHandler());
        }

        builder.Services.AddKgsmCluster(new ClusterOptions
        {
            MemberId = id,
            Secret = Secret,
            StorePath = Path.Combine(dir, "cluster.db"),
            Kind = kind,
            DrainMs = 100,
            GossipMs = 3_600_000,
            PollMs = 3_600_000,
        });

        if (kind == MemberKind.Node)
            builder.Services.AddSingleton<IMemberCardSource>(sp => new NodeCardSource(sp));

        builder.Services.AddSingleton(new AuthorityReporterOptions { ManifestDirectories = [manifests] });

        if (kind == MemberKind.Anchor)
        {
            builder.Services.AddSingleton(AnchorOptions.FromSettings(new AnchorSettings { UserStorePath = Path.Combine(dir, "users.db") }));
            builder.Services.AddKgsmJournal(AnchorJournal.ProducerId, typeof(AnchorJournal).Assembly);
            builder.Services.AddSingleton<AnchorJournal>();
            builder.Services.AddSingleton<AnchorAuthority>();
            builder.Services.AddSingleton<AuthorityIntake>();
            builder.Services.AddSingleton<IAuthorityIntake>(sp => sp.GetRequiredService<AuthorityIntake>());
            builder.Services.AddSingleton<IClusterMessageHandler, CatalogDeclaredHandler>();
            builder.Services.AddSingleton<IClusterMessageHandler, InstanceUninstalledHandler>();
            builder.Services.AddSingleton<MemberDepartureWorker>();
        }

        builder.Services.AddSingleton<AuthorityReporter>();

        WebApplication app = builder.Build();
        app.MapClusterEndpoints();
        await app.StartAsync();

        string bound = app.Urls.First();
        await app.Services.GetRequiredService<SelfIdentityStore>().RecordCandidateAsync(
            $"http://{id}.lan:{new Uri(bound).Port}", client: true, SelfIdentityStore.OperatorProvenance, default);

        Member member = new(app, id, bound, manifests);
        _members.Add(member);
        return member;
    }

    private sealed class NodeCardSource(IServiceProvider services) : IMemberCardSource
    {
        public async Task<MemberCard> BuildAsync(CancellationToken ct)
        {
            MemberCard card = await new SelfMemberCardSource(
                services.GetRequiredService<ClusterOptions>(),
                services.GetRequiredService<SelfIdentityStore>(),
                services.GetRequiredService<SelfIncarnation>(),
                services.GetRequiredService<SelfPublications>()).BuildAsync(ct);

            return card with { Node = new NodeFacts("v1", "test-build", []) };
        }
    }

    /// <summary>Members advertise <c>&lt;id&gt;.lan</c>; this sends the connection where they listen.</summary>
    private sealed class LanResolvingHandler() : DelegatingHandler(new HttpClientHandler())
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri is { Host: var host } uri && host.EndsWith(".lan", StringComparison.Ordinal))
                request.RequestUri = new UriBuilder(uri) { Host = "127.0.0.1" }.Uri;

            return base.SendAsync(request, ct);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────────────────────

    private SqliteAuthorityStore Store => _anchor.Resolve<AnchorAuthority>().Store!;

    private static void Write(Member node, string file, string component, string? version, params (string Id, string Effect, string Scope)[] actions) =>
        File.WriteAllText(Path.Combine(node.Manifests, file), JsonSerializer.Serialize(
            new ActionManifest(1, component, version,
                [.. actions.Select(a => new ManifestAction(a.Id, a.Id, a.Effect, a.Scope, null))],
                component == "reactor" ? [new ManifestRequirement("kgsm:server.restart", "instance", "restart a crashed server")] : []),
            AccessJsonContext.Default.ActionManifest));

    private static void Engine(Member node) =>
        Write(node, "kgsm.json", "kgsm", "3.18.0", ("server.start", "execute", "instance"), ("server.restart", "execute", "instance"));

    /// <summary>Wait for the anchor to see what the bus is carrying to it.</summary>
    private static async Task EventuallyAsync(Func<Task<bool>> condition, string what)
    {
        for (int i = 0; i < 100; i++)
        {
            if (await condition())
                return;

            await Task.Delay(100);
        }

        Assert.Fail($"the anchor never saw {what}");
    }

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
