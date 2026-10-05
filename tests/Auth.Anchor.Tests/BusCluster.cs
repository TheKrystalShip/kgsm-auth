using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using TheKrystalShip.Auth.Cluster;
using TheKrystalShip.Auth.Minting;
using TheKrystalShip.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;
using TheKrystalShip.KGSM.Extensions;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// An auth anchor and nodes on real ports, delivering to each other over the bus: the anchor carries the
/// authority store, its intake, its broadcast and the snapshot route; a node carries a reporter over a
/// directory of manifests and a replica of the authority.
/// </summary>
/// <remarks>
/// Used from the anchor's collection, because the journal's state root is a process environment variable.
/// </remarks>
internal sealed class BusCluster : IAsyncDisposable
{
    private const string Secret = "bus-cluster-secret";

    public const string AnchorId = "auth-anchor";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "kgsm-bus-cluster-" + Guid.NewGuid().ToString("N"));
    private readonly string? _stateRoot = Environment.GetEnvironmentVariable(JournalServiceCollectionExtensions.StateRootVariable);
    private readonly List<BusMember> _members = [];

    public BusMember Anchor { get; private set; } = null!;

    /// <summary>Start an anchor and <paramref name="nodes"/>, join the nodes, and tell everyone who holds the accounts.</summary>
    public static async Task<BusCluster> StartAsync(params string[] nodes)
    {
        BusCluster cluster = new();
        Directory.CreateDirectory(cluster._root);
        Environment.SetEnvironmentVariable(JournalServiceCollectionExtensions.StateRootVariable, Path.Combine(cluster._root, "state"));

        cluster.Anchor = await cluster.StartMemberAsync(AnchorId, MemberKind.Anchor);
        foreach (string node in nodes)
        {
            BusMember member = await cluster.StartMemberAsync(node, MemberKind.Node);
            MemberAddResult joined = await cluster.Anchor.Resolve<MemberHandshakeService>().AddMemberAsync(member.Url, null, default);
            Assert.Equal(MemberAddOutcome.Added, joined.Outcome);
        }

        // Who holds the accounts is gossiped in a deployment; here each member is told directly, so
        // nothing waits on a round.
        foreach (BusMember member in cluster._members)
            await member.Resolve<ClusterStateStore>().TryClaimAsync(ClusterCapability.Auth, AnchorId, default);

        return cluster;
    }

    public BusMember this[string id] => _members.Single(m => m.Id == id);

    /// <summary>The anchor's authority store.</summary>
    public SqliteAuthorityStore Store => Anchor.Resolve<AnchorAuthority>().Store!;

    public async ValueTask DisposeAsync()
    {
        foreach (BusMember member in _members)
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

    /// <summary>Wait for something the bus is carrying to land.</summary>
    public static async Task EventuallyAsync(Func<Task<bool>> condition, string what)
    {
        for (int i = 0; i < 100; i++)
        {
            if (await condition())
                return;

            await Task.Delay(100);
        }

        Assert.Fail($"never saw {what}");
    }

    private async Task<BusMember> StartMemberAsync(string id, string kind)
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

        builder.Services.AddSingleton(new AuthorityReporterOptions { ManifestDirectories = [manifests] });

        if (kind == MemberKind.Anchor)
        {
            builder.Services.AddSingleton(AnchorOptions.FromSettings(new AnchorSettings { UserStorePath = Path.Combine(dir, "users.db") }));
            builder.Services.AddKgsmJournal(AnchorJournal.ProducerId, typeof(AnchorJournal).Assembly);
            builder.Services.AddSingleton<AnchorJournal>();
            builder.Services.AddSingleton<AnchorAuthority>();
            builder.Services.AddSingleton<MemberTargets>();
            builder.Services.AddSingleton<AuthorityBroadcast>();
            builder.Services.AddSingleton<IAuthorityAnnouncer>(sp => sp.GetRequiredService<AuthorityBroadcast>());
            builder.Services.AddSingleton(TimeProvider.System);
            builder.Services.AddSingleton<AuthorityBroadcastWorker>();
            builder.Services.AddSingleton<AuthorityIntake>();
            builder.Services.AddSingleton<IAuthorityIntake>(sp => sp.GetRequiredService<AuthorityIntake>());
            builder.Services.AddSingleton<IClusterMessageHandler, CatalogDeclaredHandler>();
            builder.Services.AddSingleton<IClusterMessageHandler, InstanceUninstalledHandler>();
            builder.Services.AddSingleton<MemberDepartureWorker>();
            builder.Services.AddSingleton(_ => new SqliteSessionRegistry(Path.Combine(dir, "sessions.db")));
            builder.Services.AddSingleton<ISessionRegistry>(sp => sp.GetRequiredService<SqliteSessionRegistry>());
            builder.Services.AddSingleton<AnchorAccess>();

            // Sessions, minted and read the way the anchor does, for the authority's own routes.
            builder.Services.AddSingleton<ISessionTokenService>(_ => new SessionTokenService(
                new SessionTokenOptions("kgsm-cluster", TimeSpan.FromMinutes(15), TimeSpan.FromDays(30), "https://auth.test"),
                EcdsaSessionSigner.Generate()));
            builder.Services.AddSingleton<Microsoft.Extensions.Caching.Memory.IMemoryCache>(_ =>
                new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()));
            builder.Services.AddSingleton<ISessionValidator>(sp => new SessionValidator(
                sp.GetRequiredService<ISessionRegistry>(),
                sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(),
                TimeSpan.Zero));
            builder.Services.AddSingleton<SessionReader>();
            builder.Services.AddSingleton<AuthorityCaller>();
            builder.Services.AddSingleton(sp => new AnchorRole(sp.GetRequiredService<ClusterOptions>().Enabled));
        }
        else
        {
            builder.Services.AddSingleton<IMemberCardSource>(sp => new NodeCardSource(sp));
            builder.Services.AddSingleton<IReplicatedAuthority>(new FileReplica(Path.Combine(dir, "users.db")));
            builder.Services.AddAuthorityReplica();
            builder.Services.AddSingleton<RecordingListener>();
            builder.Services.AddSingleton<IAuthorityChangeListener>(sp => sp.GetRequiredService<RecordingListener>());
        }

        builder.Services.AddSingleton<AuthorityReporter>();

        WebApplication app = builder.Build();
        app.MapClusterEndpoints();
        if (kind == MemberKind.Anchor)
        {
            app.MapGet("/auth/cluster/snapshot", MemberEndpoints.Snapshot);
            app.MapGet("/auth/cluster/authority", AuthorityEndpoints.Read);
            app.MapPost("/auth/cluster/authority/edits", AuthorityEndpoints.Edit);
            app.MapPost("/auth/cluster/authority/checks", AuthorityEndpoints.Check);
            app.MapGet("/me/access", AuthorityEndpoints.MeAccess);
            app.Services.GetRequiredService<AnchorRole>().Update(AnchorStanding.Holder, AnchorId);
        }

        await app.StartAsync();

        string bound = app.Urls.First();
        await app.Services.GetRequiredService<SelfIdentityStore>().RecordCandidateAsync(
            $"http://{id}.lan:{new Uri(bound).Port}", client: true, SelfIdentityStore.OperatorProvenance, default);

        BusMember member = new(app, id, bound, manifests);
        _members.Add(member);
        return member;
    }

    private sealed class FileReplica(string path) : IReplicatedAuthority
    {
        public SqliteAuthorityStore? Replica { get; } = new(new UserStoreOptions { Path = path });

        public string? UnavailableReason => null;
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
}

/// <summary>Counts the changes a node's replica told its listeners about.</summary>
internal sealed class RecordingListener : IAuthorityChangeListener
{
    private int _changes;

    public int Changes => Volatile.Read(ref _changes);

    public Task AuthorityChangedAsync(CancellationToken ct)
    {
        Interlocked.Increment(ref _changes);
        return Task.CompletedTask;
    }
}

/// <summary>One member of a <see cref="BusCluster"/>.</summary>
internal sealed class BusMember(WebApplication app, string id, string url, string manifests) : IAsyncDisposable
{
    private bool _stopped;

    public string Id { get; } = id;
    public string Url { get; } = url;

    /// <summary>The directory this member's components install their manifests into.</summary>
    public string Manifests { get; } = manifests;

    public T Resolve<T>() where T : notnull => app.Services.GetRequiredService<T>();

    /// <summary>A node's authority replica.</summary>
    public SqliteAuthorityStore Replica => Resolve<IReplicatedAuthority>().Replica!;

    /// <summary>A node's snapshot worker, to run on demand.</summary>
    public AuthoritySnapshotWorker SnapshotWorker => app.Services.GetServices<IHostedService>().OfType<AuthoritySnapshotWorker>().Single();

    public async ValueTask DisposeAsync()
    {
        if (_stopped)
            return;

        _stopped = true;
        await app.StopAsync();
        await app.DisposeAsync();
    }
}
