using TheKrystalShip.Auth.Cluster;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;
using TheKrystalShip.KGSM.ComponentSurface;
using TheKrystalShip.KGSM.ComponentSurface.Http;
using TheKrystalShip.KGSM.Dns.Member;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// The KGSM module: what this anchor does as the account authority of a KGSM cluster, composed beside
/// the core only when a cluster is configured.
/// </summary>
/// <remarks>
/// <para>
/// <b>Configured means the cluster secret is set.</b> That is the same signal
/// <see cref="ClusterOptions.Enabled"/> and <see cref="AnchorStanding.Standalone"/> read, so there is one
/// switch and nothing that can disagree with it.
/// </para>
/// <para>
/// The module is cluster membership and the bus, the DNS member, the standing worker and the founding
/// claim through <c>/etc/kgsm/cluster-founded</c>, the published facts (<c>auth.*</c>, including where
/// clients live), the account store's replication to every member, every member's catalog report, the
/// end of a removed member's grants, the session revocations members hear, and this anchor's component
/// surface under <c>/auth/config</c>, <c>/auth/logs</c> and the rest, read from KGSM's descriptor in
/// <c>/var/lib/kgsm/anchors</c>. Every KGSM path this daemon touches is touched from here.
/// </para>
/// </remarks>
internal static class KgsmModule
{
    /// <summary>This anchor as a member of the configured cluster; <see cref="ClusterOptions.Enabled"/> says whether there is one.</summary>
    /// <remarks>
    /// The secret is read through <see cref="ClusterConfiguration"/> so every member on the machine spells
    /// the key identically — one that spelled it differently would read a blank from a file that is not
    /// empty and quietly report itself standalone.
    /// </remarks>
    internal static ClusterOptions ClusterFrom(IConfiguration configuration, AnchorOptions options) => new()
    {
        MemberId = options.MemberId,
        Kind = MemberKind.Anchor,
        Secret = ClusterConfiguration.Secret(configuration),
        SecretPrevious = ClusterConfiguration.SecretPrevious(configuration),
        // Whether this machine founded the cluster decides whether this anchor may claim its accounts. A
        // deployment reads the one record kgsm-base writes; the key exists so a test reads its own.
        FoundedPath = configuration["Cluster:FoundedPath"] is { Length: > 0 } founded
            ? founded
            : ClusterFounding.DefaultPath,
        // Named from this member's own database inside its own StateDirectory=. Two members sharing one
        // would share a roster and an outbox, which nothing notices until one of them disables somebody
        // on the other's behalf.
        StorePath = Path.Combine(
            Path.GetDirectoryName(Path.GetFullPath(options.SessionStorePath)) ?? ".", "cluster.db"),
        PublicBaseUrl = options.PublicBaseUrl,
    };

    internal static IServiceCollection AddKgsmModule(
        this IServiceCollection services, AnchorOptions options, ClusterOptions cluster)
    {
        // Cluster membership and durable member-to-member messaging.
        services.AddKgsmCluster(cluster);

        // The accounts capability's name, when a DNS anchor holds the cluster's zone: this anchor says
        // where it is reached, and while it holds the capability it keeps a certificate for the name and
        // serves it. Inert with nobody holding dns.
        services.AddKgsmDnsMember(options.PublicHost, "tks-auth");

        // An anchor registers no card source of its own. What it has to say about itself — its id, its
        // kind, its addresses, its incarnation — is entirely what the package already holds; the node
        // block exists for facts an anchor does not have.

        // This anchor's own surface — the descriptor its build wrote, the overrides set through it, what
        // this host's deploy files set beneath them, its journal, and the bounce that makes a change take
        // effect. All of it is TheKrystalShip.KGSM.ComponentSurface: a component owns these wherever it
        // runs, and only the way a browser reaches them differs. Here that is HTTP on this anchor's own
        // origin.
        services.AddComponentSurface(new ComponentSurfaceOptions(
            options.ConfigDescriptorPath, options.ConfigOverridePath));

        // Where this anchor stands, the founding claim, the published facts and the clients members
        // announce.
        services.AddHostedService<ClusterMembershipWorker>();

        // Who may do what: every member's report of the actions it performs arrives over the bus from
        // another member or straight from this one, and a removed member's report is forgotten. The
        // anchor's own manifest sits in the actions directory beside its descriptor, under the same
        // name — one place the name is spelled.
        services.AddSingleton<IAuthorityIntake>(sp => sp.GetRequiredService<AuthorityIntake>());
        services.AddSingleton<IClusterMessageHandler, CatalogDeclaredHandler>();
        services.AddSingleton<IClusterMessageHandler, InstanceUninstalledHandler>();
        services.AddHostedService<MemberDepartureWorker>();
        services.AddSingleton(new AuthorityReporterOptions
        {
            ManifestFiles =
            [
                Path.Combine(
                    Path.GetDirectoryName(options.ConfigDescriptorPath) ?? ".", "actions",
                    Path.GetFileName(options.ConfigDescriptorPath)),
            ],
        });
        services.AddSingleton<AuthorityReporter>();
        services.AddHostedService(sp => sp.GetRequiredService<AuthorityReporter>());

        // What changed about who may do what reaches every member, drained from the store's outbox the
        // moment a write lands and on a timer after; every live member hears the version and the
        // staleness bound on the heartbeat.
        services.AddSingleton<MemberTargets>();
        services.AddSingleton<AuthorityBroadcast>();
        services.AddSingleton<IAuthorityAnnouncer>(sp => sp.GetRequiredService<AuthorityBroadcast>());
        services.AddHostedService<AuthorityBroadcastWorker>();

        // A session ended here is still accepted by every member until they hear it ended.
        services.AddSingleton<SessionBroadcast>();
        services.AddSingleton<ISessionAnnouncer>(sp => sp.GetRequiredService<SessionBroadcast>());

        return services;
    }

    internal static WebApplication MapKgsmModule(this WebApplication app)
    {
        // The member-to-member wire, served by the package. One implementation of the status codes, the
        // size cap, the token check and the spoof guard, so two members cannot disagree about what the
        // protocol is.
        app.MapClusterEndpoints();

        // What the cluster contains, behind a session. The only place a client learns it: a member of a
        // cluster tells nobody what cluster it is in, so a panel signs in here and drives the roster it
        // is handed rather than holding a list of its own.
        app.MapGet("/auth/cluster/members", DiscoveryEndpoints.Roster);

        // What this anchor answers about ITSELF — its configuration, its unit, its journal and the
        // commands it declares. It answers for itself because nothing else can: a leaf is configured
        // through the node that runs it, and an anchor is a peer of every node rather than something one
        // hosts.
        //
        // The routes are the shared library's, identical to the ones every other component serves, so
        // one Control Panel page renders any of them and a node's relay needs no knowledge of which
        // component it is forwarding to. What is this anchor's own is the gate in front of them.
        app.MapGroup("/auth").AddEndpointFilter<OwnSurfaceFilter>().WithMetadata(OwnSurfaceFilter.Marker).MapComponentSurface();

        // What this anchor serves to other MEMBERS: the accounts, so each can answer for itself who
        // somebody is and what they may do. Authenticated by a member service token, never by a person's
        // session.
        app.MapGet("/auth/cluster/snapshot", MemberEndpoints.Snapshot);

        // The verification key, unauthenticated because publishing it is the point: every member has to
        // hold it to check a session, and holding it grants nothing — it verifies a signature and cannot
        // produce one.
        app.MapGet("/auth/cluster/public-key", (TheKrystalShip.Auth.Minting.EcdsaSessionSigner keys) =>
            Results.Text(keys.PublicKeysJson, "application/json"));

        return app;
    }
}
