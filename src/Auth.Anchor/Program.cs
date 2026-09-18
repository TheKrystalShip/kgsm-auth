using Microsoft.Extensions.Caching.Memory;

using TheKrystalShip.KGSM.Auth;
using TheKrystalShip.KGSM.Auth.Discord;
using TheKrystalShip.KGSM.Auth.Anchor;
using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Extensions;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Dns.Member;

var builder = WebApplication.CreateSlimBuilder(args);

// The daemon's settings file, loaded from beside the binary. Two reasons it is explicit:
//   1. CreateSlimBuilder under a systemd unit with no WorkingDirectory leaves the content root at
//      "/", so the framework's own appsettings.json discovery finds nothing and the file's settings
//      silently never apply. AppContext.BaseDirectory is the binary's own directory, which is where
//      deploy installs the file.
//   2. It is named kgsm-auth-anchor.settings.json rather than appsettings.json, so it can never
//      collide with a sibling ecosystem service's config if they ever share a directory.
builder.Configuration.AddJsonFile(
    Path.Combine(AppContext.BaseDirectory, "kgsm-auth-anchor.settings.json"),
    optional: true, reloadOnChange: false);

// Environment variables are re-registered so they sit LAST and therefore win. Configuration resolves
// by source order, and the file above was appended after the sources the builder installed —
// including its own environment provider. Without this line the file would outrank every Anchor__
// and Logging__ variable, and an override would read as applied while changing nothing.
builder.Configuration.AddEnvironmentVariables();

// One journald-native sink with the <N> syslog priority prefix, so `journalctl -p` filters by level.
builder.Logging.ClearProviders();
builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
builder.Logging.AddSystemdConsole();

AnchorSettings settings =
    builder.Configuration.GetSection(AnchorSettings.Section).Get<AnchorSettings>() ?? new AnchorSettings();
AnchorOptions options = AnchorOptions.FromSettings(settings);
builder.Services.AddSingleton(options);

// The private key, generated once on a machine that has none. Read before the host is built so a key
// that cannot be read stops the daemon here rather than at the first sign-in attempt.
//
// A key that is present and unreadable ends the process, and never yields a fresh one: every member
// of the cluster verifies against this key's public half, so replacing it would invalidate every
// session at once and leave every member checking against something nothing signs with. The failure
// is written as one line naming the file, because an operator reading it has a file to fix — an
// unhandled exception would say the same thing in a stack trace and dump core on every restart.
EcdsaSessionSigner signer;
SigningKeyStore.Origin keyOrigin;
try
{
    (signer, keyOrigin) = SigningKeyStore.LoadOrCreate(options.SigningKeyPath);
}
catch (Exception ex)
{
    // Written to stderr with the journald priority prefix rather than through the logger: the
    // logging pipeline belongs to a host that does not exist yet.
    Console.Error.WriteLine(
        $"<2>the session signing key at {options.SigningKeyPath} could not be read: {ex.Message}");
    Console.Error.WriteLine(
        "<2>fix or remove that file — a key is generated only when there is none, because replacing "
        + "one invalidates every session in the cluster");
    return 1;
}

builder.Services.AddSingleton(signer);

builder.Services.AddSingleton<IUserStore>(_ => new SqliteUserStore(
    new UserStoreOptions { Path = options.UserStorePath }));
builder.Services.AddSingleton<IUserPasswordHasher, IdentityPasswordHasher>();

// The counter every account change is ordered by, cluster-wide, and the record of what the cluster
// has not yet been told. Both live beside the accounts, in tables older builds of the store have
// never heard of — so a surface pinned to an earlier version goes on reading accounts exactly as it
// did — and one instance serves both, because a version and the announcement owed for it are written
// in the same transaction.
builder.Services.AddSingleton<SqliteAccountVersions>(_ => new SqliteAccountVersions(
    new UserStoreOptions { Path = options.UserStorePath }));
builder.Services.AddSingleton<IAccountVersions>(sp => sp.GetRequiredService<SqliteAccountVersions>());
builder.Services.AddSingleton<IAccountAnnouncements>(sp => sp.GetRequiredService<SqliteAccountVersions>());

// The staleness bound on a demotion. Short, because the read behind it is a local point query and
// there is nothing to buy by keeping it long.
builder.Services.AddSingleton(sp => new UserStoreAuthority(
    sp.GetRequiredService<IUserStore>(), TimeSpan.FromSeconds(5)));

builder.Services.AddSingleton(sp => new LocalSignInService(
    sp.GetRequiredService<IUserStore>(),
    sp.GetRequiredService<IUserPasswordHasher>(),
    sp.GetRequiredService<UserStoreAuthority>()));

// This anchor's own event journal — the record of what happened to the cluster's accounts. It writes
// to this daemon's state directory under its own producer name, which is the same rule a reader
// inverts to attribute a line, so writer and reader agree on the location without either being told.
//
// A Control Panel on this machine finds it by scanning for journals and serves it merged with every
// other producer's. One on a DIFFERENT machine does not: a journal is a local file, and an anchor
// running where no API does keeps a complete record that no panel renders.
builder.Services.AddKgsmJournal(AnchorJournal.ProducerId, typeof(AnchorJournal).Assembly);
builder.Services.AddSingleton<AnchorJournal>();

// The administrator an empty store gets. An anchor sharing a machine with a Control Panel inherits
// the accounts that panel bootstrapped; one on a machine of its own starts with nothing, and without
// this is a door nobody can open — registration is off unless a cluster turns it on, and an account
// made through it waits for an approval only an administrator can give.
builder.Services.AddHostedService<AnchorBootstrapper>();

// Whether a session has proved lately that its holder owns it, and the links started against that
// proof. Both in memory: a restart makes every session prove itself again, which is the safe
// direction to fail in, and drops links in flight, which costs a click and cannot grant anything.
builder.Services.AddSingleton(sp => new ReauthGate(sp.GetRequiredService<AnchorOptions>().ReauthWindow));
builder.Services.AddSingleton<LinkTicketStore>();

// Sessions are cluster-scoped: the audience is the cluster, not this machine, because a session
// minted here is presented to every member of it. Signed with the private key above, so a member can
// verify one and cannot mint one.
builder.Services.AddSingleton<ISessionTokenService>(sp => new SessionTokenService(
    new SessionTokenOptions(
        HostId: options.ClusterId,
        SigningKey: "",
        AccessLifetime: options.AccessLifetime,
        RefreshLifetime: options.RefreshLifetime,
        Issuer: options.Issuer),
    sp.GetRequiredService<ILogger<SessionTokenService>>(),
    signer));

// Cluster membership. Registered unconditionally and inert without a secret: a host that is not part
// of a cluster starts no worker and answers its inbox to nobody, which is the state a standalone
// install is in and not a misconfiguration. The secret is read through ClusterConfiguration so every
// member on the machine spells the key identically — one that spelled it differently would read a
// blank from a file that is not empty and quietly report itself standalone.
//
// The store is named from this member's own database inside its own StateDirectory=. Two members
// sharing one would share a roster and an outbox, which nothing notices until one of them disables
// somebody on the other's behalf.
var clusterOptions = new ClusterOptions
{
    MemberId = options.MemberId,
    Kind = MemberKind.Anchor,
    Secret = ClusterConfiguration.Secret(builder.Configuration),
    SecretPrevious = ClusterConfiguration.SecretPrevious(builder.Configuration),
    StorePath = Path.Combine(
        Path.GetDirectoryName(Path.GetFullPath(options.SessionStorePath)) ?? ".", "cluster.db"),
    PublicBaseUrl = options.PublicBaseUrl,
};
builder.Services.AddKgsmCluster(clusterOptions);

// The accounts capability's name, when a DNS anchor holds the cluster's zone: this anchor says where it
// is reached, and while it holds the capability it keeps a certificate for the name and serves it. Inert
// with no cluster and with nobody holding dns.
builder.Services.AddKgsmDnsMember(options.PublicHost, "kgsm-auth-anchor");

// An anchor registers no card source of its own. What it has to say about itself — its id, its kind,
// its addresses, its incarnation — is entirely what the package already holds; the node block exists
// for facts an anchor does not have.
builder.Services.AddSingleton(sp => new AnchorRole(sp.GetRequiredService<ClusterOptions>()));

// The anchor's own configuration surface: the descriptor its build wrote, the overrides an
// administrator has set, what this host's deploy files set beneath them, and the bounce that makes a
// change take effect.
builder.Services.AddSingleton<ConfigDescriptorStore>();
builder.Services.AddSingleton<ConfigOverrideStore>();
builder.Services.AddSingleton<ConfigFloorReader>();
builder.Services.AddSingleton<SelfRestart>();
builder.Services.AddSingleton<AnchorConfigService>();
builder.Services.AddSingleton<UnitLogReader>();
builder.Services.AddSingleton<UnitLogFollower>();
builder.Services.AddHostedService<ClusterMembershipWorker>();

builder.Services.AddSingleton<ISessionRegistry>(_ => new SqliteSessionRegistry(options.SessionStorePath));
builder.Services.AddSingleton<IMemoryCache>(_ => new MemoryCache(new MemoryCacheOptions()));
builder.Services.AddSingleton<ISessionValidator>(sp => new SessionValidator(
    sp.GetRequiredService<ISessionRegistry>(),
    sp.GetRequiredService<IMemoryCache>(),
    TimeSpan.FromSeconds(5)));
builder.Services.AddSingleton<AnchorAuth>();

// Signing in with an account somebody already holds elsewhere. The provider answers WHO, and the
// account store answers what they may do — so a provider is added with no authority story of its own.
// Transient like the typed HttpClient underneath it: holding one for the process lifetime pins its
// handler and silently stops the factory rotating it, so DNS changes never land.
builder.Services.AddHttpClient(nameof(DiscordDirectory), c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddSingleton(sp => new AnchorAddress(
    sp.GetRequiredService<AnchorOptions>(),
    sp.GetServices<ISelfAddressSource>()));
builder.Services.AddTransient(sp => new ProviderCatalog(
    sp.GetRequiredService<IConfiguration>(),
    sp.GetRequiredService<IHttpClientFactory>(),
    sp.GetRequiredService<AnchorAddress>()));
builder.Services.AddSingleton(sp => new IdentityLinkService(sp.GetRequiredService<IUserStore>()));
builder.Services.AddSingleton<MemberTargets>();
builder.Services.AddSingleton<AccountBroadcast>();
// Sends what the write paths did not manage to: a change made while the process was dying, a bus that
// was unreachable, a cluster that had no members at the time. Nothing depends on a write path having
// drained, which is what makes the announcement as durable as the change.
builder.Services.AddHostedService<AccountBroadcastWorker>();
builder.Services.AddSingleton<SessionBroadcast>();

// Deletes rows already past their cap. Housekeeping — it ends no session that is still alive.
builder.Services.AddHostedService(sp => new SessionCleanupWorker(
    sp.GetRequiredService<ISessionRegistry>(),
    options.SessionCleanup,
    sp.GetRequiredService<ILogger<SessionCleanupWorker>>()));

// A person signs in here directly, so this is a TCP surface rather than a leaf's unix socket.
builder.WebHost.UseUrls(options.ListenAddress);

WebApplication app = builder.Build();

app.UseMiddleware<CorsMiddleware>();

// The member-to-member wire, served by the package. One implementation of the status codes, the size
// cap, the token check and the spoof guard, so two members cannot disagree about what the protocol is.
app.MapClusterEndpoints();

// Unified ecosystem liveness probe: 200 means this anchor is up and serving.
app.MapGet("/health", () => Results.Text("ok\n"));

// What this is. Unauthenticated, because a client handed one address has to establish what is behind
// it before it can do anything, and a caller with no session is exactly who is asking. An anchor and
// a standalone node both answer /auth/providers with a provider list, so that question cannot tell
// them apart — and guessing wrong sends somebody to sign in at a machine that does not hold their
// account.
app.MapGet("/auth/identity", DiscoveryEndpoints.Identity);

// What the cluster contains, behind a session. The only place a client learns it: a member of a
// cluster tells nobody what cluster it is in, so a panel signs in here and drives the roster it is
// handed rather than holding a list of its own.
app.MapGet("/auth/cluster/members", DiscoveryEndpoints.Roster);

app.MapGet("/auth/providers", ProviderEndpoints.Providers);
app.MapGet("/auth/{provider}/start", ProviderEndpoints.Start);
app.MapGet("/auth/{provider}/callback", ProviderEndpoints.Callback);

app.MapPost("/auth/register", RegisterEndpoint.Register);
app.MapPost("/auth/sign-in", Endpoints.SignIn);
app.MapPost("/auth/session/refresh", Endpoints.Refresh);
app.MapPost("/auth/session/sign-out", Endpoints.SignOut);
app.MapGet("/auth/session", Endpoints.Session);
// This anchor's own configuration surface. It answers for itself because nothing else can: a leaf is
// configured through the node that runs it, and an anchor is a peer of every node rather than
// something one hosts.
app.MapGet("/auth/config", ConfigEndpoints.Read);
app.MapPut("/auth/config", ConfigEndpoints.Apply);
app.MapGet("/auth/logs", LogEndpoints.Read);
app.MapGet("/auth/logs/stream", LogEndpoints.Stream);

app.MapGet("/auth/cluster/users", Endpoints.Accounts);
app.MapPost("/auth/cluster/users", AccountEndpoints.CreateAccount);
app.MapPatch("/auth/cluster/users/{userId}", Endpoints.PatchAccount);

// What somebody may do to their OWN account. A person holds one account across the whole cluster, so
// this is the only place any of it can be changed — a member writing to its replica would be
// overwritten by the next thing published about that account.
app.MapPost("/auth/password", AccountEndpoints.ChangePassword);
app.MapGet("/auth/identities", AccountEndpoints.Identities);

// Changing what proves an account asks for a credential again. Holding a session is not the same as
// having proved you own it, and attaching an identity outlives the session that attached it.
app.MapPost("/auth/reauth", IdentityEndpoints.Reauth);
app.MapPost("/auth/identities/{provider}/start", IdentityEndpoints.StartLink);
app.MapGet("/auth/identities/{provider}/callback", IdentityEndpoints.CompleteLink);
app.MapDelete("/auth/identities/{credentialId}", AccountEndpoints.Unlink);

// What an administrator may do to somebody else's. Setting a password knows no current one, because
// the case it exists for is a person who has lost theirs.
app.MapPost("/auth/cluster/users/{userId}/password", AccountEndpoints.SetPassword);
app.MapDelete("/auth/cluster/users/{userId}", AccountEndpoints.DeleteAccount);

// The devices somebody is signed in on, and ending them. Listed here because they exist ONLY here: a
// member verifies a cluster session offline against a published key and stores nothing, so a member
// asked what devices somebody holds answers honestly with none — an empty card rather than a wrong
// question. Ending one is never gated on holding the capability, because revoking takes authority
// away and a member that has stood down still holds the rows for what it minted.
app.MapGet("/auth/sessions", SessionEndpoints.List);
app.MapPost("/auth/session/revoke", SessionEndpoints.Revoke);
app.MapPost("/auth/cluster/users/{userId}/sessions/revoke-all", SessionEndpoints.RevokeAll);
app.MapPost("/auth/cluster/users/{userId}/sessions/{sid}/revoke", SessionEndpoints.RevokeOne);

// What this anchor serves to other MEMBERS: the accounts, so each can answer for itself who somebody
// is and what they may do. Authenticated by a member service token, never by a person's session.
app.MapGet("/auth/cluster/snapshot", MemberEndpoints.Snapshot);

// The verification key, unauthenticated because publishing it is the point: every member has to hold
// it to check a session, and holding it grants nothing — it verifies a signature and cannot produce
// one.
app.MapGet("/auth/cluster/public-key", (EcdsaSessionSigner keys) =>
    Results.Text(keys.PublicKeysJson, "application/json"));

app.Logger.LogInformation(
    "kgsm-auth-anchor listening on {Address} as member {Member} for cluster {Cluster} — accounts {Store}, "
    + "signing key {Key} ({Origin})",
    options.ListenAddress, options.MemberId, options.ClusterId, options.UserStorePath,
    options.SigningKeyPath, keyOrigin == SigningKeyStore.Origin.Generated ? "generated" : "loaded");

app.Run();

return 0;
