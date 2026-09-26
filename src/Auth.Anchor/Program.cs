using Microsoft.Extensions.Caching.Memory;

using TheKrystalShip.KGSM.Auth;
using TheKrystalShip.KGSM.Auth.Anchor;
using TheKrystalShip.KGSM.Auth.Cluster;
using TheKrystalShip.KGSM.Auth.Minting;
using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Extensions;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;
using TheKrystalShip.KGSM.Dns.Member;
using TheKrystalShip.KGSM.ComponentSurface;
using TheKrystalShip.KGSM.ComponentSurface.Http;

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

// `kgsm-auth-anchor owner grant <username>` — the Owner recovery path, run on this host as the anchor's
// service account. It reads the same settings the daemon does, so it opens the store the daemon opens.
if (args is [OwnerCommand.Verb, ..])
    return await OwnerCommand.RunAsync(args, options);

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

// The account store is at schema version 2: accounts, and everything that decides what they may do.
// A version 1 file is brought forward here, once, before anything opens it — every session is ended
// once the daemon is up, so no token minted under the tiers outlives them.
UpgradeReport upgrade;
try
{
    upgrade = File.Exists(options.UserStorePath)
        ? UserStoreUpgrade.ToVersion2(options.UserStorePath, DateTimeOffset.UtcNow)
        : new UpgradeReport(AuthoritySchema.Version, null, []);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"<2>the account store at {options.UserStorePath} could not be brought to schema version 2: {ex.Message}");
    return 1;
}

builder.Services.AddSingleton(upgrade);
builder.Services.AddSingleton<IUserStore>(sp => sp.GetRequiredService<AnchorAuthority>().Store
    ?? throw new InvalidOperationException(sp.GetRequiredService<AnchorAuthority>().UnavailableReason));
builder.Services.AddSingleton<IUserPasswordHasher, IdentityPasswordHasher>();

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

// The links the account page has started and a provider has not yet sent back. In memory: a restart
// drops links in flight, which costs a click and cannot grant anything.
builder.Services.AddSingleton<LinkTicketStore>();

// Sessions are cluster-scoped: the audience is the cluster, not this machine, because a session
// minted here is presented to every member of it. Signed with the private key above, so a member can
// verify one and cannot mint one.
builder.Services.AddSingleton<ISessionTokenService>(_ => new SessionTokenService(
    new SessionTokenOptions(
        Audience: options.ClusterId,
        AccessLifetime: options.AccessLifetime,
        RefreshLifetime: options.RefreshLifetime,
        Issuer: options.Issuer),
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
    // Whether this machine founded the cluster decides whether this anchor may claim its accounts. A
    // deployment reads the one record kgsm-base writes; the key exists so a test reads its own.
    FoundedPath = builder.Configuration["Cluster:FoundedPath"] is { Length: > 0 } founded
        ? founded
        : ClusterFounding.DefaultPath,
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

// This anchor's own surface — the descriptor its build wrote, the overrides an administrator has set,
// what this host's deploy files set beneath them, its journal, and the bounce that makes a change take
// effect. All of it is TheKrystalShip.KGSM.ComponentSurface: a component owns these wherever it runs,
// and only the way a browser reaches them differs. Here that is HTTP on this anchor's own origin.
builder.Services.AddComponentSurface(new ComponentSurfaceOptions(
    options.ConfigDescriptorPath, options.ConfigOverridePath));
builder.Services.AddHostedService<ClusterMembershipWorker>();

// Who may do what: every member's report of the actions it performs arrives here, over the bus from
// another member or straight from this one, and a removed member's report is forgotten. The anchor's
// own manifest sits in the actions directory beside its descriptor, under the same name — one place
// the name is spelled.
builder.Services.AddSingleton<AnchorAuthority>();
builder.Services.AddSingleton<AuthorityIntake>();
builder.Services.AddSingleton<IAuthorityIntake>(sp => sp.GetRequiredService<AuthorityIntake>());
builder.Services.AddSingleton<IClusterMessageHandler, CatalogDeclaredHandler>();
builder.Services.AddSingleton<IClusterMessageHandler, InstanceUninstalledHandler>();
builder.Services.AddHostedService<MemberDepartureWorker>();
builder.Services.AddSingleton(new AuthorityReporterOptions
{
    ManifestFiles =
    [
        Path.Combine(
            Path.GetDirectoryName(options.ConfigDescriptorPath) ?? ".", "actions",
            Path.GetFileName(options.ConfigDescriptorPath)),
    ],
});
builder.Services.AddSingleton<AuthorityReporter>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<AuthorityReporter>());

// What changed about who may do what reaches every member, drained from the store's outbox the moment
// a write lands and on a timer after; every live member hears the version and the staleness bound on
// the heartbeat.
builder.Services.AddSingleton<AuthorityBroadcast>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHostedService<AuthorityBroadcastWorker>();

builder.Services.AddSingleton(_ => new SqliteSessionRegistry(options.SessionStorePath));
builder.Services.AddSingleton<ISessionRegistry>(sp => sp.GetRequiredService<SqliteSessionRegistry>());
builder.Services.AddSingleton<AnchorAccess>();

// The OpenID Connect provider: the clients it answers, the browsers signed in at it, and the id_token
// beside every session it mints. Its rows live beside the sessions, because a browser's sign-in here is a
// session and every session minted through it records which one it came from.
builder.Services.AddSingleton(sp => new ClientRegistry(
    sp.GetRequiredService<SqliteSessionRegistry>(), options.PanelOrigins));
builder.Services.AddSingleton<ProviderSessions>();
builder.Services.AddSingleton<IdTokens>();
builder.Services.AddSingleton<ProviderBundle>();
builder.Services.AddSingleton<ReauthRoundTrips>();
builder.Services.AddSingleton<IMemoryCache>(_ => new MemoryCache(new MemoryCacheOptions()));
builder.Services.AddSingleton<ISessionValidator>(sp => new SessionValidator(
    sp.GetRequiredService<ISessionRegistry>(),
    sp.GetRequiredService<IMemoryCache>(),
    TimeSpan.FromSeconds(5)));
builder.Services.AddSingleton<SessionReader>();
builder.Services.AddSingleton<AnchorAuth>();
builder.Services.AddSingleton<AuthorityCaller>();

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
// it before it can do anything, and a caller with no session is exactly who is asking.
app.MapGet("/auth/identity", DiscoveryEndpoints.Identity);

// What the cluster contains, behind a session. The only place a client learns it: a member of a
// cluster tells nobody what cluster it is in, so a panel signs in here and drives the roster it is
// handed rather than holding a list of its own.
app.MapGet("/auth/cluster/members", DiscoveryEndpoints.Roster);

// The OpenID Connect provider every browser surface in the cluster signs in through. Served only when
// the issuer is this anchor's browser-facing URL; otherwise each door says so rather than guessing one.
app.MapGet("/.well-known/openid-configuration", OidcEndpoints.Discovery);
app.MapGet("/.well-known/jwks.json", OidcEndpoints.Jwks);
app.MapGet("/authorize", OidcEndpoints.Authorize);
app.MapPost("/authorize/credentials", OidcEndpoints.Credentials);
app.MapGet("/authorize/wait", OidcEndpoints.Wait);
app.MapGet("/authorize/floor.css", ProviderPages.StylesheetAsync);
app.MapGet("/authorize/context", OidcEndpoints.Context);
app.MapPost("/authorize/register", OidcEndpoints.Register);
app.MapGet("/authorize/{provider}", OidcEndpoints.ProviderStart);
app.MapPost("/token", OidcEndpoints.Token);
app.MapGet("/userinfo", OidcEndpoints.UserInfo);
app.MapPost("/userinfo", OidcEndpoints.UserInfo);
app.MapGet("/sign-out", OidcEndpoints.SignOut);
app.MapPost("/sign-out", OidcEndpoints.ConfirmSignOut);

// The provider's own pages as kgsm-web builds them, and the account page's calls. Every one of those is
// authenticated by the provider's cookie and answered on this origin alone.
app.MapGet("/ui/{**path}", ProviderBundle.ServeAssetAsync);
app.MapGet("/account", AccountPageEndpoints.Page);
app.MapGet("/account/sign-in", AccountPageEndpoints.SignIn);
app.MapGet("/account/me", AccountPageEndpoints.Me);
app.MapPost("/account/reauth", AccountPageEndpoints.Reauth);
app.MapGet("/account/reauth/{provider}", AccountPageEndpoints.ReauthWithProvider);
app.MapPost("/account/password", AccountPageEndpoints.SetPassword);
app.MapPost("/account/identities/{provider}/start", AccountPageEndpoints.StartLink);
app.MapDelete("/account/identities/{credentialId}", AccountPageEndpoints.Unlink);
app.MapPost("/account/sessions/revoke", AccountPageEndpoints.Revoke);
app.MapPost("/account/sign-out", AccountPageEndpoints.SignOut);

// The clients it answers. Announced ones arrive over gossip; these are the ones an administrator
// registers by hand, for whatever no member serves.
app.MapGet("/auth/cluster/clients", OidcEndpoints.ListClients);
app.MapPost("/auth/cluster/clients", OidcEndpoints.RegisterClient);
app.MapDelete("/auth/cluster/clients/{clientId}", OidcEndpoints.RemoveClient);

// Where a provider sends the browser back: to complete the request in flight, or to prove the person
// again for the account page. The one address registered with the provider's application.
app.MapGet("/auth/{provider}/callback", ProviderEndpoints.Callback);

// What this anchor answers about ITSELF — its configuration, its unit, its journal and the commands
// it declares. It answers for itself because nothing else can: a leaf is configured through the node
// that runs it, and an anchor is a peer of every node rather than something one hosts.
//
// The routes are the shared library's, identical to the ones every other component serves, so one
// Control Panel page renders any of them and a node's relay needs no knowledge of which component it
// is forwarding to. What is this anchor's own is the gate in front of them.
app.MapGroup("/auth").AddEndpointFilter<OwnSurfaceFilter>().MapComponentSurface();

app.MapGet("/auth/cluster/users", Endpoints.Accounts);
app.MapPost("/auth/cluster/users", AccountEndpoints.CreateAccount);
app.MapPatch("/auth/cluster/users/{userId}", Endpoints.PatchAccount);

// Where a provider sends the browser back after the account page began attaching an identity. A
// different address from the sign-in callback: one attaches whoever comes back to an account already
// signed in, and sharing an address would let a link return through the sign-in door.
app.MapGet("/auth/identities/{provider}/callback", IdentityEndpoints.CompleteLink);

// What an administrator may do to somebody else's account. Setting a password knows no current one,
// because the case it exists for is a person who has lost theirs.
app.MapPost("/auth/cluster/users/{userId}/password", AccountEndpoints.SetPassword);
app.MapDelete("/auth/cluster/users/{userId}", AccountEndpoints.DeleteAccount);

// The devices somebody is signed in on, and ending them. Listed here because they exist ONLY here: a
// member verifies a cluster session offline against a published key and stores nothing, so a member
// asked what devices somebody holds answers honestly with none — an empty card rather than a wrong
// question. Ending one is never gated on holding the capability, because revoking takes authority
// away and a member that has stood down still holds the rows for what it minted.
app.MapGet("/auth/cluster/users/{userId}/sessions", SessionEndpoints.List);
app.MapPost("/auth/cluster/users/{userId}/sessions/revoke-all", SessionEndpoints.RevokeAll);
app.MapPost("/auth/cluster/users/{userId}/sessions/{sid}/revoke", SessionEndpoints.RevokeOne);

// What this anchor serves to other MEMBERS: the accounts, so each can answer for itself who somebody
// is and what they may do. Authenticated by a member service token, never by a person's session.
app.MapGet("/auth/cluster/snapshot", MemberEndpoints.Snapshot);

// Who may do what: the authority for the pages that administer it, one change at a time, and the
// caller's own actions here. Served from a store at schema version 2, and 503 from one that is not.
app.MapGet("/auth/cluster/authority", AuthorityEndpoints.Read);
app.MapPost("/auth/cluster/authority/edits", AuthorityEndpoints.Edit);
app.MapGet("/me/access", AuthorityEndpoints.MeAccess);

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

// Said at every start, because a panel origin mistyped in the settings is otherwise a sign-in that sends
// nobody back with nothing anywhere saying why.
ClientRegistry registry = app.Services.GetRequiredService<ClientRegistry>();
foreach (RegisteredClient panel in registry.Declared)
    app.Logger.LogInformation("the panel at {Redirect} is a client, as {ClientId}", panel.RedirectUris[0], panel.ClientId);
foreach ((string origin, string problem) in registry.RefusedPanelOrigins)
    app.Logger.LogWarning("the panel origin '{Origin}' is not a client: {Problem}", origin, problem);

app.Run();

return 0;
