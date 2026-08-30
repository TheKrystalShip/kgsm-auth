using Microsoft.Extensions.Caching.Memory;

using TheKrystalShip.KGSM.Auth;
using TheKrystalShip.KGSM.Auth.Anchor;
using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

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

// The staleness bound on a demotion. Short, because the read behind it is a local point query and
// there is nothing to buy by keeping it long.
builder.Services.AddSingleton(sp => new UserStoreAuthority(
    sp.GetRequiredService<IUserStore>(), TimeSpan.FromSeconds(5)));

builder.Services.AddSingleton(sp => new LocalSignInService(
    sp.GetRequiredService<IUserStore>(),
    sp.GetRequiredService<IUserPasswordHasher>(),
    sp.GetRequiredService<UserStoreAuthority>()));

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

// An anchor registers no card source of its own. What it has to say about itself — its id, its kind,
// its addresses, its incarnation — is entirely what the package already holds; the node block exists
// for facts an anchor does not have.
builder.Services.AddSingleton(sp => new AnchorRole(sp.GetRequiredService<ClusterOptions>()));
builder.Services.AddHostedService<ClusterMembershipWorker>();

builder.Services.AddSingleton<ISessionRegistry>(_ => new SqliteSessionRegistry(options.SessionStorePath));
builder.Services.AddSingleton<IMemoryCache>(_ => new MemoryCache(new MemoryCacheOptions()));
builder.Services.AddSingleton<ISessionValidator>(sp => new SessionValidator(
    sp.GetRequiredService<ISessionRegistry>(),
    sp.GetRequiredService<IMemoryCache>(),
    TimeSpan.FromSeconds(5)));
builder.Services.AddSingleton<AnchorAuth>();

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

app.MapPost("/auth/sign-in", Endpoints.SignIn);
app.MapPost("/auth/session/refresh", Endpoints.Refresh);
app.MapPost("/auth/session/sign-out", Endpoints.SignOut);
app.MapGet("/auth/session", Endpoints.Session);
app.MapGet("/auth/cluster/users", Endpoints.Accounts);

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
