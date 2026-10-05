using TheKrystalShip.Auth.Anchor;
using TheKrystalShip.Auth.Minting;
using TheKrystalShip.KGSM.Cluster;

var builder = WebApplication.CreateSlimBuilder(args);

// The daemon's settings file, loaded from beside the binary. Two reasons it is explicit:
//   1. CreateSlimBuilder under a systemd unit with no WorkingDirectory leaves the content root at
//      "/", so the framework's own appsettings.json discovery finds nothing and the file's settings
//      silently never apply. AppContext.BaseDirectory is the binary's own directory, which is where
//      deploy installs the file.
//   2. It is named tks-auth.settings.json rather than appsettings.json, so it can never
//      collide with a sibling ecosystem service's config if they ever share a directory.
builder.Configuration.AddJsonFile(
    Path.Combine(AppContext.BaseDirectory, "tks-auth.settings.json"),
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

// `tks-auth owner grant <username>` — the Owner recovery path, run on this host as the anchor's
// service account. It reads the same settings the daemon does, so it opens the store the daemon opens.
if (args is [OwnerCommand.Verb, ..])
    return await OwnerCommand.RunAsync(args, options);

// The private key, generated once on a machine that has none. Read before the host is built so a key
// that cannot be read stops the daemon here rather than at the first sign-in attempt.
//
// A key that is present and unreadable ends the process, and never yields a fresh one: every surface
// that verifies sessions holds this key's public half, so replacing it would invalidate every session
// at once and leave every verifier checking against something nothing signs with. The failure is
// written as one line naming the file, because an operator reading it has a file to fix — an
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
        + "one invalidates every session there is");
    return 1;
}

// The core — accounts, sessions, the OpenID Connect provider, its clients, the account and admin
// doors, the journal — and, only when a KGSM cluster is configured, the KGSM module beside it. The
// cluster secret is the one switch: with none, this machine holds its own accounts and serves
// everything, and nothing under /etc/kgsm or /var/lib/kgsm is read or written.
ClusterOptions cluster = KgsmModule.ClusterFrom(builder.Configuration, options);

builder.Services.AddTksAuthCore(options, signer, clustered: cluster.Enabled);
if (cluster.Enabled)
    builder.Services.AddKgsmModule(options, cluster);

// A person signs in here directly, so this is a TCP surface rather than a leaf's unix socket.
builder.WebHost.UseUrls(options.ListenAddress);

WebApplication app = builder.Build();

app.UseMiddleware<CorsMiddleware>();

app.MapTksAuthCore();
if (cluster.Enabled)
    app.MapKgsmModule();

app.Logger.LogInformation(
    "tks-auth listening on {Address}, {Standing}, as {Member} for audience {Cluster} — accounts {Store}, "
    + "signing key {Key} ({Origin})",
    options.ListenAddress, cluster.Enabled ? "in a KGSM cluster" : "standalone", options.MemberId,
    options.ClusterId, options.UserStorePath,
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
