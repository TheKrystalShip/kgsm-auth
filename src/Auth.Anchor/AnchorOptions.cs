using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The validated form of <see cref="AnchorSettings"/>: what the daemon actually runs on, with every
/// value clamped to something it can honour.
/// </summary>
/// <remarks>
/// Separate from the settings type so the raw configuration and the runtime view stay distinguishable.
/// A value below its floor is raised rather than refused — a daemon that will not start because a
/// number is one below a bound is worse than one that starts and says what it used.
/// </remarks>
/// <param name="MemberId">This anchor's identity as a cluster member.</param>
/// <param name="ListenAddress">Where Kestrel binds.</param>
/// <param name="PublicBaseUrl">Where browsers and other members reach it, when configured.</param>
/// <param name="PublicHost">Where it is reached from the internet, as the DNS anchor points its name.</param>
/// <param name="ClusterId">The token audience: the cluster a session is valid on.</param>
/// <param name="Issuer">The <c>iss</c> claim; the provider's browser-facing URL when it serves OpenID Connect.</param>
/// <param name="UserStorePath">The account store.</param>
/// <param name="SessionStorePath">Where live sessions are recorded.</param>
/// <param name="SigningKeyPath">The private signing key.</param>
/// <param name="ConfigDescriptorPath">The descriptor this anchor's own configuration surface is read from.</param>
/// <param name="ConfigOverridePath">Where a change made through that surface is written.</param>
/// <param name="AccessLifetime">How long an access bearer lives.</param>
/// <param name="RefreshLifetime">The absolute session cap.</param>
/// <param name="AllowedOrigins">Browser origins allowed to call this anchor.</param>
/// <param name="PanelOrigins">Origins a Control Panel is served from with no member behind it.</param>
/// <param name="SessionCleanup">How often expired session rows are swept.</param>
/// <param name="FrontendUrl">Where a browser lands after a provider sign-in, or null to answer as JSON.</param>
/// <param name="Pending">What is allowed to accumulate while nobody has approved it.</param>
/// <param name="AllowSelfRegistration">Whether somebody with no account may make one.</param>
/// <param name="ReauthWindow">How long a proved credential lets somebody change what proves them.</param>
/// <param name="UiPath">Where the provider's pages are installed.</param>
internal sealed record AnchorOptions(
    string MemberId,
    string ListenAddress,
    string PublicBaseUrl,
    string PublicHost,
    string ClusterId,
    string Issuer,
    string UserStorePath,
    string SessionStorePath,
    string SigningKeyPath,
    string ConfigDescriptorPath,
    string ConfigOverridePath,
    TimeSpan AccessLifetime,
    TimeSpan RefreshLifetime,
    IReadOnlyList<string> AllowedOrigins,
    IReadOnlyList<string> PanelOrigins,
    TimeSpan SessionCleanup,
    string? FrontendUrl,
    PendingPolicy Pending,
    bool AllowSelfRegistration,
    TimeSpan ReauthWindow,
    string UiPath)
{
    /// <summary>
    /// Where the bootstrap administrator's one-time password is left, on an anchor whose account store
    /// was empty when it first started.
    /// </summary>
    /// <remarks>
    /// Beside the session store rather than beside the accounts: the accounts may be a file shared
    /// with every other KGSM service on the machine, and a credential belongs to the daemon that
    /// minted it, in the directory only that daemon writes.
    /// </remarks>
    public string InitialAdminPasswordPath =>
        Path.Combine(
            Path.GetDirectoryName(Path.GetFullPath(SessionStorePath)) is { Length: > 0 } dir ? dir : ".",
            "initial-admin-password");

    /// <summary>
    /// The issuer as the browser-facing URL the OpenID Connect doors are served under, or null when the
    /// configured issuer is not one.
    /// </summary>
    /// <remarks>
    /// Configuration, never inferred from a request: a Host header is the caller's to set, and an issuer
    /// taken from one would let any caller choose what every token it is handed says about who minted
    /// it. An anchor with no URL here serves no OpenID Connect door, and says so rather than guessing.
    /// </remarks>
    public Uri? IssuerUrl =>
        Uri.TryCreate(Issuer, UriKind.Absolute, out Uri? uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
        && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment)
            ? uri
            : null;

    /// <summary>The issuer's origin — what a browser sends as <c>Origin</c> from the provider's own pages.</summary>
    public string? IssuerOrigin => IssuerUrl?.GetLeftPart(UriPartial.Authority);

    /// <summary>Whether a browser is sent anywhere after a provider sign-in.</summary>
    public bool RedirectsToPanel => !string.IsNullOrWhiteSpace(FrontendUrl);

    public static AnchorOptions FromSettings(AnchorSettings s)
    {
        return new AnchorOptions(
            MemberId: DeriveMemberId(s.MemberId),
            ListenAddress: Text(s.ListenAddress, "http://0.0.0.0:8098"),
            // Blank is the ordinary case, not a gap: a machine that can see its own address has one
            // reflected back to it when a member joins.
            PublicBaseUrl: s.PublicBaseUrl?.Trim() ?? "",
            PublicHost: s.PublicHost?.Trim() ?? "",
            ClusterId: Text(s.ClusterId, "kgsm-cluster"),
            // A URL loses the trailing slash a person naturally types, so the discovery document, every
            // token's iss and the gossiped fact all state the one string a client compares them by.
            Issuer: Text(s.Issuer, "kgsm").TrimEnd('/'),
            UserStorePath: Text(s.UserStorePath, UserStoreOptions.DefaultPath),
            SessionStorePath: Text(s.SessionStorePath, "/var/lib/kgsm-auth-anchor/sessions.db"),
            SigningKeyPath: Text(s.SigningKeyPath, "/var/lib/kgsm-auth-anchor/session-signing.pem"),
            ConfigDescriptorPath: s.ConfigDescriptorPath.Trim(),
            ConfigOverridePath: s.ConfigOverridePath.Trim(),
            AccessLifetime: TimeSpan.FromMinutes(
                AtLeast(s.AccessLifetimeMinutes ?? 15, AnchorSettings.Floors.AccessLifetimeMinutes)),
            RefreshLifetime: TimeSpan.FromDays(
                AtLeast(s.RefreshLifetimeDays ?? 30, AnchorSettings.Floors.RefreshLifetimeDays)),
            AllowedOrigins: Origins(s.AllowedOrigins),
            PanelOrigins: Origins(s.PanelOrigins),
            SessionCleanup: TimeSpan.FromMinutes(
                AtLeast(s.SessionCleanupMinutes ?? 60, AnchorSettings.Floors.SessionCleanupMinutes)),
            // Blank is a decision rather than an omission: a deployment with no browser in front of it
            // wants the session in the response, not a redirect to somewhere there is nothing.
            FrontendUrl: string.IsNullOrWhiteSpace(s.FrontendUrl) ? null : s.FrontendUrl.Trim(),
            // Off unless a cluster says otherwise. It is an unauthenticated write, and a cluster that
            // has not decided to take strangers should not be taking them because a default did.
            AllowSelfRegistration: s.AllowSelfRegistration ?? false,
            Pending: new PendingPolicy(
                Cap: Math.Max(0, s.PendingCap ?? 25),
                Ttl: TimeSpan.FromDays(AtLeast(s.PendingTtlDays ?? 14, 1))),
            ReauthWindow: TimeSpan.FromMinutes(AtLeast(s.ReauthWindowMinutes ?? 5, 1)),
            UiPath: Text(s.UiPath, "/usr/share/kgsm-web-auth"));
    }

    /// <summary>
    /// This anchor's cluster identity, derived from the machine name when none is configured.
    /// </summary>
    /// <remarks>
    /// Suffixed rather than taken bare, because a machine can run more than one member and two
    /// members sharing an id are one member counted twice — the roster's unique index would collapse
    /// a node and the anchor beside it into a single row.
    /// </remarks>
    private static string DeriveMemberId(string? configured) =>
        string.IsNullOrWhiteSpace(configured)
            ? Environment.MachineName.Trim().ToLowerInvariant() + "-auth"
            : configured.Trim();

    private static string Text(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private static int AtLeast(int value, int floor) => value < floor ? floor : value;

    /// <summary>
    /// The origin list, trimmed of the trailing slash a person naturally types. A browser sends
    /// <c>Origin: https://panel.example</c> with no path and no slash, so an entry carrying one
    /// matches nothing and reads as an origin that was allowed and is not.
    /// </summary>
    private static IReadOnlyList<string> Origins(string? csv) =>
        string.IsNullOrWhiteSpace(csv)
            ? []
            : [.. csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     .Select(o => o.TrimEnd('/'))
                     .Where(o => o.Length > 0)];
}
