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
/// <param name="PublicBaseUrl">Where other members reach it, when it cannot see its own address.</param>
/// <param name="ClusterId">The token audience: the cluster a session is valid on.</param>
/// <param name="Issuer">The <c>iss</c> claim.</param>
/// <param name="UserStorePath">The account store.</param>
/// <param name="SessionStorePath">Where live sessions are recorded.</param>
/// <param name="SigningKeyPath">The private signing key.</param>
/// <param name="PublishedKeyPath">Where the public half is written, or null to publish no file.</param>
/// <param name="AccessLifetime">How long an access bearer lives.</param>
/// <param name="RefreshLifetime">The absolute session cap.</param>
/// <param name="AllowedOrigins">Browser origins allowed to call this anchor.</param>
/// <param name="SessionCleanup">How often expired session rows are swept.</param>
/// <param name="FrontendUrl">Where a browser lands after a provider sign-in, or null to answer as JSON.</param>
/// <param name="Pending">What is allowed to accumulate while nobody has approved it.</param>
/// <param name="AllowSelfRegistration">Whether somebody with no account may make one.</param>
/// <param name="ReauthWindow">How long a proved credential lets somebody change what proves them.</param>
internal sealed record AnchorOptions(
    string MemberId,
    string ListenAddress,
    string PublicBaseUrl,
    string ClusterId,
    string Issuer,
    string UserStorePath,
    string SessionStorePath,
    string SigningKeyPath,
    string? PublishedKeyPath,
    TimeSpan AccessLifetime,
    TimeSpan RefreshLifetime,
    IReadOnlyList<string> AllowedOrigins,
    TimeSpan SessionCleanup,
    string? FrontendUrl,
    PendingPolicy Pending,
    bool AllowSelfRegistration,
    TimeSpan ReauthWindow)
{
    /// <summary>
    /// Where a provider sends the browser back, for one provider.
    /// </summary>
    /// <remarks>
    /// Built from this anchor's own public address rather than configured per provider, so the two
    /// callbacks a provider needs registered against it can never name different origins. A provider
    /// accepts only redirect URIs registered on the application, so this exact string has to be one
    /// of them or the bounce is refused at the provider, where no log here sees it.
    /// </remarks>
    public string RedirectUri(string provider) =>
        $"{PublicBaseUrl.TrimEnd('/')}/auth/{provider}/callback";

    /// <summary>
    /// Where a provider sends the browser back when somebody is <em>attaching</em> an account rather
    /// than signing in with one.
    /// </summary>
    /// <remarks>
    /// A separate address because the two arrivals mean different things and must not be confused: one
    /// mints a session for whoever comes back, the other attaches whoever comes back to an account
    /// that is already signed in. Both have to be registered against the provider's application, or
    /// the bounce is refused at the provider where no log here sees it.
    /// </remarks>
    public string LinkRedirectUri(string provider) =>
        $"{PublicBaseUrl.TrimEnd('/')}/auth/identities/{provider}/callback";

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
            ClusterId: Text(s.ClusterId, "kgsm-cluster"),
            Issuer: Text(s.Issuer, "kgsm"),
            UserStorePath: Text(s.UserStorePath, UserStoreOptions.DefaultPath),
            SessionStorePath: Text(s.SessionStorePath, "/var/lib/kgsm-auth-anchor/sessions.db"),
            SigningKeyPath: Text(s.SigningKeyPath, "/var/lib/kgsm-auth-anchor/session-signing.pem"),
            // Blank is a decision, not an omission: an anchor with no member beside it publishes no
            // file and serves the key over HTTP alone.
            PublishedKeyPath: string.IsNullOrWhiteSpace(s.PublishedKeyPath) ? null : s.PublishedKeyPath.Trim(),
            AccessLifetime: TimeSpan.FromMinutes(
                AtLeast(s.AccessLifetimeMinutes ?? 15, AnchorSettings.Floors.AccessLifetimeMinutes)),
            RefreshLifetime: TimeSpan.FromDays(
                AtLeast(s.RefreshLifetimeDays ?? 30, AnchorSettings.Floors.RefreshLifetimeDays)),
            AllowedOrigins: Origins(s.AllowedOrigins),
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
            ReauthWindow: TimeSpan.FromMinutes(AtLeast(s.ReauthWindowMinutes ?? 5, 1)));
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
