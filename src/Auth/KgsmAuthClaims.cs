namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// The claim names a KGSM session token carries, and the relay headers a trusted caller forwards an
/// already-resolved identity with. Both are named here so a token minted by one surface reads
/// identically in another, and so a relay's headers cannot drift apart between the sender and the
/// receiver.
/// </summary>
public static class KgsmAuthClaims
{
    /// <summary>The authorization tier, as a <see cref="KgsmTiers"/> wire string.</summary>
    public const string Tier = "tier";

    /// <summary>The host id this bearer is scoped to (mirrors the token audience).</summary>
    public const string Host = "host";

    /// <summary>
    /// Token kind — <see cref="KgsmTokenKind"/>. Keeps a refresh token from being accepted as an
    /// access bearer on a protected endpoint.
    /// </summary>
    public const string TokenKind = "tkn";

    /// <summary>Discord username, a login-time profile snapshot.</summary>
    public const string Username = "uname";

    /// <summary>Discord display name, a login-time profile snapshot.</summary>
    public const string Display = "disp";

    /// <summary>Discord avatar URL, a login-time profile snapshot. Optional.</summary>
    public const string Avatar = "avatar";

    /// <summary>
    /// The session id, stable across a session's lifetime and carried by both the access and the
    /// refresh token. It is the key a session registry answers "is this session still alive" with —
    /// the one fact a stateless JWT cannot answer on its own.
    /// </summary>
    public const string SessionId = "sid";

    /// <summary>
    /// The per-token id, fresh on every mint. The session row stores the current refresh token's
    /// value, so a refresh presenting a stale one is a replay and is refused.
    /// </summary>
    public const string Jti = "jti";
}

/// <summary>The two kinds of token carried in the <see cref="KgsmAuthClaims.TokenKind"/> claim.</summary>
public static class KgsmTokenKind
{
    public const string Access = "access";
    public const string Refresh = "refresh";
}

/// <summary>
/// Headers a trusted, co-located caller forwards a verified end-user with, instead of that user
/// logging in a second time. The receiving service authenticates the <em>relay</em> by the shared
/// secret and then acts as the forwarded identity.
/// </summary>
/// <remarks>
/// Authority rides as one tier rather than a set of booleans, so the relay cannot express a
/// permission shape the rest of the ecosystem does not have. Parsing is fail-closed: an absent or
/// unrecognised <see cref="Tier"/> is <see cref="KgsmTier.None"/>, so a relay that does not speak
/// this header can never silently grant anything.
/// </remarks>
public static class KgsmRelayHeaders
{
    /// <summary>The shared secret proving the caller is the trusted relay.</summary>
    public const string Secret = "X-Relay-Secret";

    /// <summary>The Discord user id the relay is acting on behalf of.</summary>
    public const string User = "X-Relay-User";

    /// <summary>That user's display name, for rendering only.</summary>
    public const string UserName = "X-Relay-User-Name";

    /// <summary>The tier the relay resolved for that user, as a <see cref="KgsmTiers"/> wire string.</summary>
    public const string Tier = "X-Relay-Tier";
}
