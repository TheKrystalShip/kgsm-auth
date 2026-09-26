namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// The claim names a KGSM session token carries. Named here so the token the anchor mints reads
/// identically on every member that verifies it. A token proves who; nothing it carries says what the
/// holder may do.
/// </summary>
public static class KgsmAuthClaims
{
    /// <summary>The host id this bearer is scoped to (mirrors the token audience).</summary>
    public const string Host = "host";

    /// <summary>
    /// Token kind — <see cref="KgsmTokenKind"/>. Keeps a refresh token from being accepted as an
    /// access bearer on a protected endpoint.
    /// </summary>
    public const string TokenKind = "tkn";

    /// <summary>The provider's username, a login-time profile snapshot.</summary>
    public const string Username = "uname";

    /// <summary>The provider's display name, a login-time profile snapshot.</summary>
    public const string Display = "disp";

    /// <summary>The provider's avatar URL, a login-time profile snapshot. Optional.</summary>
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
