using System.Security.Claims;

namespace TheKrystalShip.KGSM.Auth.Sessions;

/// <summary>
/// Reads identity, tier and session back out of a validated token's claims — shared by the refresh
/// path and by anything answering "who is this caller".
/// </summary>
/// <remarks>
/// The profile here is the snapshot taken at login, not a live read: no KGSM surface keeps an
/// identity provider's token, so there is nothing to re-fetch with. A display name that changed at
/// the provider after login stays stale until the next one, which is the honest consequence of not
/// retaining the token and is preferable to holding one.
/// </remarks>
public static class SessionClaims
{
    /// <summary>
    /// The identity a token carries, or <see langword="null"/> when the subject is absent or is not a
    /// <c>provider:subject</c> handle. A caller with no readable identity is treated as
    /// unauthenticated rather than as an anonymous someone.
    /// </summary>
    /// <remarks>
    /// The provider is read from the handle rather than matched against a list this build knows: a
    /// token minted by a host configured with a provider this build predates still names a real
    /// person, and refusing it would make adding a provider a synchronised upgrade across every
    /// surface. Authority does not ride on the provider — that is the <c>tier</c> claim, checked
    /// separately — so reading an unfamiliar one grants nothing.
    /// </remarks>
    public static KgsmIdentity? ReadIdentity(ClaimsIdentity ci)
    {
        string? sub = ci.FindFirst("sub")?.Value ?? ci.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!KgsmActor.TryParse(sub, out string provider, out string subject))
            return null;

        string username = ci.FindFirst(KgsmAuthClaims.Username)?.Value ?? subject;
        string display = ci.FindFirst(KgsmAuthClaims.Display)?.Value ?? username;
        string? avatar = ci.FindFirst(KgsmAuthClaims.Avatar)?.Value;
        string scope = ci.FindFirst("scope")?.Value ?? "";

        return new KgsmIdentity(
            provider, subject, username, display, avatar,
            [.. scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)]);
    }

    /// <summary>The tier claim. A missing or unreadable one parses to <see cref="KgsmTier.None"/>.</summary>
    public static KgsmTier ReadTier(ClaimsIdentity ci) =>
        KgsmTiers.Parse(ci.FindFirst(KgsmAuthClaims.Tier)?.Value);

    /// <summary>
    /// The session id, or <see langword="null"/> on a token that carries none. A token with no
    /// session is one no registry can revoke, so a surface that has a registry rejects it.
    /// </summary>
    public static string? ReadSessionId(ClaimsIdentity ci) =>
        ci.FindFirst(KgsmAuthClaims.SessionId)?.Value;

    /// <summary>
    /// The per-token id. On the refresh path it is checked against what the session currently holds,
    /// which is the reuse detection; on an access token it is informational, because a short lifetime
    /// plus the registry check already bound it.
    /// </summary>
    public static string? ReadJti(ClaimsIdentity ci) =>
        ci.FindFirst(KgsmAuthClaims.Jti)?.Value;
}
