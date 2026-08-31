using System.Security.Claims;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>Why a request carries no usable caller.</summary>
internal enum CallerRefusal
{
    /// <summary>There is a caller.</summary>
    None = 0,

    /// <summary>No bearer, an unreadable one, or one this anchor did not sign.</summary>
    Unauthenticated,

    /// <summary>A valid token for a session that has been ended.</summary>
    SessionEnded,

    /// <summary>A valid session for an account that has been switched off.</summary>
    AccountDisabled,
}

/// <summary>The caller behind a request, or why there is not one.</summary>
/// <param name="Refusal">Why this is not a caller, or <see cref="CallerRefusal.None"/>.</param>
/// <param name="User">The account, resolved from the store on this request.</param>
/// <param name="Tier">What they may do, resolved on this request rather than read off the token.</param>
/// <param name="SessionId">The session the bearer belongs to.</param>
/// <param name="Identity">
/// The identity the caller signed in with, as the token carries it. Kept beside the account because
/// it says which door they came through, which the account alone cannot — somebody with a password
/// and a Discord identity attached is one account and two ways in.
/// </param>
internal readonly record struct Caller(
    CallerRefusal Refusal,
    KgsmUser? User,
    KgsmTier Tier,
    string? SessionId,
    KgsmIdentity? Identity = null)
{
    /// <summary>Whether there is a caller at all.</summary>
    public bool IsAuthenticated => Refusal == CallerRefusal.None && User is not null;

    /// <summary>
    /// Whether the caller holds at least <paramref name="required"/>. The tiers are ordered, so an
    /// admin satisfies an operator requirement and an operator satisfies a viewer one.
    /// </summary>
    public bool Holds(KgsmTier required) => IsAuthenticated && Tier >= required;
}

/// <summary>
/// Resolves the caller behind a request: the signature, then the session, then the account.
/// </summary>
/// <remarks>
/// <para>
/// <b>Authority is read from the store on every request, never from the token.</b> The tier claim a
/// bearer carries is what was true when it was minted; a demotion has to take effect at the next
/// request rather than at the token's expiry, so the claim is overwritten by what the store says now.
/// </para>
/// <para>
/// The three checks are separate because they fail for different reasons and a caller acts
/// differently on each: a bad signature is an unauthenticated stranger, an ended session is somebody
/// who has signed out somewhere, and a disabled account is a person whose access was withdrawn.
/// </para>
/// </remarks>
internal sealed class AnchorAuth(
    ISessionTokenService tokens,
    ISessionValidator sessions,
    UserStoreAuthority authority)
{
    private readonly JsonWebTokenHandler _handler = new();

    /// <summary>The caller behind <paramref name="request"/>.</summary>
    internal async Task<Caller> ResolveAsync(HttpRequest request, CancellationToken ct)
    {
        string? bearer = ReadBearer(request);
        if (bearer is null)
            return new Caller(CallerRefusal.Unauthenticated, null, KgsmTier.None, null);

        TokenValidationResult result =
            await _handler.ValidateTokenAsync(bearer, tokens.ValidationParameters).ConfigureAwait(false);

        if (!result.IsValid || result.ClaimsIdentity is null)
            return new Caller(CallerRefusal.Unauthenticated, null, KgsmTier.None, null);

        ClaimsIdentity claims = result.ClaimsIdentity;

        // A refresh token presented as a bearer would turn the long-lived credential into the one
        // sent on every request, which is the whole reason the two are different kinds.
        if (claims.FindFirst(KgsmAuthClaims.TokenKind)?.Value != KgsmTokenKind.Access)
            return new Caller(CallerRefusal.Unauthenticated, null, KgsmTier.None, null);

        string? sessionId = SessionClaims.ReadSessionId(claims);
        if (sessionId is null)
            return new Caller(CallerRefusal.Unauthenticated, null, KgsmTier.None, null);

        if (!await sessions.IsValidAsync(sessionId, ct).ConfigureAwait(false))
            return new Caller(CallerRefusal.SessionEnded, null, KgsmTier.None, sessionId);

        KgsmIdentity? identity = SessionClaims.ReadIdentity(claims);
        if (identity is null)
            return new Caller(CallerRefusal.Unauthenticated, null, KgsmTier.None, sessionId);

        AuthorityAnswer answer = await authority.ResolveAsync(identity, ct).ConfigureAwait(false);

        return answer.Outcome switch
        {
            AuthorityOutcome.Disabled =>
                new Caller(CallerRefusal.AccountDisabled, answer.User, KgsmTier.None, sessionId, identity),

            // An account that has been deleted since the session was minted is a stranger holding a
            // token, which is exactly an unauthenticated caller.
            AuthorityOutcome.NoAccount =>
                new Caller(CallerRefusal.Unauthenticated, null, KgsmTier.None, sessionId),

            _ => new Caller(CallerRefusal.None, answer.User, answer.Tier, sessionId, identity),
        };
    }

    /// <summary>
    /// The bearer token on a request, or null. Only the <c>Authorization</c> header is read: a token
    /// in a query string lands in every access log and proxy cache it passes through.
    /// </summary>
    private static string? ReadBearer(HttpRequest request)
    {
        string? header = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header))
            return null;

        const string scheme = "Bearer ";
        if (!header.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
            return null;

        string token = header[scheme.Length..].Trim();
        return token.Length == 0 ? null : token;
    }
}
