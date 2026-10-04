using System.Security.Claims;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.Auth.Minting;
using TheKrystalShip.Auth.Cluster;
using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor;

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
/// <param name="SessionId">The session the bearer belongs to.</param>
/// <param name="Identity">
/// The identity the caller signed in with, as the token carries it. Kept beside the account because
/// it says which door they came through, which the account alone cannot — somebody with a password
/// and a Discord identity attached is one account and two ways in.
/// </param>
/// <remarks>What the caller may do is never here: it is evaluated, per action, against the authority.</remarks>
internal readonly record struct Caller(
    CallerRefusal Refusal,
    KgsmUser? User,
    string? SessionId,
    KgsmIdentity? Identity = null)
{
    /// <summary>Whether there is a caller at all.</summary>
    public bool IsAuthenticated => Refusal == CallerRefusal.None && User is not null;
}

/// <summary>
/// Resolves the account behind a request: the signature, then the session, then the account and
/// whether it is switched off.
/// </summary>
/// <remarks>
/// <para>
/// The three checks are separate because they fail for different reasons and a caller acts
/// differently on each: a bad signature is an unauthenticated stranger, an ended session is somebody
/// who has signed out somewhere, and a disabled account is a person whose access was withdrawn.
/// </para>
/// </remarks>
internal sealed class AnchorAuth(SessionReader sessions, AccountResolver accounts)
{
    /// <summary>The caller behind <paramref name="request"/>.</summary>
    internal async Task<Caller> ResolveAsync(HttpRequest request, CancellationToken ct)
    {
        (CallerRefusal refusal, string? sessionId, KgsmIdentity? identity) =
            await sessions.ReadAsync(request, ct).ConfigureAwait(false);

        if (refusal != CallerRefusal.None || identity is null)
            return new Caller(refusal, null, sessionId);

        AccountAnswer answer = await accounts.ResolveAsync(identity, ct).ConfigureAwait(false);

        return answer.Outcome switch
        {
            AccountOutcome.Disabled =>
                new Caller(CallerRefusal.AccountDisabled, answer.User, sessionId, identity),

            // An account that has been deleted since the session was minted is a stranger holding a
            // token, which is exactly an unauthenticated caller.
            AccountOutcome.NoAccount =>
                new Caller(CallerRefusal.Unauthenticated, null, sessionId),

            _ => new Caller(CallerRefusal.None, answer.User, sessionId, identity),
        };
    }
}

/// <summary>
/// Reads the session behind a request: the signature, the token kind, and whether the session is
/// still alive. Who the session's holder is, and what they may do, is the caller's next question.
/// </summary>
internal sealed class SessionReader(ISessionTokenService tokens, ISessionValidator sessions)
{
    private readonly JsonWebTokenHandler _handler = new();

    /// <summary>The live session on <paramref name="request"/> and who it names, or why there is none.</summary>
    internal async Task<(CallerRefusal Refusal, string? SessionId, KgsmIdentity? Identity)> ReadAsync(
        HttpRequest request, CancellationToken ct)
    {
        string? bearer = ReadBearer(request);
        if (bearer is null)
            return (CallerRefusal.Unauthenticated, null, null);

        TokenValidationResult result =
            await _handler.ValidateTokenAsync(bearer, tokens.ValidationParameters).ConfigureAwait(false);

        if (!result.IsValid || result.ClaimsIdentity is null)
            return (CallerRefusal.Unauthenticated, null, null);

        ClaimsIdentity claims = result.ClaimsIdentity;

        // A refresh token presented as a bearer would turn the long-lived credential into the one
        // sent on every request, which is the whole reason the two are different kinds.
        if (claims.FindFirst(KgsmAuthClaims.TokenKind)?.Value != KgsmTokenKind.Access)
            return (CallerRefusal.Unauthenticated, null, null);

        string? sessionId = SessionClaims.ReadSessionId(claims);
        if (sessionId is null)
            return (CallerRefusal.Unauthenticated, null, null);

        if (!await sessions.IsValidAsync(sessionId, ct).ConfigureAwait(false))
            return (CallerRefusal.SessionEnded, sessionId, null);

        KgsmIdentity? identity = SessionClaims.ReadIdentity(claims);
        return identity is null
            ? (CallerRefusal.Unauthenticated, sessionId, null)
            : (CallerRefusal.None, sessionId, identity);
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
