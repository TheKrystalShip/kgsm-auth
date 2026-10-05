using System.Security.Claims;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.Auth.Cluster;

namespace TheKrystalShip.Auth.Minting;

/// <summary>A just-minted token, its absolute expiry, and the <c>jti</c> it was minted with.</summary>
/// <remarks>
/// The expiry is returned rather than left for the client to decode out of the JWT: the anchor handing
/// a session to a browser should be able to say when it dies without the browser parsing a token it
/// is not supposed to interpret. The <c>jti</c> goes to the registry, where a refresh token's value
/// becomes the reuse-detection key.
/// </remarks>
public sealed record MintedToken(string Token, DateTimeOffset ExpiresAt, string Jti);

/// <summary>
/// What a valid refresh token yields: enough to re-mint an access token without going back to the
/// identity provider.
/// </summary>
/// <remarks>
/// The anchor re-reads the account before it mints the next pair, so a token outliving its account's
/// switch-off buys nothing.
/// </remarks>
public sealed record RefreshClaims(KgsmIdentity Identity, string SessionId, string Jti)
{
    /// <summary>
    /// The audience it was minted for: the cluster for a KGSM session, the issuer for a session of an
    /// application outside KGSM.
    /// </summary>
    public string? Audience { get; init; }
}

/// <summary>
/// An access token for an application outside KGSM: who it names, and what that application's audience,
/// lifetime and actions are.
/// </summary>
/// <param name="Subject">The account, as the application keys a person: the <c>id_token</c>'s subject.</param>
/// <param name="Username">The account's username, as <c>preferred_username</c>.</param>
/// <param name="DisplayName">What the account is shown as, as <c>name</c>.</param>
/// <param name="Picture">The account's picture, when one is known.</param>
/// <param name="SessionId">
/// The session it is scoped to, carried as <c>sid</c>; null for a token minted by an exchange, which
/// belongs to no session and is never refreshed.
/// </param>
/// <param name="ClientId">The client it was minted for.</param>
/// <param name="Audience">The application's audience, the one string its resource server checks.</param>
/// <param name="Lifetime">How long it lives: the application's, never KGSM's.</param>
/// <param name="Actions">
/// The application's actions the account holds, evaluated at this mint. Carried in
/// <see cref="ApplicationClaims.Actions"/>, an array even when it is empty.
/// </param>
public sealed record ApplicationAccess(
    string Subject,
    string Username,
    string DisplayName,
    string? Picture,
    string? SessionId,
    string ClientId,
    string Audience,
    TimeSpan Lifetime,
    IReadOnlyList<string> Actions)
{
    /// <summary>
    /// The client acting for the account, carried as <c>act</c> (RFC 8693 §4.1) — <c>{"sub": "&lt;client id&gt;"}</c> —
    /// or null when the account's holder is the one presenting it.
    /// </summary>
    public string? Actor { get; init; }
}

/// <summary>The claims an access token for an application outside KGSM carries beyond the registered ones.</summary>
public static class ApplicationClaims
{
    /// <summary>
    /// The application's actions the account holds, as an array of action ids. An application reads it
    /// under a name it is configured with, so a provider other than tks-auth can emit its own.
    /// </summary>
    public const string Actions = "tks_actions";

    /// <summary>The client the token was minted for (RFC 9068).</summary>
    public const string ClientId = "client_id";

    /// <summary>The JWT <c>typ</c> of an access token (RFC 9068), which no id token carries.</summary>
    public const string AccessTokenType = "at+jwt";

    /// <summary>
    /// Who is acting for the subject (RFC 8693 §4.1): an object whose <c>sub</c> is the acting client's id.
    /// A resource server holding a token with it is being called by that client on the subject's behalf.
    /// </summary>
    public const string Actor = "act";
}

/// <summary>How the anchor mints session tokens.</summary>
/// <param name="Audience">
/// The token audience: the cluster a session is valid on. Every member verifies against it, so
/// changing it on a running cluster invalidates every session at once.
/// </param>
/// <param name="AccessLifetime">How long an access bearer lives. Short — it bounds privilege.</param>
/// <param name="RefreshLifetime">
/// The absolute session cap: how long someone stays signed in, rotating access tokens, before a fresh
/// sign-in. <b>The registry's expiry must be written from this same value</b>, which is why it is a
/// setting and not a constant — two copies of one lifetime drift, and the drift is invisible until a
/// token outlives its own row or the reverse.
/// </param>
/// <param name="Issuer">
/// The <c>iss</c> claim: the provider's browser-facing URL, which every member validates. <b>Changing
/// it on a running cluster invalidates every token already issued</b>.
/// </param>
public sealed record SessionTokenOptions(
    string Audience,
    TimeSpan AccessLifetime,
    TimeSpan RefreshLifetime,
    string Issuer);

/// <summary>
/// Mints and reads the cluster's session JWTs. An <em>access</em> token is the bearer on every
/// protected request; a <em>refresh</em> token buys a new one without a fresh sign-in, until the
/// absolute cap.
/// </summary>
/// <remarks>
/// A KGSM session proves who and carries no claim about what: a member resolves what the holder may do
/// from its own replica on every request, so nothing a token says can outlive a revocation. An
/// application outside KGSM holds no replica, so its access token lists that application's actions the
/// holder has, evaluated at every mint, and its short lifetime bounds how long a list outlives a change.
/// </remarks>
public interface ISessionTokenService
{
    /// <summary>Mint a short-lived access bearer, scoped to a session.</summary>
    /// <param name="identity">Who the session belongs to.</param>
    /// <param name="sessionId">The session it is scoped to.</param>
    MintedToken MintAccess(KgsmIdentity identity, string sessionId);

    /// <summary>Mint the refresh token for a session. Its lifetime is the absolute cap.</summary>
    /// <param name="identity">Who the session belongs to.</param>
    /// <param name="sessionId">The session it is scoped to.</param>
    MintedToken MintRefresh(KgsmIdentity identity, string sessionId);

    /// <summary>
    /// Mint an access token for an application outside KGSM: its audience, its lifetime, and the
    /// actions claim, typed <c>at+jwt</c>.
    /// </summary>
    MintedToken MintApplicationAccess(ApplicationAccess access);

    /// <summary>
    /// Mint the refresh token for a session of an application outside KGSM. Its audience is the issuer:
    /// it is presented back here and nowhere else, so no application's resource server accepts it.
    /// </summary>
    MintedToken MintApplicationRefresh(KgsmIdentity identity, string sessionId);

    /// <summary>
    /// Validate a presented refresh token — a KGSM session's, audienced to the cluster, or an
    /// application's, audienced to the issuer. Returns <see langword="null"/> when it is invalid, expired,
    /// not a refresh token, or missing the <c>sid</c>/<c>jti</c> a session needs — the caller answers
    /// 401 and does not try to salvage a partial answer.
    /// </summary>
    Task<RefreshClaims?> ReadRefreshAsync(string token);

    /// <summary>
    /// The validation rules for what this service mints. Handing these out rather than re-declaring
    /// them is what keeps the issuer, audience and key from disagreeing between the mint and the check.
    /// </summary>
    TokenValidationParameters ValidationParameters { get; }
}

/// <summary>ES256 session tokens, signed with the anchor's private key.</summary>
public sealed class SessionTokenService : ISessionTokenService
{
    private readonly SessionTokenOptions _options;
    private readonly SigningCredentials _signing;
    private readonly JsonWebTokenHandler _handler = new();
    private readonly TokenValidationParameters _refreshValidation;

    public TokenValidationParameters ValidationParameters { get; }

    /// <param name="options">The audience, lifetimes and issuer the anchor mints under.</param>
    /// <param name="signer">
    /// The private key. Every member verifies against its published public half and holds nothing that
    /// could produce a signature.
    /// </param>
    public SessionTokenService(SessionTokenOptions options, EcdsaSessionSigner signer)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signer);

        _options = options;
        _signing = signer.Credentials;

        ValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = options.Issuer,
            ValidateAudience = true,
            ValidAudience = options.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signer.VerificationKey,
            // Pinned, so a token offering any other algorithm is refused before its signature is
            // looked at. Without it a public verification key is one an attacker may present as an
            // HMAC secret, and the key everybody holds becomes the key everybody can sign with.
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidateLifetime = true,
            ClockSkew = ClusterSessionValidation.ClockSkew,
            NameClaimType = "sub",
        };

        // A refresh token comes back only here, audienced to the cluster for a KGSM session and to the
        // issuer for an application's, so this one check accepts both and the bearer check above
        // accepts neither of an application's.
        _refreshValidation = ValidationParameters.Clone();
        _refreshValidation.ValidAudience = null;
        _refreshValidation.ValidAudiences = [options.Audience, options.Issuer];
    }

    public MintedToken MintAccess(KgsmIdentity identity, string sessionId) =>
        Mint(identity, KgsmTokenKind.Access, _options.AccessLifetime, sessionId, _options.Audience);

    public MintedToken MintRefresh(KgsmIdentity identity, string sessionId) =>
        Mint(identity, KgsmTokenKind.Refresh, _options.RefreshLifetime, sessionId, _options.Audience);

    public MintedToken MintApplicationRefresh(KgsmIdentity identity, string sessionId) =>
        Mint(identity, KgsmTokenKind.Refresh, _options.RefreshLifetime, sessionId, _options.Issuer);

    public MintedToken MintApplicationAccess(ApplicationAccess access)
    {
        ArgumentNullException.ThrowIfNull(access);

        string jti = Guid.NewGuid().ToString("N");
        DateTime now = DateTime.UtcNow;
        DateTime expires = now.Add(access.Lifetime);

        // The registered claims an OpenID Connect resource server reads (RFC 9068), the profile an
        // id_token carries under the same names, and the actions — an array whatever its length, so a
        // reader never has to tell one action from a list of them.
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["sub"] = access.Subject,
            [ApplicationClaims.ClientId] = access.ClientId,
            [KgsmAuthClaims.TokenKind] = KgsmTokenKind.Access,
            [KgsmAuthClaims.Jti] = jti,
            ["preferred_username"] = access.Username,
            ["name"] = access.DisplayName,
            [ApplicationClaims.Actions] = access.Actions.ToArray(),
        };
        if (access.SessionId is not null)
            claims[KgsmAuthClaims.SessionId] = access.SessionId;
        if (access.Picture is not null)
            claims["picture"] = access.Picture;
        if (access.Actor is not null)
            claims[ApplicationClaims.Actor] = new Dictionary<string, object>(StringComparer.Ordinal) { ["sub"] = access.Actor };

        string token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = access.Audience,
            Claims = claims,
            Expires = expires,
            IssuedAt = now,
            TokenType = ApplicationClaims.AccessTokenType,
            SigningCredentials = _signing,
        });

        return new MintedToken(token, new DateTimeOffset(expires, TimeSpan.Zero), jti);
    }

    private MintedToken Mint(KgsmIdentity identity, string kind, TimeSpan ttl, string sessionId, string audience)
    {
        // A fresh jti per mint. For a refresh token this is the reuse-detection key the registry
        // stores; for an access token it is informational, and both get one so every token is
        // uniquely identifiable without a per-kind code path.
        string jti = Guid.NewGuid().ToString("N");

        List<Claim> claims =
        [
            new("sub", identity.Handle),
            new(KgsmAuthClaims.Host, audience),
            new(KgsmAuthClaims.TokenKind, kind),
            new(KgsmAuthClaims.SessionId, sessionId),
            new(KgsmAuthClaims.Jti, jti),
            new(KgsmAuthClaims.Username, identity.Username),
            new(KgsmAuthClaims.Display, identity.Display),
            new("scope", string.Join(' ', identity.Scopes)),
        ];
        if (identity.AvatarUrl is not null)
            claims.Add(new Claim(KgsmAuthClaims.Avatar, identity.AvatarUrl));

        DateTime expires = DateTime.UtcNow.Add(ttl);
        string token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(claims),
            Expires = expires,
            IssuedAt = DateTime.UtcNow,
            SigningCredentials = _signing,
        });

        return new MintedToken(token, new DateTimeOffset(expires, TimeSpan.Zero), jti);
    }

    public async Task<RefreshClaims?> ReadRefreshAsync(string token)
    {
        TokenValidationResult result = await _handler.ValidateTokenAsync(token, _refreshValidation);
        if (!result.IsValid || result.ClaimsIdentity is null)
            return null;

        ClaimsIdentity ci = result.ClaimsIdentity;

        // An access token presented here would otherwise buy a refresh, turning the short-lived
        // bearer into an unbounded one.
        if (ci.FindFirst(KgsmAuthClaims.TokenKind)?.Value != KgsmTokenKind.Refresh)
            return null;

        KgsmIdentity? identity = SessionClaims.ReadIdentity(ci);
        if (identity is null)
            return null;

        // A token carrying no session is one no registry can revoke. Refuse rather than treat it as
        // a session that happens to have no name.
        string? sid = SessionClaims.ReadSessionId(ci);
        string? jti = SessionClaims.ReadJti(ci);
        if (sid is null || jti is null)
            return null;

        return new RefreshClaims(identity, sid, jti)
        {
            Audience = result.SecurityToken is JsonWebToken jwt ? jwt.Audiences.FirstOrDefault() : null,
        };
    }
}
