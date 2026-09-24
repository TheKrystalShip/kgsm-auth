using System.Security.Claims;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Cluster;

namespace TheKrystalShip.KGSM.Auth.Minting;

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
/// The tier here is what was true when the token was minted. The anchor re-reads the account before
/// it mints the next pair, so nothing is decided on it.
/// </remarks>
public sealed record RefreshClaims(KgsmIdentity Identity, KgsmTier Tier, string SessionId, string Jti);

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
public interface ISessionTokenService
{
    /// <summary>Mint a short-lived access bearer, scoped to a session.</summary>
    MintedToken MintAccess(KgsmIdentity identity, KgsmTier tier, string sessionId);

    /// <summary>Mint the refresh token for a session. Its lifetime is the absolute cap.</summary>
    MintedToken MintRefresh(KgsmIdentity identity, KgsmTier tier, string sessionId);

    /// <summary>
    /// Validate a presented refresh token. Returns <see langword="null"/> when it is invalid, expired,
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
    }

    public MintedToken MintAccess(KgsmIdentity identity, KgsmTier tier, string sessionId) =>
        Mint(identity, tier, KgsmTokenKind.Access, _options.AccessLifetime, sessionId);

    public MintedToken MintRefresh(KgsmIdentity identity, KgsmTier tier, string sessionId) =>
        Mint(identity, tier, KgsmTokenKind.Refresh, _options.RefreshLifetime, sessionId);

    private MintedToken Mint(
        KgsmIdentity identity, KgsmTier tier, string kind, TimeSpan ttl, string sessionId)
    {
        // A fresh jti per mint. For a refresh token this is the reuse-detection key the registry
        // stores; for an access token it is informational, and both get one so every token is
        // uniquely identifiable without a per-kind code path.
        string jti = Guid.NewGuid().ToString("N");

        List<Claim> claims =
        [
            new("sub", identity.Handle),
            new(KgsmAuthClaims.Tier, KgsmTiers.ToWire(tier)),
            new(KgsmAuthClaims.Host, _options.Audience),
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
            Audience = _options.Audience,
            Subject = new ClaimsIdentity(claims),
            Expires = expires,
            IssuedAt = DateTime.UtcNow,
            SigningCredentials = _signing,
        });

        return new MintedToken(token, new DateTimeOffset(expires, TimeSpan.Zero), jti);
    }

    public async Task<RefreshClaims?> ReadRefreshAsync(string token)
    {
        TokenValidationResult result = await _handler.ValidateTokenAsync(token, ValidationParameters);
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

        return new RefreshClaims(identity, SessionClaims.ReadTier(ci), sid, jti);
    }
}
