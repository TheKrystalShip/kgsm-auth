using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Discord;

namespace TheKrystalShip.KGSM.Auth.Sessions;

/// <summary>A just-minted token, its absolute expiry, and the <c>jti</c> it was minted with.</summary>
/// <remarks>
/// The expiry is returned rather than left for the client to decode out of the JWT: a surface handing
/// a session to a browser should be able to say when it dies without the browser parsing a token it
/// is not supposed to interpret. The <c>jti</c> goes to the registry, where a refresh token's value
/// becomes the reuse-detection key.
/// </remarks>
public sealed record MintedToken(string Token, DateTimeOffset ExpiresAt, string Jti);

/// <summary>
/// What a valid refresh token yields: enough to re-mint an access token with no Discord round-trip.
/// </summary>
/// <remarks>
/// The tier comes off the token rather than being re-resolved, so a role change takes effect at the
/// next full login rather than the next refresh. That is a deliberate cost of not calling Discord on
/// every rotation; a surface that needs faster propagation re-derives the tier itself.
/// </remarks>
public sealed record RefreshClaims(DiscordIdentity Identity, KgsmTier Tier, string SessionId, string Jti);

/// <summary>How this surface mints session tokens.</summary>
/// <param name="HostId">The token audience — a bearer is scoped to one host and useless on another.</param>
/// <param name="SigningKey">
/// The HMAC secret, of any length (it is hashed to 256 bits). Blank generates an ephemeral
/// per-process key: every token dies on restart, which is fine for a test and never for a real host.
/// </param>
/// <param name="AccessLifetime">How long an access bearer lives. Short — it bounds privilege.</param>
/// <param name="RefreshLifetime">
/// The absolute session cap: how long someone stays signed in, rotating access tokens, before a fresh
/// login. <b>The registry's expiry must be written from this same value</b>, which is why it is a
/// setting and not a constant — two copies of one lifetime drift, and the drift is invisible until a
/// token outlives its own row or the reverse.
/// </param>
/// <param name="Issuer">
/// The <c>iss</c> claim, and what validation requires. <b>Changing it on a running host invalidates
/// every token already issued</b>, forcing every signed-in person to log in again — so a surface that
/// already mints tokens keeps the value it has always used rather than adopting a tidier one.
/// </param>
public sealed record SessionTokenOptions(
    string HostId,
    string SigningKey,
    TimeSpan AccessLifetime,
    TimeSpan RefreshLifetime,
    string Issuer = "kgsm");

/// <summary>
/// Mints and validates the host-scoped session JWTs. An <em>access</em> token is the bearer on every
/// protected request; a <em>refresh</em> token buys a new one without going back to Discord, until
/// the absolute cap.
/// </summary>
public interface ISessionTokenService
{
    /// <summary>Mint a short-lived access bearer, scoped to a session.</summary>
    MintedToken MintAccess(DiscordIdentity identity, KgsmTier tier, string sessionId);

    /// <summary>Mint the refresh token for a session. Its lifetime is the absolute cap.</summary>
    MintedToken MintRefresh(DiscordIdentity identity, KgsmTier tier, string sessionId);

    /// <summary>
    /// Validate a presented refresh token. Returns <see langword="null"/> when it is invalid, expired,
    /// not a refresh token, or missing the <c>sid</c>/<c>jti</c> a session needs — the caller answers
    /// 401 and does not try to salvage a partial answer.
    /// </summary>
    Task<RefreshClaims?> ReadRefreshAsync(string token);

    /// <summary>
    /// The validation rules, shared with the host's bearer pipeline so access and refresh tokens
    /// validate identically. Handing these out rather than re-declaring them is what keeps the
    /// issuer, audience and key from disagreeing between the mint and the check.
    /// </summary>
    TokenValidationParameters ValidationParameters { get; }
}

/// <summary>HMAC-SHA256 session tokens.</summary>
public sealed class SessionTokenService : ISessionTokenService
{
    private readonly SessionTokenOptions _options;
    private readonly SymmetricSecurityKey _key;
    private readonly SigningCredentials _signing;
    private readonly JsonWebTokenHandler _handler = new();

    public TokenValidationParameters ValidationParameters { get; }

    public SessionTokenService(SessionTokenOptions options, ILogger<SessionTokenService>? logger = null)
    {
        _options = options;

        byte[] keyBytes;
        if (!string.IsNullOrWhiteSpace(options.SigningKey))
        {
            // Hashed, so any length of secret works and the key is always exactly 256 bits.
            keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(options.SigningKey));
        }
        else
        {
            keyBytes = RandomNumberGenerator.GetBytes(32);
            logger?.LogWarning(
                "No session signing key is configured — generated an EPHEMERAL one. Every session "
                + "dies on restart. Set a stable secret on any real host.");
        }

        _key = new SymmetricSecurityKey(keyBytes);
        _signing = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);

        ValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = options.Issuer,
            ValidateAudience = true,
            ValidAudience = options.HostId,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _key,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "sub",
        };
    }

    public MintedToken MintAccess(DiscordIdentity identity, KgsmTier tier, string sessionId) =>
        Mint(identity, tier, KgsmTokenKind.Access, _options.AccessLifetime, sessionId);

    public MintedToken MintRefresh(DiscordIdentity identity, KgsmTier tier, string sessionId) =>
        Mint(identity, tier, KgsmTokenKind.Refresh, _options.RefreshLifetime, sessionId);

    private MintedToken Mint(
        DiscordIdentity identity, KgsmTier tier, string kind, TimeSpan ttl, string sessionId)
    {
        // A fresh jti per mint. For a refresh token this is the reuse-detection key the registry
        // stores; for an access token it is informational, and both get one so every token is
        // uniquely identifiable without a per-kind code path.
        string jti = Guid.NewGuid().ToString("N");

        List<Claim> claims =
        [
            new("sub", KgsmActor.Discord(null, identity.UserId)),
            new(KgsmAuthClaims.Tier, KgsmTiers.ToWire(tier)),
            new(KgsmAuthClaims.Host, _options.HostId),
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
            Audience = _options.HostId,
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

        DiscordIdentity? identity = SessionClaims.ReadIdentity(ci);
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
