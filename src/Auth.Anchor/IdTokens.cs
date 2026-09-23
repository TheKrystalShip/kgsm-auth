using System.Security.Claims;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>What an <c>id_token_hint</c> says, once its signature is checked.</summary>
/// <param name="ProviderSession">The provider session it was minted under.</param>
/// <param name="ClientId">The client it was issued to.</param>
internal sealed record IdTokenHint(string ProviderSession, string ClientId);

/// <summary>
/// The <c>id_token</c> every session through the provider comes with.
/// </summary>
/// <remarks>
/// <para>
/// Its subject is the account, never a credential handle. A client keys what it remembers about a person
/// by <c>sub</c>, and one account signed in with a password on Monday and with Discord on Tuesday is one
/// person to it. Its audience is the client, never the cluster, which is what keeps it from being
/// accepted anywhere as a bearer: every member requires the cluster's audience and an access token's
/// kind, and this carries neither.
/// </para>
/// <para>
/// <c>sid</c> is the provider session, the one thing sign-out needs from it: a browser that has lost the
/// cookie still names, in the hint, the sign-in to end.
/// </para>
/// </remarks>
internal sealed class IdTokens(EcdsaSessionSigner signer, AnchorOptions options)
{
    private readonly JsonWebTokenHandler _handler = new();

    /// <summary>An <c>id_token</c> for <paramref name="user"/>, issued to <paramref name="clientId"/>.</summary>
    internal string Mint(
        KgsmUser user, string clientId, string providerSession, DateTimeOffset authTime, string? nonce,
        string? picture)
    {
        List<Claim> claims =
        [
            new("sub", user.UserId),
            new("sid", providerSession),
            new("auth_time", authTime.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer64),
            new("preferred_username", user.Username),
            new("name", user.DisplayName),
        ];
        if (nonce is { Length: > 0 })
            claims.Add(new Claim("nonce", nonce));
        if (picture is { Length: > 0 })
            claims.Add(new Claim("picture", picture));

        DateTime now = DateTime.UtcNow;
        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = clientId,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now,
            NotBefore = now,
            Expires = now.Add(options.AccessLifetime),
            SigningCredentials = signer.Credentials,
        });
    }

    /// <summary>
    /// The provider session and client an <c>id_token_hint</c> names, or null when it is not one this
    /// provider signed.
    /// </summary>
    /// <remarks>
    /// Its lifetime is not checked. A hint is presented at sign-out, which is routinely long after the
    /// token it came from expired, and what it asks for — ending a sign-in — takes authority away. The
    /// signature, the issuer and the algorithm are checked, and so is the absence of an access token's
    /// kind, so a bearer cannot be passed off as one.
    /// </remarks>
    internal async Task<IdTokenHint?> ReadHintAsync(string? hint)
    {
        if (string.IsNullOrWhiteSpace(hint))
            return null;

        TokenValidationResult result = await _handler.ValidateTokenAsync(hint, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = options.Issuer,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signer.VerificationKey,
            ValidAlgorithms = [signer.Algorithm],
        }).ConfigureAwait(false);

        if (!result.IsValid || result.ClaimsIdentity is not { } claims)
            return null;

        if (claims.FindFirst(KgsmAuthClaims.TokenKind) is not null)
            return null;

        string? sid = claims.FindFirst("sid")?.Value;
        string? audience = result.SecurityToken is JsonWebToken jwt ? jwt.Audiences.FirstOrDefault() : null;
        return sid is { Length: > 0 } && audience is { Length: > 0 } ? new IdTokenHint(sid, audience) : null;
    }
}
