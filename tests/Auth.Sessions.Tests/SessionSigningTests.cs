using System.Security.Claims;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace TheKrystalShip.KGSM.Auth.Sessions.Tests;

/// <summary>
/// Asymmetric session signing: what a holder mints, anybody with the published key can check, and
/// nobody with only that key can produce.
/// </summary>
public sealed class SessionSigningTests
{
    private static SessionTokenOptions Options(string audience = "cluster") => new(
        HostId: audience,
        SigningKey: "",
        AccessLifetime: TimeSpan.FromMinutes(15),
        RefreshLifetime: TimeSpan.FromDays(30),
        Issuer: "kgsm");

    private static KgsmIdentity Identity() =>
        new("local", "usr_abc", "haru", "Haru", null, []);

    [Fact]
    public async Task A_token_it_signs_verifies_against_its_published_public_key()
    {
        using var signer = EcdsaSessionSigner.Generate();
        var service = new SessionTokenService(Options(), logger: null, signer: signer);

        MintedToken minted = service.MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        // The published document, and nothing else, is what a verifier is given.
        SessionJwks? published = EcdsaSessionSigner.ReadKeys(signer.PublicKeysJson);
        Assert.NotNull(published);
        IReadOnlyList<ECDsaSecurityKey> keys = EcdsaSessionSigner.VerificationKeysFrom(published);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "kgsm",
            ValidateAudience = true,
            ValidAudience = "cluster",
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = keys,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidateLifetime = true,
        };

        TokenValidationResult result =
            await new JsonWebTokenHandler().ValidateTokenAsync(minted.Token, parameters);

        Assert.True(result.IsValid);
        Assert.Equal("local:usr_abc", result.ClaimsIdentity!.FindFirst("sub")!.Value);
        Assert.Equal(KgsmTier.Admin, SessionClaims.ReadTier(result.ClaimsIdentity));
    }

    [Fact]
    public void The_published_key_cannot_mint()
    {
        using var signer = EcdsaSessionSigner.Generate();
        ECDsaSecurityKey verification = EcdsaSessionSigner.VerificationKeyFrom(signer.PublicKey);

        // Signing needs the private half. What is published carries only the public point, so a
        // member holding it can check a session and cannot issue itself one.
        Assert.False(verification.PrivateKeyStatus == PrivateKeyStatus.Exists);
    }

    [Fact]
    public async Task A_token_signed_by_another_key_is_refused()
    {
        using var mine = EcdsaSessionSigner.Generate();
        using var theirs = EcdsaSessionSigner.Generate();

        var impostor = new SessionTokenService(Options(), logger: null, signer: theirs);
        MintedToken forged = impostor.MintRefresh(Identity(), KgsmTier.Admin, "sid_1");

        var service = new SessionTokenService(Options(), logger: null, signer: mine);
        Assert.Null(await service.ReadRefreshAsync(forged.Token));
    }

    [Fact]
    public async Task A_key_survives_a_pem_round_trip_with_the_same_id()
    {
        using var original = EcdsaSessionSigner.Generate();
        string pem = original.ExportPrivatePem();

        using var reloaded = EcdsaSessionSigner.FromPem(pem);

        // The id is the key's own thumbprint, so a reload cannot quietly become a different key.
        Assert.Equal(original.PublicKey.Kid, reloaded.PublicKey.Kid);
        Assert.Equal(original.PublicKey.X, reloaded.PublicKey.X);
        Assert.Equal(original.PublicKey.Y, reloaded.PublicKey.Y);

        // And a session minted before the reload is still valid after it.
        MintedToken minted = new SessionTokenService(Options(), logger: null, signer: original)
            .MintRefresh(Identity(), KgsmTier.Operator, "sid_1");

        RefreshClaims? read = await new SessionTokenService(Options(), logger: null, signer: reloaded)
            .ReadRefreshAsync(minted.Token);

        Assert.NotNull(read);
        Assert.Equal("sid_1", read.SessionId);
        Assert.Equal(KgsmTier.Operator, read.Tier);
    }

    [Fact]
    public void An_unreadable_pem_throws_rather_than_producing_a_new_key()
    {
        Assert.ThrowsAny<Exception>(() => EcdsaSessionSigner.FromPem("not a key"));
    }

    [Fact]
    public void The_key_id_is_the_rfc7638_thumbprint_of_the_key()
    {
        using var signer = EcdsaSessionSigner.Generate();
        SessionJwk jwk = signer.PublicKey;

        string canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{jwk.X}\",\"y\":\"{jwk.Y}\"}}";
        string expected = System.Buffers.Text.Base64Url.EncodeToString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical)));

        Assert.Equal(expected, jwk.Kid);
    }

    [Fact]
    public async Task An_hmac_surface_is_unchanged_when_no_signer_is_supplied()
    {
        var service = new SessionTokenService(Options() with { SigningKey = "shared-secret" });
        MintedToken minted = service.MintRefresh(Identity(), KgsmTier.Viewer, "sid_1");

        RefreshClaims? read = await service.ReadRefreshAsync(minted.Token);
        Assert.NotNull(read);
        Assert.Equal(KgsmTier.Viewer, read.Tier);
    }
}
