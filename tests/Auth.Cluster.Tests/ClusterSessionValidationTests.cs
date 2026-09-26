using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Minting;

namespace TheKrystalShip.KGSM.Auth.Cluster.Tests;

/// <summary>
/// One kind of session: the one its cluster's auth anchor mints, verified against what the anchor
/// publishes.
/// </summary>
/// <remarks>
/// Every token the cluster does not mint has to be refused whether or not anything currently produces
/// it, because "nobody makes that today" is not a property anybody can rely on tomorrow.
/// </remarks>
public sealed class ClusterSessionValidationTests
{
    private const string ClusterId = "kgsm-cluster";
    private const string Issuer = "https://auth.test";

    private static KgsmIdentity Identity() => new("local", "usr_abc", "haru", "Haru", null, []);

    /// <summary>The anchor's token service: asymmetric, audienced to the cluster.</summary>
    private static SessionTokenService Anchor(
        EcdsaSessionSigner signer, string audience = ClusterId, string issuer = Issuer) =>
        new(new SessionTokenOptions(audience, TimeSpan.FromMinutes(15), TimeSpan.FromDays(30), issuer), signer);

    private static async Task<TokenValidationResult> Validate(string token, IClusterSessionKeys cluster) =>
        await new JsonWebTokenHandler().ValidateTokenAsync(token, ClusterSessionValidation.Accepting(cluster));

    /// <summary>What a member has been told, held still.</summary>
    private sealed record Known(string? Audience, string? Issuer, IReadOnlyList<SecurityKey> Keys)
        : IClusterSessionKeys
    {
        public static Known Nothing => new(null, null, []);

        public static Known Of(string audience, params EcdsaSessionSigner[] signers) =>
            new(audience, ClusterSessionValidationTests.Issuer,
                [.. signers.SelectMany(s => SessionKeys.VerificationKeysFrom(s.PublicKeys))]);
    }

    private static string Forge(SigningCredentials? credentials, string audience = ClusterId) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = audience,
            Subject = new ClaimsIdentity([
                new Claim("sub", "local:usr_abc"),
            ]),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = credentials,
        });

    // ── Accepted ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_session_the_anchor_minted_is_accepted()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), "sid_1");

        TokenValidationResult result = await Validate(minted.Token, Known.Of(ClusterId, signer));

        Assert.True(result.IsValid, result.Exception?.Message);
        Assert.Equal("local:usr_abc", SessionClaims.ReadIdentity(result.ClaimsIdentity!)!.Handle);
    }

    // ── Refused until the anchor is known ────────────────────────────────────

    [Fact]
    public async Task Everything_is_refused_until_the_anchor_is_known()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), "sid_1");

        Assert.False((await Validate(minted.Token, Known.Nothing)).IsValid);
    }

    [Fact]
    public async Task A_session_is_refused_while_no_key_has_been_published()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), "sid_1");

        Assert.False((await Validate(minted.Token, new Known(ClusterId, Issuer, []))).IsValid);
    }

    [Fact]
    public async Task A_session_is_refused_while_no_audience_has_been_stated()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), "sid_1");

        var half = new Known(null, Issuer, SessionKeys.VerificationKeysFrom(signer.PublicKeys));

        Assert.False((await Validate(minted.Token, half)).IsValid);
    }

    [Fact]
    public async Task A_session_is_refused_while_no_issuer_has_been_stated()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), "sid_1");

        var half = new Known(ClusterId, null, SessionKeys.VerificationKeysFrom(signer.PublicKeys));

        Assert.False((await Validate(minted.Token, half)).IsValid);
    }

    // ── Refused: not this cluster's ──────────────────────────────────────────

    [Fact]
    public async Task A_session_signed_by_a_key_nobody_published_is_refused()
    {
        using var published = EcdsaSessionSigner.Generate();
        using var stranger = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(stranger).MintAccess(Identity(), "sid_1");

        Assert.False((await Validate(minted.Token, Known.Of(ClusterId, published))).IsValid);
    }

    [Fact]
    public async Task Another_cluster_s_session_is_refused()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer, audience: "another-cluster").MintAccess(Identity(), "sid_1");

        Assert.False((await Validate(minted.Token, Known.Of(ClusterId, signer))).IsValid);
    }

    [Fact]
    public async Task A_session_carrying_another_issuer_is_refused()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer, issuer: "https://auth.elsewhere.test")
            .MintAccess(Identity(), "sid_1");

        Assert.False((await Validate(minted.Token, Known.Of(ClusterId, signer))).IsValid);
    }

    [Fact]
    public async Task A_symmetric_session_is_refused()
    {
        using var signer = EcdsaSessionSigner.Generate();
        var secret = new SymmetricSecurityKey(SHA256.HashData(Encoding.UTF8.GetBytes("a-secret-nobody-was-told")));

        string forged = Forge(new SigningCredentials(secret, SecurityAlgorithms.HmacSha256));

        Assert.False((await Validate(forged, Known.Of(ClusterId, signer))).IsValid);
    }

    /// <summary>
    /// The attack the algorithm pin exists for: the published key is a value every member holds, so a
    /// verifier that would accept it as an HMAC secret turns the key everybody has into the key
    /// everybody can sign with.
    /// </summary>
    [Fact]
    public async Task The_published_key_offered_as_an_hmac_secret_is_refused()
    {
        using var signer = EcdsaSessionSigner.Generate();
        SessionJwk published = signer.PublicKey;

        // Anything an attacker can derive from the published document, presented as the secret.
        foreach (string material in new[] { published.X, published.Y, published.Kid, signer.PublicKeysJson })
        {
            var key = new SymmetricSecurityKey(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
            string forged = Forge(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

            Assert.False((await Validate(forged, Known.Of(ClusterId, signer))).IsValid);
        }
    }

    [Fact]
    public async Task An_unsigned_token_is_refused()
    {
        using var signer = EcdsaSessionSigner.Generate();

        Assert.False((await Validate(Forge(credentials: null), Known.Of(ClusterId, signer))).IsValid);
    }

    // ── Rotation ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task During_an_overlap_both_published_keys_verify()
    {
        using var outgoing = EcdsaSessionSigner.Generate();
        using var incoming = EcdsaSessionSigner.Generate();
        Known both = Known.Of(ClusterId, outgoing, incoming);

        MintedToken old = Anchor(outgoing).MintAccess(Identity(), "sid_1");
        MintedToken @new = Anchor(incoming).MintAccess(Identity(), "sid_2");

        Assert.True((await Validate(old.Token, both)).IsValid);
        Assert.True((await Validate(@new.Token, both)).IsValid);
    }

    [Fact]
    public async Task A_key_dropped_from_the_published_set_stops_verifying()
    {
        using var outgoing = EcdsaSessionSigner.Generate();
        using var incoming = EcdsaSessionSigner.Generate();

        MintedToken old = Anchor(outgoing).MintAccess(Identity(), "sid_1");

        Assert.True((await Validate(old.Token, Known.Of(ClusterId, outgoing, incoming))).IsValid);
        Assert.False((await Validate(old.Token, Known.Of(ClusterId, incoming))).IsValid);
    }
}
