using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace TheKrystalShip.KGSM.Auth.Sessions.Tests;

/// <summary>
/// One door, two kinds of session: the ones a member mints for itself, and the ones its cluster's
/// auth anchor mints for everybody.
/// </summary>
/// <remarks>
/// The pairing of the algorithm to the audience and the issuer is the whole of what is under test.
/// Every combination the cluster does not mint has to be refused whether or not anything currently
/// produces it, because "nobody makes that today" is not a property anybody can rely on tomorrow.
/// </remarks>
public sealed class ClusterSessionValidationTests
{
    private const string HostId = "hotrod";
    private const string ClusterId = "kgsm-cluster";
    private const string LocalSecret = "a-host-secret-of-no-particular-length";

    private static KgsmIdentity Identity() => new("local", "usr_abc", "haru", "Haru", null, []);

    private static SessionTokenOptions Options(string audience) => new(
        HostId: audience,
        SigningKey: "",
        AccessLifetime: TimeSpan.FromMinutes(15),
        RefreshLifetime: TimeSpan.FromDays(30),
        Issuer: "kgsm");

    /// <summary>This member's own token service — symmetric, audienced to itself.</summary>
    private static SessionTokenService Local() =>
        new(Options(HostId) with { SigningKey = LocalSecret });

    /// <summary>The anchor's — asymmetric, audienced to the cluster.</summary>
    private static SessionTokenService Anchor(EcdsaSessionSigner signer, string audience = ClusterId) =>
        new(Options(audience), logger: null, signer: signer);

    private static TokenValidationParameters Combined(IClusterSessionKeys cluster) =>
        ClusterSessionValidation.Accepting(Local().ValidationParameters, cluster);

    private static async Task<TokenValidationResult> Validate(
        string token, IClusterSessionKeys cluster) =>
        await new JsonWebTokenHandler().ValidateTokenAsync(token, Combined(cluster));

    /// <summary>What a member has been told, held still.</summary>
    private sealed record Known(string? Audience, string? Issuer, IReadOnlyList<SecurityKey> Keys)
        : IClusterSessionKeys
    {
        public static Known Nothing => new(null, null, []);

        public static Known Of(string audience, params EcdsaSessionSigner[] signers) =>
            new(audience, "kgsm",
                [.. signers.SelectMany(s => EcdsaSessionSigner.VerificationKeysFrom(s.PublicKeys))]);
    }

    // ── The two kinds, both accepted ─────────────────────────────────────────

    [Fact]
    public async Task A_session_the_anchor_minted_is_accepted()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await Validate(minted.Token, Known.Of(ClusterId, signer));

        Assert.True(result.IsValid);
        Assert.Equal("local:usr_abc", result.ClaimsIdentity!.FindFirst("sub")!.Value);
    }

    [Fact]
    public async Task A_session_this_member_minted_is_still_accepted()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Local().MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await Validate(minted.Token, Known.Of(ClusterId, signer));

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task A_member_that_knows_of_no_anchor_still_accepts_its_own()
    {
        MintedToken minted = Local().MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        Assert.True((await Validate(minted.Token, Known.Nothing)).IsValid);
    }

    // ── Fail-closed while nothing is known ───────────────────────────────────

    [Fact]
    public async Task A_cluster_session_is_refused_while_no_key_has_been_published()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        Assert.False((await Validate(minted.Token, Known.Nothing)).IsValid);
    }

    [Fact]
    public async Task A_cluster_session_is_refused_while_no_audience_has_been_stated()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        // Keys and no audience is a half-heard anchor. Guessing the audience would accept a session
        // minted for a different cluster entirely.
        var half = new Known(null, "kgsm", EcdsaSessionSigner.VerificationKeysFrom(signer.PublicKeys));

        Assert.False((await Validate(minted.Token, half)).IsValid);
    }

    [Fact]
    public async Task A_cluster_session_is_refused_while_no_issuer_has_been_stated()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        var half = new Known(ClusterId, null, EcdsaSessionSigner.VerificationKeysFrom(signer.PublicKeys));

        Assert.False((await Validate(minted.Token, half)).IsValid);
    }

    /// <summary>
    /// The two surfaces genuinely stamp different issuers, so this is the ordinary case rather than a
    /// contrived one — and validating both against a single value refuses whichever it is not.
    /// </summary>
    [Fact]
    public async Task The_anchor_s_issuer_and_this_member_s_own_are_both_accepted_when_they_differ()
    {
        using var signer = EcdsaSessionSigner.Generate();

        var member = new SessionTokenService(
            Options(HostId) with { SigningKey = LocalSecret, Issuer = "kgsm-api" });
        var anchor = new SessionTokenService(
            Options(ClusterId) with { Issuer = "kgsm" }, logger: null, signer: signer);

        var known = new Known(ClusterId, "kgsm", EcdsaSessionSigner.VerificationKeysFrom(signer.PublicKeys));
        TokenValidationParameters combined =
            ClusterSessionValidation.Accepting(member.ValidationParameters, known);

        var handler = new JsonWebTokenHandler();
        MintedToken own = member.MintAccess(Identity(), KgsmTier.Admin, "sid_1");
        MintedToken theirs = anchor.MintAccess(Identity(), KgsmTier.Admin, "sid_2");

        Assert.True((await handler.ValidateTokenAsync(own.Token, combined)).IsValid);
        Assert.True((await handler.ValidateTokenAsync(theirs.Token, combined)).IsValid);
    }

    [Fact]
    public async Task An_anchor_signature_carrying_this_member_s_issuer_is_refused()
    {
        using var signer = EcdsaSessionSigner.Generate();
        var impostor = new SessionTokenService(
            Options(ClusterId) with { Issuer = "kgsm-api" }, logger: null, signer: signer);

        var member = new SessionTokenService(
            Options(HostId) with { SigningKey = LocalSecret, Issuer = "kgsm-api" });
        var known = new Known(ClusterId, "kgsm", EcdsaSessionSigner.VerificationKeysFrom(signer.PublicKeys));

        MintedToken minted = impostor.MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        Assert.False((await new JsonWebTokenHandler().ValidateTokenAsync(
            minted.Token, ClusterSessionValidation.Accepting(member.ValidationParameters, known))).IsValid);
    }

    [Fact]
    public async Task A_session_signed_by_a_key_nobody_published_is_refused()
    {
        using var anchor = EcdsaSessionSigner.Generate();
        using var stranger = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(stranger).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        Assert.False((await Validate(minted.Token, Known.Of(ClusterId, anchor))).IsValid);
    }

    // ── The pairing of algorithm to audience ─────────────────────────────────

    [Fact]
    public async Task An_anchor_signature_over_this_member_s_audience_is_refused()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer, audience: HostId).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        Assert.False((await Validate(minted.Token, Known.Of(ClusterId, signer))).IsValid);
    }

    [Fact]
    public async Task A_local_signature_over_the_cluster_s_audience_is_refused()
    {
        using var signer = EcdsaSessionSigner.Generate();
        var impostor = new SessionTokenService(Options(ClusterId) with { SigningKey = LocalSecret });
        MintedToken minted = impostor.MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        Assert.False((await Validate(minted.Token, Known.Of(ClusterId, signer))).IsValid);
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
            var forger = new JsonWebTokenHandler();
            var key = new SymmetricSecurityKey(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
            string forged = forger.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "kgsm",
                Audience = ClusterId,
                Subject = new ClaimsIdentity([
                    new Claim("sub", "local:usr_abc"),
                    new Claim(KgsmAuthClaims.Tier, KgsmTiers.ToWire(KgsmTier.Admin)),
                ]),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
            });

            Assert.False((await Validate(forged, Known.Of(ClusterId, signer))).IsValid);
        }
    }

    [Fact]
    public async Task An_unsigned_token_is_refused()
    {
        var handler = new JsonWebTokenHandler();
        string forged = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "kgsm",
            Audience = ClusterId,
            Subject = new ClaimsIdentity([new Claim("sub", "local:usr_abc")]),
            Expires = DateTime.UtcNow.AddMinutes(15),
        });

        using var signer = EcdsaSessionSigner.Generate();
        Assert.False((await Validate(forged, Known.Of(ClusterId, signer))).IsValid);
    }

    // ── Rotation ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task During_an_overlap_both_published_keys_verify()
    {
        using var outgoing = EcdsaSessionSigner.Generate();
        using var incoming = EcdsaSessionSigner.Generate();
        Known both = Known.Of(ClusterId, outgoing, incoming);

        MintedToken old = Anchor(outgoing).MintAccess(Identity(), KgsmTier.Admin, "sid_1");
        MintedToken @new = Anchor(incoming).MintAccess(Identity(), KgsmTier.Admin, "sid_2");

        Assert.True((await Validate(old.Token, both)).IsValid);
        Assert.True((await Validate(@new.Token, both)).IsValid);
    }

    [Fact]
    public async Task A_key_dropped_from_the_published_set_stops_verifying()
    {
        using var outgoing = EcdsaSessionSigner.Generate();
        using var incoming = EcdsaSessionSigner.Generate();

        MintedToken old = Anchor(outgoing).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        Assert.True((await Validate(old.Token, Known.Of(ClusterId, outgoing, incoming))).IsValid);
        Assert.False((await Validate(old.Token, Known.Of(ClusterId, incoming))).IsValid);
    }

    // ── Telling the two apart afterwards ─────────────────────────────────────

    [Fact]
    public async Task A_validated_cluster_session_is_recognised_as_one()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await Validate(minted.Token, Known.Of(ClusterId, signer));

        Assert.True(ClusterSessionValidation.IsClusterSession(result.ClaimsIdentity!, HostId));
    }

    [Fact]
    public async Task A_validated_local_session_is_not()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Local().MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await Validate(minted.Token, Known.Of(ClusterId, signer));

        Assert.False(ClusterSessionValidation.IsClusterSession(result.ClaimsIdentity!, HostId));
    }

    // ── A surface that signs nobody in ───────────────────────────────────────

    private static async Task<TokenValidationResult> ValidateClusterOnly(
        string token, IClusterSessionKeys cluster) =>
        await new JsonWebTokenHandler().ValidateTokenAsync(token, ClusterSessionValidation.Accepting(cluster));

    [Fact]
    public async Task A_surface_that_mints_nothing_accepts_the_anchor_s_session()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await ValidateClusterOnly(minted.Token, Known.Of(ClusterId, signer));

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task A_surface_that_mints_nothing_refuses_a_symmetric_session()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Local().MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await ValidateClusterOnly(minted.Token, Known.Of(ClusterId, signer));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task A_surface_that_mints_nothing_refuses_everything_until_its_anchor_is_known()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await ValidateClusterOnly(minted.Token, Known.Nothing);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task A_surface_that_mints_nothing_refuses_another_cluster_s_session()
    {
        using var signer = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(signer, audience: "another-cluster").MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await ValidateClusterOnly(minted.Token, Known.Of(ClusterId, signer));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task A_surface_that_mints_nothing_refuses_a_key_nobody_published()
    {
        using var published = EcdsaSessionSigner.Generate();
        using var stranger = EcdsaSessionSigner.Generate();
        MintedToken minted = Anchor(stranger).MintAccess(Identity(), KgsmTier.Admin, "sid_1");

        TokenValidationResult result = await ValidateClusterOnly(minted.Token, Known.Of(ClusterId, published));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task A_surface_that_mints_nothing_refuses_the_published_key_offered_as_an_hmac_secret()
    {
        using var signer = EcdsaSessionSigner.Generate();
        Known known = Known.Of(ClusterId, signer);
        var asSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signer.PublicKeysJson));
        string forged = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "kgsm",
            Audience = ClusterId,
            Subject = new ClaimsIdentity([new Claim("sub", "local:usr_abc")]),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(asSecret, SecurityAlgorithms.HmacSha256),
        });

        TokenValidationResult result = await ValidateClusterOnly(forged, known);

        Assert.False(result.IsValid);
    }

    // ── Composition ──────────────────────────────────────────────────────────

    [Fact]
    public void A_member_signing_its_own_sessions_asymmetrically_is_refused_at_composition()
    {
        using var signer = EcdsaSessionSigner.Generate();
        var confused = new SessionTokenService(Options(HostId), logger: null, signer: signer);

        Assert.Throws<ArgumentException>(
            () => ClusterSessionValidation.Accepting(confused.ValidationParameters, Known.Nothing));
    }
}
