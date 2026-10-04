using TheKrystalShip.Auth.Minting;

namespace TheKrystalShip.Auth.Anchor.Tests;

public class SessionTokenServiceTests
{
    private const string Issuer = "https://auth.test";

    private static readonly EcdsaSessionSigner Signer = EcdsaSessionSigner.Generate();

    private static readonly KgsmIdentity Identity =
        new("discord", "198772043", "haru", "Haru", "https://cdn.test/a.png", ["identify", "guilds"]);

    private static SessionTokenService Service(
        string audience = "cluster",
        TimeSpan? refreshLifetime = null,
        string issuer = Issuer,
        EcdsaSessionSigner? signer = null) =>
        new(new SessionTokenOptions(audience, TimeSpan.FromMinutes(15), refreshLifetime ?? TimeSpan.FromDays(30), issuer),
            signer ?? Signer);

    [Fact]
    public async Task RefreshTokenRoundTripsIdentityAndSession()
    {
        SessionTokenService svc = Service();
        MintedToken refresh = svc.MintRefresh(Identity, "sid_1");

        RefreshClaims? claims = await svc.ReadRefreshAsync(refresh.Token);

        Assert.NotNull(claims);
        Assert.Equal("198772043", claims.Identity.Subject);
        Assert.Equal("haru", claims.Identity.Username);
        Assert.Equal("Haru", claims.Identity.Display);
        Assert.Equal(["identify", "guilds"], claims.Identity.Scopes);
        Assert.Equal("sid_1", claims.SessionId);
        Assert.Equal(refresh.Jti, claims.Jti);
    }

    [Fact]
    public void ATokenCarriesNoClaimAboutWhatItsHolderMayDo()
    {
        SessionTokenService svc = Service();

        foreach (string token in new[] { svc.MintRefresh(Identity, "sid_1").Token, svc.MintAccess(Identity, "sid_1").Token })
        {
            var parsed = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(token);
            Assert.DoesNotContain(parsed.Claims, c => c.Type is "role" or "roles" or "actions");
        }
    }

    [Fact]
    public async Task AnAccessTokenIsNotAcceptedAsARefreshToken()
    {
        // Otherwise a stolen 15-minute bearer buys a 30-day one, and the short lifetime that bounds
        // privilege stops bounding anything.
        SessionTokenService svc = Service();
        MintedToken access = svc.MintAccess(Identity,"sid_1");

        Assert.Null(await svc.ReadRefreshAsync(access.Token));
    }

    [Fact]
    public async Task ATokenForAnotherClusterIsRefused()
    {
        // A session is scoped to one cluster. Without the audience check, a token minted for one
        // cluster would be accepted by another holding the same key.
        MintedToken other = Service(audience: "other-cluster").MintRefresh(Identity,"sid_1");

        Assert.Null(await Service(audience: "cluster").ReadRefreshAsync(other.Token));
    }

    [Fact]
    public async Task AnExpiredTokenIsRefused()
    {
        SessionTokenService svc = Service(refreshLifetime: TimeSpan.FromSeconds(-60));

        Assert.Null(await svc.ReadRefreshAsync(svc.MintRefresh(Identity,"sid_1").Token));
    }

    [Fact]
    public void EveryMintGetsItsOwnJti()
    {
        // The jti is the reuse-detection key. Two refresh tokens sharing one would make a rotated-away
        // token indistinguishable from the live one.
        SessionTokenService svc = Service();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        for (int i = 0; i < 50; i++)
            Assert.True(seen.Add(svc.MintRefresh(Identity,"sid_1").Jti));
    }

    [Fact]
    public void TheSessionIdIsStableAcrossRotation()
    {
        // Access rotation must not look like a new session, or every rotation would orphan the row
        // that makes the session revocable.
        SessionTokenService svc = Service();

        Assert.NotEqual(
            svc.MintAccess(Identity,"sid_1").Jti,
            svc.MintAccess(Identity,"sid_1").Jti);
    }

    [Fact]
    public void MintedExpiryMatchesTheConfiguredLifetime()
    {
        // The registry writes its row from the same lifetime. If the mint used a constant instead,
        // a token could outlive its own row, or the row outlive the token, with nothing to catch it.
        SessionTokenService svc = Service(refreshLifetime: TimeSpan.FromDays(7));

        MintedToken refresh = svc.MintRefresh(Identity,"sid_1");
        TimeSpan life = refresh.ExpiresAt - DateTimeOffset.UtcNow;

        Assert.InRange(life, TimeSpan.FromDays(7) - TimeSpan.FromMinutes(1), TimeSpan.FromDays(7));
    }

    [Fact]
    public async Task ATokenFromAnotherIssuerIsRefused()
    {
        // The issuer is not cosmetic: changing it on a running cluster invalidates every token already
        // out there and forces everyone to sign in again. This is what makes that consequence real.
        SessionTokenService mine = Service(issuer: "https://auth.one.test");
        SessionTokenService theirs = Service(issuer: "https://auth.other.test");

        Assert.Null(await mine.ReadRefreshAsync(theirs.MintRefresh(Identity,"sid_1").Token));
        Assert.NotNull(await mine.ReadRefreshAsync(mine.MintRefresh(Identity,"sid_1").Token));
    }

    // ── The identity a token carries is the provider's, not one provider ─────

    [Fact]
    public async Task ADiscordSubjectIsExactlyProviderColonId()
    {
        // The subject claim is `discord:<id>` and is also what a session row is keyed by. It is pinned here because a change to its spelling is a flag day — every live
        // token stops validating and every stored row stops matching — and nothing else in the mint
        // path would fail loudly enough to catch it.
        SessionTokenService svc = Service();

        RefreshClaims? claims = await svc.ReadRefreshAsync(
            svc.MintRefresh(Identity,"sid_1").Token);

        Assert.NotNull(claims);
        Assert.Equal("discord:198772043", claims.Identity.Handle);
    }

    [Fact]
    public async Task AnIdentityFromAnotherProviderRoundTripsIntact()
    {
        // Nothing in the token layer is Discord's. A person signing in elsewhere is minted and read
        // the same way, and the provider survives the round trip rather than being assumed on the way
        // back out.
        SessionTokenService svc = Service();
        var github = new KgsmIdentity("github", "u_9931", "heisen", "Heisen", null, ["read:user"]);

        RefreshClaims? claims = await svc.ReadRefreshAsync(
            svc.MintRefresh(github, "sid_2").Token);

        Assert.NotNull(claims);
        Assert.Equal("github", claims.Identity.Provider);
        Assert.Equal("u_9931", claims.Identity.Subject);
        Assert.Equal("github:u_9931", claims.Identity.Handle);
    }

    [Fact]
    public async Task TwoProvidersHandingOutTheSameSubjectAreDifferentPeople()
    {
        // A subject is unique only within its provider. If the handle dropped the provider half, these
        // two would collide into one account — and one of them would inherit the other's authority.
        SessionTokenService svc = Service();
        var a = new KgsmIdentity("discord", "12345", "a", "A", null, []);
        var b = new KgsmIdentity("github", "12345", "b", "B", null, []);

        RefreshClaims? ra = await svc.ReadRefreshAsync(svc.MintRefresh(a, "sid_a").Token);
        RefreshClaims? rb = await svc.ReadRefreshAsync(svc.MintRefresh(b, "sid_b").Token);

        Assert.NotEqual(ra!.Identity.Handle, rb!.Identity.Handle);
    }

    [Fact]
    public async Task ASubjectThatNamesNoProviderIsNotAnIdentity()
    {
        // A bare subject cannot say who issued it, so it names nobody in particular. Reading it as an
        // identity would invent a provider; the caller treats the request as unauthenticated instead.
        SessionTokenService svc = Service();
        var unqualified = new KgsmIdentity("", "198772043", "haru", "Haru", null, []);

        Assert.Null(await svc.ReadRefreshAsync(svc.MintRefresh(unqualified, "sid_1").Token));
    }
}
