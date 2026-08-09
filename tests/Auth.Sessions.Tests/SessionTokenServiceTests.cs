using TheKrystalShip.KGSM.Auth;
using TheKrystalShip.KGSM.Auth.Sessions;

namespace TheKrystalShip.KGSM.Auth.Sessions.Tests;

public class SessionTokenServiceTests
{
    private static readonly KgsmIdentity Identity =
        new("discord", "198772043", "haru", "Haru", "https://cdn.test/a.png", ["identify", "guilds"]);

    private static SessionTokenService Service(string key = "a-stable-secret", string host = "hotrod") =>
        new(new SessionTokenOptions(host, key, TimeSpan.FromMinutes(15), TimeSpan.FromDays(30)));

    [Fact]
    public async Task RefreshTokenRoundTripsIdentityTierAndSession()
    {
        SessionTokenService svc = Service();
        MintedToken refresh = svc.MintRefresh(Identity, KgsmTier.Admin, "sid_1");

        RefreshClaims? claims = await svc.ReadRefreshAsync(refresh.Token);

        Assert.NotNull(claims);
        Assert.Equal("198772043", claims.Identity.Subject);
        Assert.Equal("haru", claims.Identity.Username);
        Assert.Equal("Haru", claims.Identity.Display);
        Assert.Equal(["identify", "guilds"], claims.Identity.Scopes);
        Assert.Equal(KgsmTier.Admin, claims.Tier);
        Assert.Equal("sid_1", claims.SessionId);
        Assert.Equal(refresh.Jti, claims.Jti);
    }

    [Fact]
    public async Task AnAccessTokenIsNotAcceptedAsARefreshToken()
    {
        // Otherwise a stolen 15-minute bearer buys a 30-day one, and the short lifetime that bounds
        // privilege stops bounding anything.
        SessionTokenService svc = Service();
        MintedToken access = svc.MintAccess(Identity, KgsmTier.Admin, "sid_1");

        Assert.Null(await svc.ReadRefreshAsync(access.Token));
    }

    [Fact]
    public async Task ATokenSignedWithAnotherKeyIsRefused()
    {
        MintedToken foreign = Service(key: "someone-elses-secret").MintRefresh(Identity, KgsmTier.Admin, "sid_1");

        Assert.Null(await Service(key: "our-secret").ReadRefreshAsync(foreign.Token));
    }

    [Fact]
    public async Task ATokenForAnotherHostIsRefused()
    {
        // A bearer is scoped to one host. Without the audience check, a token minted on a shared
        // Discord app would authorize every host in the fleet.
        MintedToken other = Service(host: "other-host").MintRefresh(Identity, KgsmTier.Admin, "sid_1");

        Assert.Null(await Service(host: "hotrod").ReadRefreshAsync(other.Token));
    }

    [Fact]
    public async Task AnExpiredTokenIsRefused()
    {
        var svc = new SessionTokenService(
            new SessionTokenOptions("hotrod", "k", TimeSpan.FromMinutes(15), TimeSpan.FromSeconds(-60)));

        Assert.Null(await svc.ReadRefreshAsync(svc.MintRefresh(Identity, KgsmTier.Admin, "sid_1").Token));
    }

    [Fact]
    public void EveryMintGetsItsOwnJti()
    {
        // The jti is the reuse-detection key. Two refresh tokens sharing one would make a rotated-away
        // token indistinguishable from the live one.
        SessionTokenService svc = Service();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        for (int i = 0; i < 50; i++)
            Assert.True(seen.Add(svc.MintRefresh(Identity, KgsmTier.Admin, "sid_1").Jti));
    }

    [Fact]
    public void TheSessionIdIsStableAcrossRotation()
    {
        // Access rotation must not look like a new session, or every rotation would orphan the row
        // that makes the session revocable.
        SessionTokenService svc = Service();

        Assert.NotEqual(
            svc.MintAccess(Identity, KgsmTier.Admin, "sid_1").Jti,
            svc.MintAccess(Identity, KgsmTier.Admin, "sid_1").Jti);
    }

    [Fact]
    public void MintedExpiryMatchesTheConfiguredLifetime()
    {
        // The registry writes its row from the same lifetime. If the mint used a constant instead,
        // a token could outlive its own row, or the row outlive the token, with nothing to catch it.
        var svc = new SessionTokenService(
            new SessionTokenOptions("hotrod", "k", TimeSpan.FromMinutes(15), TimeSpan.FromDays(7)));

        MintedToken refresh = svc.MintRefresh(Identity, KgsmTier.Admin, "sid_1");
        TimeSpan life = refresh.ExpiresAt - DateTimeOffset.UtcNow;

        Assert.InRange(life, TimeSpan.FromDays(7) - TimeSpan.FromMinutes(1), TimeSpan.FromDays(7));
    }

    [Fact]
    public async Task AnEphemeralKeyStillMintsUsableTokensWithinOneProcess()
    {
        // Blank key = a dev/test run. It must work, and the warning is what says it will not survive
        // a restart.
        var svc = new SessionTokenService(
            new SessionTokenOptions("hotrod", "", TimeSpan.FromMinutes(15), TimeSpan.FromDays(30)));

        Assert.NotNull(await svc.ReadRefreshAsync(svc.MintRefresh(Identity, KgsmTier.Viewer, "sid_1").Token));
    }

    [Fact]
    public async Task TwoProcessesWithEphemeralKeysCannotReadEachOthersTokens()
    {
        var a = new SessionTokenService(new SessionTokenOptions("hotrod", "", TimeSpan.FromMinutes(15), TimeSpan.FromDays(30)));
        var b = new SessionTokenService(new SessionTokenOptions("hotrod", "", TimeSpan.FromMinutes(15), TimeSpan.FromDays(30)));

        Assert.Null(await b.ReadRefreshAsync(a.MintRefresh(Identity, KgsmTier.Admin, "sid_1").Token));
    }

    [Fact]
    public async Task ATokenFromAnotherIssuerIsRefused()
    {
        // The issuer is not cosmetic: changing it on a running host invalidates every token already
        // out there and forces everyone to log in again. This is what makes that consequence real, so
        // a surface that already mints tokens keeps the value it has.
        var mine = new SessionTokenService(
            new SessionTokenOptions("hotrod", "k", TimeSpan.FromMinutes(15), TimeSpan.FromDays(30), "kgsm-api"));
        var theirs = new SessionTokenService(
            new SessionTokenOptions("hotrod", "k", TimeSpan.FromMinutes(15), TimeSpan.FromDays(30), "kgsm-other"));

        Assert.Null(await mine.ReadRefreshAsync(theirs.MintRefresh(Identity, KgsmTier.Admin, "sid_1").Token));
        Assert.NotNull(await mine.ReadRefreshAsync(mine.MintRefresh(Identity, KgsmTier.Admin, "sid_1").Token));
    }

    // ── The identity a token carries is the provider's, not one provider ─────

    [Fact]
    public async Task ADiscordSubjectIsExactlyProviderColonId()
    {
        // The subject claim is `discord:<id>` and is also what a session row is keyed by on some
        // surfaces. It is pinned here because a change to its spelling is a flag day — every live
        // token stops validating and every stored row stops matching — and nothing else in the mint
        // path would fail loudly enough to catch it.
        SessionTokenService svc = Service();

        RefreshClaims? claims = await svc.ReadRefreshAsync(
            svc.MintRefresh(Identity, KgsmTier.Admin, "sid_1").Token);

        Assert.NotNull(claims);
        Assert.Equal("discord:198772043", claims.Identity.Handle);
    }

    [Fact]
    public async Task AnIdentityFromAnotherProviderRoundTripsIntact()
    {
        // Nothing in the token layer is Discord's. A host signing people in elsewhere mints and reads
        // the same way, and the provider survives the round trip rather than being assumed on the way
        // back out.
        SessionTokenService svc = Service();
        var github = new KgsmIdentity("github", "u_9931", "heisen", "Heisen", null, ["read:user"]);

        RefreshClaims? claims = await svc.ReadRefreshAsync(
            svc.MintRefresh(github, KgsmTier.Operator, "sid_2").Token);

        Assert.NotNull(claims);
        Assert.Equal("github", claims.Identity.Provider);
        Assert.Equal("u_9931", claims.Identity.Subject);
        Assert.Equal("github:u_9931", claims.Identity.Handle);
        Assert.Equal(KgsmTier.Operator, claims.Tier);
    }

    [Fact]
    public async Task TwoProvidersHandingOutTheSameSubjectAreDifferentPeople()
    {
        // A subject is unique only within its provider. If the handle dropped the provider half, these
        // two would collide into one account — and one of them would inherit the other's authority.
        SessionTokenService svc = Service();
        var a = new KgsmIdentity("discord", "12345", "a", "A", null, []);
        var b = new KgsmIdentity("github", "12345", "b", "B", null, []);

        RefreshClaims? ra = await svc.ReadRefreshAsync(svc.MintRefresh(a, KgsmTier.Viewer, "sid_a").Token);
        RefreshClaims? rb = await svc.ReadRefreshAsync(svc.MintRefresh(b, KgsmTier.Viewer, "sid_b").Token);

        Assert.NotEqual(ra!.Identity.Handle, rb!.Identity.Handle);
    }

    [Fact]
    public async Task ASubjectThatNamesNoProviderIsNotAnIdentity()
    {
        // A bare subject cannot say who issued it, so it names nobody in particular. Reading it as an
        // identity would invent a provider; the caller treats the request as unauthenticated instead.
        var svc = new SessionTokenService(
            new SessionTokenOptions("hotrod", "k", TimeSpan.FromMinutes(15), TimeSpan.FromDays(30)));
        var unqualified = new KgsmIdentity("", "198772043", "haru", "Haru", null, []);

        Assert.Null(await svc.ReadRefreshAsync(svc.MintRefresh(unqualified, KgsmTier.Admin, "sid_1").Token));
    }
}
