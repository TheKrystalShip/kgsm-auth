using System.Net;
using System.Text;

using TheKrystalShip.KGSM.Auth;
using TheKrystalShip.KGSM.Auth.Discord;

namespace TheKrystalShip.KGSM.Auth.Discord.Tests;

/// <summary>
/// A whole login through the Discord provider. The directory answers one half — who someone is — and
/// the second argument answers the other, which in production is the KGSM account store. A guild role
/// is not in this picture anywhere: composing an identity provider with an authority that knows
/// nothing about Discord is the real wiring.
/// </summary>
internal static class DiscordSignIn
{
    private sealed class FixedAuthority(KgsmTier tier) : IAuthorityProvider
    {
        public Task<KgsmTier> ResolveTierAsync(KgsmIdentity identity, CancellationToken ct) =>
            Task.FromResult(tier);
    }

    public static SignInService SignIn(this DiscordDirectory directory, KgsmTier tier = KgsmTier.Viewer) =>
        new(directory, new FixedAuthority(tier));
}

/// <summary>
/// The failure contract. Every branch here decides whether someone gets in during an outage, so each
/// is pinned against a stubbed transport rather than trusted to the implementation's shape.
/// </summary>
public class DiscordDirectoryTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(respond(request));
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static DiscordDirectory Directory(Func<HttpRequestMessage, HttpResponseMessage> respond) =>
        new(new HttpClient(new StubHandler(respond)),
            new KgsmAuthOptions { ClientId = "cid", ClientSecret = "secret" },
            new DiscordOAuthEndpoints("https://host.test/callback"));

    // ── The authorize URL ────────────────────────────────────────────────────

    [Fact]
    public void AuthorizeUrlCarriesPkceAndState()
    {
        string url = Directory(_ => new HttpResponseMessage())
            .BuildAuthorizeUrl("the-state", "the-challenge", "none");

        Assert.Contains("code_challenge=the-challenge", url);
        Assert.Contains("code_challenge_method=S256", url);
        Assert.Contains("state=the-state", url);
        Assert.Contains("client_id=cid", url);
        // The verifier is the one thing that must never reach a URL.
        Assert.DoesNotContain("code_verifier", url);
    }

    [Theory]
    [InlineData("consent", "prompt=consent")]
    [InlineData("none", "prompt=none")]
    [InlineData("anything-else", "prompt=none")]
    public void PromptIsConstrainedToWhatDiscordAccepts(string prompt, string expected) =>
        Assert.Contains(expected, Directory(_ => new HttpResponseMessage())
            .BuildAuthorizeUrl("s", "c", prompt));

    // ── The full resolve ─────────────────────────────────────────────────────

    private static HttpResponseMessage Route(HttpRequestMessage req) =>
        req.RequestUri!.AbsolutePath switch
        {
            "/api/oauth2/token" => Json(HttpStatusCode.OK, """{"access_token":"user-token"}"""),
            _ => Json(HttpStatusCode.OK,
                """{"id":"42","username":"haru","global_name":"Haru","avatar":"abc"}"""),
        };

    [Fact]
    public async Task ResolvesTheIdentity()
    {
        ResolvedPrincipal? principal = await Directory(Route)
            .SignIn(KgsmTier.Operator).ResolveAsync("code", "verifier", default);

        Assert.NotNull(principal);
        Assert.Equal("42", principal.Identity.Subject);
        Assert.Equal("haru", principal.Identity.Username);
        Assert.Equal("Haru", principal.Identity.Display);
        Assert.Equal("https://cdn.discordapp.com/avatars/42/abc.png", principal.Identity.AvatarUrl);
        Assert.Equal(KgsmTier.Operator, principal.Tier);
    }

    [Fact]
    public async Task TheTierComesFromTheAuthority_NeverFromDiscord()
    {
        // Nothing Discord answers moves this. The directory asks discord.com exactly one question —
        // who is holding this code — and the tier is decided by a seam that never heard of a guild.
        ResolvedPrincipal? principal = await Directory(Route)
            .SignIn(KgsmTier.None).ResolveAsync("code", "verifier", default);

        Assert.NotNull(principal);
        Assert.Equal("42", principal.Identity.Subject);
        Assert.Equal(KgsmTier.None, principal.Tier);
    }

    [Fact]
    public async Task BadCode_IsNull_NotAnException()
    {
        // An expired or replayed code is the caller's problem: 401, start again. Throwing would report
        // it as an upstream outage.
        ResolvedPrincipal? principal = await Directory(r =>
                r.RequestUri!.AbsolutePath == "/api/oauth2/token"
                    ? new HttpResponseMessage(HttpStatusCode.BadRequest)
                    : Route(r))
            .SignIn().ResolveAsync("stale-code", "verifier", default);

        Assert.Null(principal);
    }

    [Fact]
    public async Task TokenEndpointServerError_Throws()
    {
        await Assert.ThrowsAsync<DiscordAuthException>(() =>
            Directory(r => r.RequestUri!.AbsolutePath == "/api/oauth2/token"
                    ? new HttpResponseMessage(HttpStatusCode.BadGateway)
                    : Route(r))
                .SignIn().ResolveAsync("code", "verifier", default));
    }

    [Fact]
    public async Task TheVerifierIsSentAtTheExchange()
    {
        string? sent = null;
        DiscordDirectory directory = Directory(r =>
        {
            if (r.RequestUri!.AbsolutePath == "/api/oauth2/token")
                sent = r.Content!.ReadAsStringAsync().Result;
            return Route(r);
        });

        await directory.SignIn().ResolveAsync("code", "the-verifier", default);

        Assert.NotNull(sent);
        Assert.Contains("code_verifier=the-verifier", sent);
    }

    [Fact]
    public async Task TheCallersTokenBuysExactlyOneThing()
    {
        // The user token is presented to users/@me and then dropped. Nothing else is asked with it and
        // nothing is stored, so a login leaves this host holding no credential at Discord at all.
        string? meAuth = null;
        DiscordDirectory directory = Directory(r =>
        {
            if (r.RequestUri!.AbsolutePath == "/api/users/@me")
                meAuth = r.Headers.Authorization?.ToString();
            return Route(r);
        });

        await directory.SignIn().ResolveAsync("code", "verifier", default);

        Assert.Equal("Bearer user-token", meAuth);
    }
}
