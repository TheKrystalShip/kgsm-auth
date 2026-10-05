using System.Net;
using System.Text;

namespace TheKrystalShip.Auth.Anchor.Tests;

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
            new KgsmOAuthApplication { ClientId = "cid", ClientSecret = "secret" },
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
        KgsmIdentity? identity = await Directory(Route).VerifyAsync("code", "verifier", default);

        Assert.NotNull(identity);
        Assert.Equal(KgsmActorProvider.Discord, identity.Provider);
        Assert.Equal("42", identity.Subject);
        Assert.Equal("haru", identity.Username);
        Assert.Equal("Haru", identity.Display);
        Assert.Equal("https://cdn.discordapp.com/avatars/42/abc.png", identity.AvatarUrl);
    }

    [Fact]
    public async Task BadCode_IsNull_NotAnException()
    {
        // An expired or replayed code is the caller's problem: 401, start again. Throwing would report
        // it as an upstream outage.
        KgsmIdentity? identity = await Directory(r =>
                r.RequestUri!.AbsolutePath == "/api/oauth2/token"
                    ? new HttpResponseMessage(HttpStatusCode.BadRequest)
                    : Route(r))
            .VerifyAsync("stale-code", "verifier", default);

        Assert.Null(identity);
    }

    [Fact]
    public async Task TokenEndpointServerError_Throws()
    {
        await Assert.ThrowsAsync<DiscordAuthException>(() =>
            Directory(r => r.RequestUri!.AbsolutePath == "/api/oauth2/token"
                    ? new HttpResponseMessage(HttpStatusCode.BadGateway)
                    : Route(r))
                .VerifyAsync("code", "verifier", default));
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

        await directory.VerifyAsync("code", "the-verifier", default);

        Assert.NotNull(sent);
        Assert.Contains("code_verifier=the-verifier", sent);
    }

    [Fact]
    public async Task TheCallersTokenBuysExactlyOneThing()
    {
        // The user token is presented to users/@me and then dropped. Nothing else is asked with it and
        // nothing is stored, so a login leaves the anchor holding no credential at Discord at all.
        string? meAuth = null;
        DiscordDirectory directory = Directory(r =>
        {
            if (r.RequestUri!.AbsolutePath == "/api/users/@me")
                meAuth = r.Headers.Authorization?.ToString();
            return Route(r);
        });

        await directory.VerifyAsync("code", "verifier", default);

        Assert.Equal("Bearer user-token", meAuth);
    }

    // ── Who a token belongs to, for an exchange ──────────────────────────────

    private static Task<DiscordAuthorization?> Authorization(Func<HttpRequestMessage, HttpResponseMessage> respond) =>
        DiscordDirectory.ReadAuthorizationAsync(new HttpClient(new StubHandler(respond)), "activity-token", default);

    [Fact]
    public async Task A_token_names_its_application_its_user_and_its_expiry()
    {
        string? asked = null;
        DiscordAuthorization? authorization = await Authorization(r =>
        {
            asked = $"{r.RequestUri!.AbsolutePath} {r.Headers.Authorization}";
            return Json(HttpStatusCode.OK, """
                {"application":{"id":"777","name":"Activity"},"scopes":["identify"],
                 "expires":"2026-10-12T10:00:00.000000+00:00",
                 "user":{"id":"42","username":"haru","global_name":"Haru","avatar":"abc"}}
                """);
        });

        Assert.Equal("/api/oauth2/@me Bearer activity-token", asked);
        Assert.NotNull(authorization);
        Assert.Equal("777", authorization.ApplicationId);
        Assert.Equal("discord:42", authorization.Identity.Handle);
        Assert.Equal("Haru", authorization.Identity.Display);
        Assert.Equal(new DateTimeOffset(2026, 10, 12, 10, 0, 0, TimeSpan.Zero), authorization.Expires);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task A_token_Discord_refuses_is_null(HttpStatusCode status) =>
        Assert.Null(await Authorization(_ => Json(status, """{"message":"401: Unauthorized"}""")));

    [Fact]
    public async Task A_token_without_identify_names_nobody_and_is_null() =>
        Assert.Null(await Authorization(_ => Json(HttpStatusCode.OK,
            """{"application":{"id":"777"},"scopes":["guilds"],"expires":"2026-10-12T10:00:00+00:00"}""")));

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    public async Task A_rate_limit_or_an_outage_throws(HttpStatusCode status) =>
        await Assert.ThrowsAsync<DiscordAuthException>(() => Authorization(_ => Json(status, "{}")));

    [Fact]
    public async Task An_unreadable_answer_throws() =>
        await Assert.ThrowsAsync<DiscordAuthException>(() => Authorization(_ => Json(HttpStatusCode.OK, "not json")));
}
