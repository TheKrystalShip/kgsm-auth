using System.Net;
using System.Text;

using TheKrystalShip.KGSM.Auth;
using TheKrystalShip.KGSM.Auth.Discord;

namespace TheKrystalShip.KGSM.Auth.Discord.Tests;

/// <summary>
/// The failure contract. Every branch here decides whether someone gets in during an outage, so each
/// is pinned against a stubbed transport rather than trusted to the implementation's shape.
/// </summary>
public class DiscordDirectoryTests
{
    private const string AdminRole = "1520175931828867193";
    private const string OperatorRole = "1520175983880179804";

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
            new KgsmAuthOptions { ClientId = "cid", ClientSecret = "secret", BotToken = "bot", GuildId = "g1" },
            new DiscordOAuthEndpoints("https://host.test/callback"),
            new KgsmRoleMap([AdminRole], [OperatorRole]));

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

    // ── Role lookup: the three answers that are not the same answer ──────────

    [Fact]
    public async Task NotAMember_IsNull_NotEmpty()
    {
        // 404 means no member object. Returning an empty list instead would floor a stranger at
        // viewer and hand them every read on the host.
        IReadOnlyList<string>? roles = await Directory(_ => new HttpResponseMessage(HttpStatusCode.NotFound))
            .GetGuildRolesAsync("u1", default);

        Assert.Null(roles);
    }

    [Fact]
    public async Task MemberWithNoRoles_IsEmpty_NotNull()
    {
        IReadOnlyList<string>? roles = await Directory(_ => Json(HttpStatusCode.OK, """{"roles":[]}"""))
            .GetGuildRolesAsync("u1", default);

        Assert.NotNull(roles);
        Assert.Empty(roles);
    }

    [Fact]
    public async Task RateLimited_Throws_NeverReadsAsNoRoles()
    {
        // A 429 says nothing about who this person is. Answering "no roles" would silently demote an
        // admin mid-incident; answering "member" would be worse.
        await Assert.ThrowsAsync<DiscordAuthException>(() =>
            Directory(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests))
                .GetGuildRolesAsync("u1", default));
    }

    [Fact]
    public async Task Unreachable_Throws()
    {
        await Assert.ThrowsAsync<DiscordAuthException>(() =>
            Directory(_ => throw new HttpRequestException("no route"))
                .GetGuildRolesAsync("u1", default));
    }

    [Fact]
    public async Task MalformedJson_Throws()
    {
        await Assert.ThrowsAsync<DiscordAuthException>(() =>
            Directory(_ => Json(HttpStatusCode.OK, "{not json"))
                .GetGuildRolesAsync("u1", default));
    }

    // ── The full resolve ─────────────────────────────────────────────────────

    private static HttpResponseMessage Route(HttpRequestMessage req, string rolesJson) =>
        req.RequestUri!.AbsolutePath switch
        {
            "/api/oauth2/token" => Json(HttpStatusCode.OK, """{"access_token":"user-token"}"""),
            "/api/users/@me" => Json(HttpStatusCode.OK,
                """{"id":"42","username":"haru","global_name":"Haru","avatar":"abc"}"""),
            _ => Json(HttpStatusCode.OK, rolesJson),
        };

    [Fact]
    public async Task ResolvesIdentityAndTier()
    {
        ResolvedPrincipal? principal = await Directory(r => Route(r, $$"""{"roles":["{{OperatorRole}}"]}"""))
            .ResolveAsync("code", "verifier", default);

        Assert.NotNull(principal);
        Assert.Equal("42", principal.Identity.UserId);
        Assert.Equal("haru", principal.Identity.Username);
        Assert.Equal("Haru", principal.Identity.Display);
        Assert.Equal("https://cdn.discordapp.com/avatars/42/abc.png", principal.Identity.AvatarUrl);
        Assert.Equal(KgsmTier.Operator, principal.Tier);
    }

    [Fact]
    public async Task VerifiedButNotAMember_ResolvesToNone_NotAnError()
    {
        // "We know who you are and you have no access" is a real, final answer — the caller turns it
        // into a 403, not a retry.
        ResolvedPrincipal? principal = await Directory(r =>
                r.RequestUri!.AbsolutePath.Contains("/members/")
                    ? new HttpResponseMessage(HttpStatusCode.NotFound)
                    : Route(r, "{}"))
            .ResolveAsync("code", "verifier", default);

        Assert.NotNull(principal);
        Assert.Equal("42", principal.Identity.UserId);
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
                    : Route(r, "{}"))
            .ResolveAsync("stale-code", "verifier", default);

        Assert.Null(principal);
    }

    [Fact]
    public async Task TokenEndpointServerError_Throws()
    {
        await Assert.ThrowsAsync<DiscordAuthException>(() =>
            Directory(r => r.RequestUri!.AbsolutePath == "/api/oauth2/token"
                    ? new HttpResponseMessage(HttpStatusCode.BadGateway)
                    : Route(r, "{}"))
                .ResolveAsync("code", "verifier", default));
    }

    [Fact]
    public async Task TheVerifierIsSentAtTheExchange()
    {
        string? sent = null;
        DiscordDirectory directory = Directory(r =>
        {
            if (r.RequestUri!.AbsolutePath == "/api/oauth2/token")
                sent = r.Content!.ReadAsStringAsync().Result;
            return Route(r, "{}");
        });

        await directory.ResolveAsync("code", "the-verifier", default);

        Assert.NotNull(sent);
        Assert.Contains("code_verifier=the-verifier", sent);
    }

    [Fact]
    public async Task RolesAreReadWithTheBotTokenNotTheCallersToken()
    {
        // The caller's scopes never carry roles, so a surface that asked with the user's token would
        // read an empty set and quietly floor everyone at viewer.
        string? memberAuth = null;
        DiscordDirectory directory = Directory(r =>
        {
            if (r.RequestUri!.AbsolutePath.Contains("/members/"))
                memberAuth = r.Headers.Authorization?.ToString();
            return Route(r, $$"""{"roles":["{{AdminRole}}"]}""");
        });

        await directory.ResolveAsync("code", "verifier", default);

        Assert.Equal("Bot bot", memberAuth);
    }
}
