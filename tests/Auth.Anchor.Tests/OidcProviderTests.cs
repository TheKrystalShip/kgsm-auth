using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// The anchor as an OpenID Connect provider, driven the way a browser and a client library drive it.
/// </summary>
/// <remarks>
/// <para>
/// Each <see cref="AnchorFixture.Following"/> client is a separate browser with its own cookie jar, and
/// redirects are reported rather than followed, because what the provider decides is exactly where it
/// sends a browser. The client library's half — the verifier, the state, the exchange — is written out
/// here, so a test fails on what the provider said rather than on what a library assumed.
/// </para>
/// <para>
/// Every account is made fresh per test, because the store is shared across the collection and a
/// lockout or a disable left behind by one test would decide another.
/// </para>
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class OidcProviderTests(AnchorFixture anchor)
{
    private const string Panel = "test-panel";
    private const string PanelRedirect = "https://panel.test/callback";
    private const string PanelSignedOut = "https://panel.test/signed-out";
    private const string Chat = "test-chat";
    private const string ChatRedirect = "https://chat.test/callback";

    // ── Plumbing ──────────────────────────────────────────────────────────────

    private async Task RegisterClientsAsync()
    {
        var registry = anchor.Service<ClientRegistry>();
        if (registry.Find(Panel) is null)
        {
            await registry.RegisterAsync(
                new ClientRegistration(Panel, "Test panel", [PanelRedirect], [PanelSignedOut]),
                DateTimeOffset.UtcNow, CancellationToken.None);
        }
        if (registry.Find(Chat) is null)
        {
            await registry.RegisterAsync(
                new ClientRegistration(Chat, "Test chat", [ChatRedirect], []),
                DateTimeOffset.UtcNow, CancellationToken.None);
        }
    }

    private async Task<(KgsmUser User, string Password)> AccountAsync(
        UserStatus status = UserStatus.Active, KgsmTier tier = KgsmTier.Viewer)
    {
        string username = "oidc-" + Guid.NewGuid().ToString("N")[..10];
        const string password = "a long enough password";
        return (await anchor.SeedAsync(username, password, tier, status), password);
    }

    private sealed record Pkce(string Verifier, string Challenge);

    private static Pkce NewPkce()
    {
        string verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return new Pkce(verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string AuthorizeUrl(
        string client, string redirect, Pkce pkce, string state = "state-1", string? nonce = "nonce-1",
        string? prompt = null)
    {
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = client,
            ["redirect_uri"] = redirect,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["state"] = state,
            ["code_challenge"] = pkce.Challenge,
            ["code_challenge_method"] = "S256",
        };
        if (nonce is not null)
            query["nonce"] = nonce;
        if (prompt is not null)
            query["prompt"] = prompt;
        return QueryHelpers.AddQueryString("/authorize", query);
    }

    private static HttpRequestMessage CredentialPost(
        string username, string password, string? site = "same-origin", string? origin = null)
    {
        var post = new HttpRequestMessage(HttpMethod.Post, "/authorize/credentials")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = username,
                ["password"] = password,
            }),
        };
        if (site is not null)
            post.Headers.Add("Sec-Fetch-Site", site);
        if (origin is not null)
            post.Headers.Add("Origin", origin);
        return post;
    }

    private static Dictionary<string, string> QueryOf(Uri location) =>
        QueryHelpers.ParseQuery(location.IsAbsoluteUri ? location.Query : new Uri(new Uri("https://x"), location).Query)
            .ToDictionary(kv => kv.Key, kv => kv.Value.ToString());

    /// <summary>A browser signs in with a password and comes back to the client with a code.</summary>
    private async Task<string> CodeByPasswordAsync(
        HttpClient browser, KgsmUser user, string password, Pkce pkce, string client = Panel,
        string redirect = PanelRedirect, string state = "state-1")
    {
        HttpResponseMessage page = await browser.GetAsync(AuthorizeUrl(client, redirect, pkce, state));
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);

        HttpResponseMessage answer = await browser.SendAsync(CredentialPost(user.Username, password));
        Assert.Equal(HttpStatusCode.SeeOther, answer.StatusCode);
        Assert.StartsWith(redirect + "?", answer.Headers.Location!.ToString(), StringComparison.Ordinal);

        Dictionary<string, string> query = QueryOf(answer.Headers.Location!);
        Assert.Equal(state, query["state"]);
        Assert.Equal(AnchorFixture.Issuer, query["iss"]);
        return query["code"];
    }

    private async Task<HttpResponseMessage> ExchangeAsync(
        string code, Pkce pkce, string client = Panel, string redirect = PanelRedirect)
    {
        return await anchor.Client.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirect,
            ["client_id"] = client,
            ["code_verifier"] = pkce.Verifier,
        }));
    }

    private static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static JsonElement Claims(string jwt)
    {
        string payload = jwt.Split('.')[1];
        payload = payload.Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(payload)).RootElement;
    }

    private async Task<HttpStatusCode> UserInfoStatusAsync(string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return (await anchor.Client.SendAsync(request)).StatusCode;
    }

    private async Task<HttpStatusCode> RefreshStatusAsync(string refreshToken)
    {
        HttpResponseMessage response = await anchor.Client.PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken }));
        return response.StatusCode;
    }

    private static void AssertOAuthError(HttpResponseMessage redirect, string error, string state = "state-1")
    {
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        Dictionary<string, string> query = QueryOf(redirect.Headers.Location!);
        Assert.Equal(error, query["error"]);
        Assert.Equal(state, query["state"]);
        Assert.False(query.ContainsKey("code"));
    }

    private void Sql(string statement)
    {
        using var connection = new SqliteConnection($"Data Source={Path.Combine(anchor.Root, "sessions.db")}");
        connection.Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText = statement;
        cmd.ExecuteNonQuery();
    }

    // ── What the provider publishes ───────────────────────────────────────────

    [Fact]
    public async Task Discovery_names_every_door_under_the_issuer()
    {
        JsonElement doc = await Json(await anchor.Client.GetAsync("/.well-known/openid-configuration"));

        Assert.Equal(AnchorFixture.Issuer, doc.GetProperty("issuer").GetString());
        Assert.Equal(AnchorFixture.Issuer + "/authorize", doc.GetProperty("authorization_endpoint").GetString());
        Assert.Equal(AnchorFixture.Issuer + "/token", doc.GetProperty("token_endpoint").GetString());
        Assert.Equal(AnchorFixture.Issuer + "/sign-out", doc.GetProperty("end_session_endpoint").GetString());
        Assert.Equal(["S256"], doc.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["none"], doc.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public async Task The_key_set_is_the_key_every_session_is_signed_with()
    {
        JsonElement jwks = await Json(await anchor.Client.GetAsync("/.well-known/jwks.json"));
        string kid = anchor.Service<EcdsaSessionSigner>().PublicKey.Kid;

        Assert.Equal(kid, Assert.Single(jwks.GetProperty("keys").EnumerateArray()).GetProperty("kid").GetString());
    }

    // ── Refusals that never leave the provider ────────────────────────────────

    [Fact]
    public async Task An_unknown_client_is_refused_here_and_sent_nowhere()
    {
        using HttpClient browser = anchor.Following();
        HttpResponseMessage response = await browser.GetAsync(AuthorizeUrl("nobody", PanelRedirect, NewPkce()));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.StartsWith("text/html", response.Content.Headers.ContentType!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_redirect_the_client_is_not_registered_with_is_refused_here_and_sent_nowhere()
    {
        // Redirecting to it with an error would be the open redirect this endpoint exists to refuse.
        await RegisterClientsAsync();
        using HttpClient browser = anchor.Following();

        foreach (string attempt in (string[])["https://evil.test/callback", PanelRedirect + "/", PanelRedirect + "?x=1"])
        {
            HttpResponseMessage response = await browser.GetAsync(AuthorizeUrl(Panel, attempt, NewPkce()));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Null(response.Headers.Location);
        }
    }

    [Fact]
    public async Task A_request_without_S256_goes_back_to_the_client_as_an_error()
    {
        await RegisterClientsAsync();
        using HttpClient browser = anchor.Following();
        string url = AuthorizeUrl(Panel, PanelRedirect, NewPkce()).Replace("S256", "plain");

        AssertOAuthError(await browser.GetAsync(url), "invalid_request");
    }

    // ── A password, end to end ────────────────────────────────────────────────

    [Fact]
    public async Task The_sign_in_page_is_a_working_form_under_a_policy_that_admits_the_client()
    {
        await RegisterClientsAsync();
        using HttpClient browser = anchor.Following();
        HttpResponseMessage page = await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce()));

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        string html = await page.Content.ReadAsStringAsync();

        // The floor: a form that signs somebody in with no script at all, and the line naming the
        // package whose pages would replace it.
        Assert.Contains("<form method=\"post\" action=\"/authorize/credentials\">", html, StringComparison.Ordinal);
        Assert.Contains("name=\"password\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/authorize/discord\"", html, StringComparison.Ordinal);
        Assert.Contains("kgsm-web-auth", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);

        // Nothing about the request rides in the page: it is held behind the cookie.
        Assert.DoesNotContain(PanelRedirect, html, StringComparison.Ordinal);
        Assert.DoesNotContain("state-1", html, StringComparison.Ordinal);

        string policy = page.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("form-action 'self' https://panel.test;", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("script-src 'self'", policy, StringComparison.Ordinal);

        string cookie = Assert.Single(page.Headers.GetValues("Set-Cookie"), c => c.StartsWith("kgsm_authz=", StringComparison.Ordinal));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_password_signs_in_and_the_code_buys_a_session_and_an_id_token()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();

        string code = await CodeByPasswordAsync(browser, user, password, pkce);
        HttpResponseMessage exchange = await ExchangeAsync(code, pkce);
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        Assert.Equal("no-store", exchange.Headers.CacheControl?.ToString());

        JsonElement tokens = await Json(exchange);
        Assert.Equal("Bearer", tokens.GetProperty("token_type").GetString());
        Assert.True(tokens.GetProperty("expires_in").GetInt64() > 0);

        // The access token is the cluster's: its audience is the cluster and its issuer the URL.
        JsonElement access = Claims(tokens.GetProperty("access_token").GetString()!);
        Assert.Equal(AnchorFixture.ClusterId, access.GetProperty("aud").GetString());
        Assert.Equal(AnchorFixture.Issuer, access.GetProperty("iss").GetString());

        // The id_token is the client's, and names the account and the provider session.
        JsonElement id = Claims(tokens.GetProperty("id_token").GetString()!);
        Assert.Equal(Panel, id.GetProperty("aud").GetString());
        Assert.Equal(AnchorFixture.Issuer, id.GetProperty("iss").GetString());
        Assert.Equal(user.UserId, id.GetProperty("sub").GetString());
        Assert.Equal("nonce-1", id.GetProperty("nonce").GetString());
        Assert.StartsWith("sid_", id.GetProperty("sid").GetString(), StringComparison.Ordinal);
        Assert.NotEqual(access.GetProperty("sid").GetString(), id.GetProperty("sid").GetString());

        // The bearer reads the account behind it.
        using var info = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
        info.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("access_token").GetString());
        JsonElement me = await Json(await anchor.Client.SendAsync(info));
        Assert.Equal(user.UserId, me.GetProperty("sub").GetString());
        Assert.Equal(user.Username, me.GetProperty("preferred_username").GetString());

        // Minted at the one mint site, so recorded as every sign-in is.
        Assert.Contains(anchor.Journal("auth.signed_in"),
            e => e.GetProperty("Data").GetProperty("Sid").GetString() == access.GetProperty("sid").GetString());
    }

    [Fact]
    public async Task The_same_code_twice_is_refused()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        string code = await CodeByPasswordAsync(browser, user, password, pkce);

        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(code, pkce)).StatusCode);

        HttpResponseMessage replay = await ExchangeAsync(code, pkce);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal("invalid_grant", (await Json(replay)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_code_presented_with_the_wrong_verifier_is_refused_and_spent()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        string code = await CodeByPasswordAsync(browser, user, password, pkce);

        HttpResponseMessage wrong = await ExchangeAsync(code, NewPkce());
        Assert.Equal("invalid_grant", (await Json(wrong)).GetProperty("error").GetString());

        // Whoever presented it wrongly is not somebody who should have it, so the right verifier
        // arriving second gets nothing either.
        Assert.Equal(HttpStatusCode.BadRequest, (await ExchangeAsync(code, pkce)).StatusCode);
    }

    [Fact]
    public async Task A_code_for_another_client_or_redirect_is_refused()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();

        string code = await CodeByPasswordAsync(browser, user, password, pkce);
        Assert.Equal(HttpStatusCode.BadRequest, (await ExchangeAsync(code, pkce, client: Chat)).StatusCode);

        using HttpClient another = anchor.Following();
        code = await CodeByPasswordAsync(another, user, password, pkce);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await ExchangeAsync(code, pkce, redirect: PanelRedirect + "?extra=1")).StatusCode);
    }

    [Fact]
    public async Task A_code_older_than_sixty_seconds_is_refused()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        string code = await CodeByPasswordAsync(browser, user, password, pkce);

        // Aged in the store rather than waited out: sixty real seconds would prove the clock works.
        Sql($"UPDATE authorization_codes SET expires = '{DateTimeOffset.UtcNow.AddSeconds(-1):O}';");

        HttpResponseMessage late = await ExchangeAsync(code, pkce);
        Assert.Equal("invalid_grant", (await Json(late)).GetProperty("error").GetString());
    }

    // ── Login CSRF ────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_cross_site_credential_post_is_refused_before_the_password_is_checked()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce()));

        // Enough wrong passwords to lock the account several times over — if any of them were checked.
        for (int i = 0; i < 6; i++)
        {
            HttpResponseMessage refused = await browser.SendAsync(CredentialPost(user.Username, "wrong wrong wrong", site: "cross-site"));
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        }

        HttpResponseMessage noMetadata = await browser.SendAsync(
            CredentialPost(user.Username, "wrong wrong wrong", site: null, origin: "https://evil.test"));
        Assert.Equal(HttpStatusCode.Forbidden, noMetadata.StatusCode);

        HttpResponseMessage neither = await browser.SendAsync(CredentialPost(user.Username, "wrong wrong wrong", site: null));
        Assert.Equal(HttpStatusCode.Forbidden, neither.StatusCode);

        // None of them counted: the real password, sent from the page, still signs in.
        HttpResponseMessage accepted = await browser.SendAsync(CredentialPost(user.Username, password));
        Assert.Equal(HttpStatusCode.SeeOther, accepted.StatusCode);
    }

    [Fact]
    public async Task The_provider_origin_stands_in_for_fetch_metadata()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce()));

        HttpResponseMessage accepted = await browser.SendAsync(
            CredentialPost(user.Username, password, site: null, origin: AnchorFixture.Issuer));
        Assert.Equal(HttpStatusCode.SeeOther, accepted.StatusCode);
    }

    [Fact]
    public async Task A_credential_with_no_request_in_flight_signs_nobody_in()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();

        HttpResponseMessage response = await browser.SendAsync(CredentialPost(user.Username, password));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(response.Headers.TryGetValues("Set-Cookie", out var set) ? set : [],
            c => c.StartsWith("kgsm_anchor=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_pages_fetch_gets_the_same_code_as_json()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce()));

        var post = new HttpRequestMessage(HttpMethod.Post, "/authorize/credentials")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { username = user.Username, password = "not it at all" }),
                Encoding.UTF8, "application/json"),
        };
        post.Headers.Add("Sec-Fetch-Site", "same-origin");
        HttpResponseMessage refused = await browser.SendAsync(post);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal("invalid_credentials", (await Json(refused)).GetProperty("error").GetProperty("code").GetString());

        post = new HttpRequestMessage(HttpMethod.Post, "/authorize/credentials")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { username = user.Username, password }), Encoding.UTF8, "application/json"),
        };
        post.Headers.Add("Sec-Fetch-Site", "same-origin");
        JsonElement answer = await Json(await browser.SendAsync(post));
        Assert.StartsWith(PanelRedirect + "?code=", answer.GetProperty("redirect").GetString(), StringComparison.Ordinal);
    }

    // ── The provider's own session ────────────────────────────────────────────

    [Fact]
    public async Task A_second_client_comes_back_signed_in_with_nothing_typed()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce first = NewPkce();
        string panelCode = await CodeByPasswordAsync(browser, user, password, first);
        JsonElement panel = await Json(await ExchangeAsync(panelCode, first));

        Pkce second = NewPkce();
        HttpResponseMessage bounce = await browser.GetAsync(AuthorizeUrl(Chat, ChatRedirect, second, state: "chat-state"));
        Assert.Equal(HttpStatusCode.Redirect, bounce.StatusCode);
        Dictionary<string, string> query = QueryOf(bounce.Headers.Location!);
        Assert.Equal("chat-state", query["state"]);

        JsonElement chat = await Json(await ExchangeAsync(query["code"], second, Chat, ChatRedirect));
        JsonElement chatId = Claims(chat.GetProperty("id_token").GetString()!);
        JsonElement panelId = Claims(panel.GetProperty("id_token").GetString()!);

        // One person, one provider session, two sessions.
        Assert.Equal(panelId.GetProperty("sub").GetString(), chatId.GetProperty("sub").GetString());
        Assert.Equal(panelId.GetProperty("sid").GetString(), chatId.GetProperty("sid").GetString());
        Assert.NotEqual(
            Claims(panel.GetProperty("access_token").GetString()!).GetProperty("sid").GetString(),
            Claims(chat.GetProperty("access_token").GetString()!).GetProperty("sid").GetString());
    }

    [Fact]
    public async Task Prompt_login_asks_for_the_credential_even_when_signed_in()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        await CodeByPasswordAsync(browser, user, password, NewPkce());

        HttpResponseMessage page = await browser.GetAsync(AuthorizeUrl(Chat, ChatRedirect, NewPkce(), prompt: "login"));
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("/authorize/credentials", await page.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Prompt_none_with_nobody_signed_in_is_login_required_and_never_a_page()
    {
        await RegisterClientsAsync();
        using HttpClient browser = anchor.Following();

        AssertOAuthError(await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce(), prompt: "none")),
            "login_required");
    }

    [Fact]
    public async Task A_disabled_account_s_next_silent_bounce_is_refused_and_its_sign_in_ends()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        await CodeByPasswordAsync(browser, user, password, NewPkce());

        await anchor.Store.UpdateAsync(user with { Status = UserStatus.Disabled, Updated = DateTimeOffset.UtcNow });
        // The authority's cache is the staleness bound on a disable; waited out rather than bypassed.
        await Task.Delay(TimeSpan.FromSeconds(6));

        AssertOAuthError(await browser.GetAsync(AuthorizeUrl(Chat, ChatRedirect, NewPkce(), prompt: "none")),
            "login_required");

        // The provider session went with it, so the next interactive bounce asks for a credential rather
        // than being refused again on the strength of a cookie.
        await anchor.Store.UpdateAsync(user with { Status = UserStatus.Active, Updated = DateTimeOffset.UtcNow });
        await Task.Delay(TimeSpan.FromSeconds(6));
        HttpResponseMessage page = await browser.GetAsync(AuthorizeUrl(Chat, ChatRedirect, NewPkce()));
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
    }

    [Fact]
    public async Task A_disabled_account_is_refused_on_the_providers_page()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync(UserStatus.Disabled);
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce()));

        HttpResponseMessage refused = await browser.SendAsync(CredentialPost(user.Username, password));
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Null(refused.Headers.Location);
        Assert.Contains("switched off", await refused.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_pending_account_waits_and_is_returned_to_the_client_once_approved()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync(UserStatus.Pending, KgsmTier.None);
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, pkce, state: "wait-state"));

        HttpResponseMessage posted = await browser.SendAsync(CredentialPost(user.Username, password));
        Assert.Equal(HttpStatusCode.SeeOther, posted.StatusCode);
        Assert.Equal("/authorize/wait", posted.Headers.Location!.ToString());

        HttpResponseMessage waiting = await browser.GetAsync("/authorize/wait");
        Assert.Equal(HttpStatusCode.OK, waiting.StatusCode);
        string html = await waiting.Content.ReadAsStringAsync();
        Assert.Contains("http-equiv=\"refresh\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("code=", html, StringComparison.Ordinal);

        await anchor.Store.UpdateAsync(user with
        {
            Status = UserStatus.Active, Tier = KgsmTier.Viewer, TierSource = TierSource.Granted,
            Updated = DateTimeOffset.UtcNow,
        });
        await Task.Delay(TimeSpan.FromSeconds(6));

        HttpResponseMessage approved = await browser.GetAsync("/authorize/wait");
        Assert.Equal(HttpStatusCode.Redirect, approved.StatusCode);
        Dictionary<string, string> query = QueryOf(approved.Headers.Location!);
        Assert.Equal("wait-state", query["state"]);
        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(query["code"], pkce)).StatusCode);
    }

    [Fact]
    public async Task A_different_account_on_the_same_browser_ends_the_first_ones_sessions()
    {
        await RegisterClientsAsync();
        (KgsmUser first, string firstPassword) = await AccountAsync();
        (KgsmUser second, string secondPassword) = await AccountAsync();
        using HttpClient browser = anchor.Following();

        Pkce pkce = NewPkce();
        JsonElement firstTokens = await Json(await ExchangeAsync(
            await CodeByPasswordAsync(browser, first, firstPassword, pkce), pkce));

        await browser.GetAsync(AuthorizeUrl(Chat, ChatRedirect, NewPkce(), prompt: "login"));
        HttpResponseMessage switched = await browser.SendAsync(CredentialPost(second.Username, secondPassword));
        Assert.Equal(HttpStatusCode.SeeOther, switched.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, await UserInfoStatusAsync(firstTokens.GetProperty("access_token").GetString()!));
        Assert.Equal(HttpStatusCode.BadRequest, await RefreshStatusAsync(firstTokens.GetProperty("refresh_token").GetString()!));
    }

    [Fact]
    public async Task The_same_account_proving_itself_again_keeps_every_session()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();

        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await ExchangeAsync(await CodeByPasswordAsync(browser, user, password, pkce), pkce));

        await browser.GetAsync(AuthorizeUrl(Chat, ChatRedirect, NewPkce(), prompt: "login"));
        Assert.Equal(HttpStatusCode.SeeOther, (await browser.SendAsync(CredentialPost(user.Username, password))).StatusCode);

        Assert.Equal(HttpStatusCode.OK, await UserInfoStatusAsync(tokens.GetProperty("access_token").GetString()!));
    }

    // ── Renewal ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_refresh_grant_rotates_and_a_rotated_away_token_is_refused()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await ExchangeAsync(await CodeByPasswordAsync(browser, user, password, pkce), pkce));
        string original = tokens.GetProperty("refresh_token").GetString()!;

        HttpResponseMessage rotated = await anchor.Client.PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = original, ["client_id"] = Panel }));
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        JsonElement fresh = await Json(rotated);
        Assert.NotEqual(original, fresh.GetProperty("refresh_token").GetString());

        Assert.Equal(HttpStatusCode.BadRequest, await RefreshStatusAsync(original));
    }

    // ── Signing out ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Sign_out_with_a_hint_ends_every_session_under_the_sign_in()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();

        Pkce first = NewPkce();
        JsonElement panel = await Json(await ExchangeAsync(await CodeByPasswordAsync(browser, user, password, first), first));
        Pkce second = NewPkce();
        HttpResponseMessage bounce = await browser.GetAsync(AuthorizeUrl(Chat, ChatRedirect, second));
        JsonElement chat = await Json(await ExchangeAsync(QueryOf(bounce.Headers.Location!)["code"], second, Chat, ChatRedirect));

        string url = QueryHelpers.AddQueryString("/sign-out", new Dictionary<string, string?>
        {
            ["id_token_hint"] = panel.GetProperty("id_token").GetString(),
            ["client_id"] = Panel,
            ["post_logout_redirect_uri"] = PanelSignedOut,
            ["state"] = "bye",
        });
        HttpResponseMessage signedOut = await browser.GetAsync(url);
        Assert.Equal(HttpStatusCode.Redirect, signedOut.StatusCode);
        Assert.Equal(PanelSignedOut + "?state=bye", signedOut.Headers.Location!.ToString());

        foreach (JsonElement tokens in (JsonElement[])[panel, chat])
        {
            Assert.Equal(HttpStatusCode.Unauthorized, await UserInfoStatusAsync(tokens.GetProperty("access_token").GetString()!));
            Assert.Equal(HttpStatusCode.BadRequest, await RefreshStatusAsync(tokens.GetProperty("refresh_token").GetString()!));
        }

        // The cookie is gone with it, so the next bounce asks for a credential.
        HttpResponseMessage next = await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce(), prompt: "none"));
        AssertOAuthError(next, "login_required");
    }

    [Fact]
    public async Task Sign_out_ends_the_sign_in_even_from_a_browser_that_lost_the_cookie()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await ExchangeAsync(await CodeByPasswordAsync(browser, user, password, pkce), pkce));

        using HttpClient elsewhere = anchor.Following();
        HttpResponseMessage response = await elsewhere.GetAsync(QueryHelpers.AddQueryString("/sign-out",
            "id_token_hint", tokens.GetProperty("id_token").GetString()!));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, await UserInfoStatusAsync(tokens.GetProperty("access_token").GetString()!));
    }

    [Fact]
    public async Task Sign_out_without_a_hint_asks_and_ends_nothing_until_confirmed()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await ExchangeAsync(await CodeByPasswordAsync(browser, user, password, pkce), pkce));

        HttpResponseMessage asked = await browser.GetAsync("/sign-out");
        Assert.Equal(HttpStatusCode.OK, asked.StatusCode);
        Assert.Contains("<form method=\"post\" action=\"/sign-out\">", await asked.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, await UserInfoStatusAsync(tokens.GetProperty("access_token").GetString()!));

        // A confirmation posted from somewhere else is the link-here attack in another shape.
        var forged = new HttpRequestMessage(HttpMethod.Post, "/sign-out") { Content = new FormUrlEncodedContent([]) };
        forged.Headers.Add("Sec-Fetch-Site", "cross-site");
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(forged)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, await UserInfoStatusAsync(tokens.GetProperty("access_token").GetString()!));

        var confirm = new HttpRequestMessage(HttpMethod.Post, "/sign-out") { Content = new FormUrlEncodedContent([]) };
        confirm.Headers.Add("Sec-Fetch-Site", "same-origin");
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(confirm)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await UserInfoStatusAsync(tokens.GetProperty("access_token").GetString()!));
    }

    [Fact]
    public async Task A_bearer_is_not_a_sign_out_hint()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await ExchangeAsync(await CodeByPasswordAsync(browser, user, password, pkce), pkce));

        using HttpClient elsewhere = anchor.Following();
        HttpResponseMessage response = await elsewhere.GetAsync(QueryHelpers.AddQueryString("/sign-out",
            "id_token_hint", tokens.GetProperty("access_token").GetString()!));

        Assert.Contains("action=\"/sign-out\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, await UserInfoStatusAsync(tokens.GetProperty("access_token").GetString()!));
    }

    [Fact]
    public async Task Ending_the_browsers_sign_in_from_the_sessions_list_ends_what_was_minted_under_it()
    {
        await RegisterClientsAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();
        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await ExchangeAsync(await CodeByPasswordAsync(browser, user, password, pkce), pkce));
        string bearer = tokens.GetProperty("access_token").GetString()!;
        string providerSession = Claims(tokens.GetProperty("id_token").GetString()!).GetProperty("sid").GetString()!;

        using var list = new HttpRequestMessage(HttpMethod.Get, "/auth/sessions");
        list.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        JsonElement page = await Json(await anchor.Client.SendAsync(list));
        JsonElement row = Assert.Single(page.GetProperty("data").EnumerateArray(), s => s.GetProperty("sid").GetString() == providerSession);
        Assert.Equal("provider", row.GetProperty("kind").GetString());

        using var revoke = new HttpRequestMessage(HttpMethod.Post, "/auth/session/revoke")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { sid = providerSession }), Encoding.UTF8, "application/json"),
        };
        revoke.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        Assert.Equal(HttpStatusCode.OK, (await anchor.Client.SendAsync(revoke)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, await UserInfoStatusAsync(bearer));
    }

    // ── Standing by ───────────────────────────────────────────────────────────

    [Fact]
    public async Task A_member_standing_by_refuses_to_authorize_and_names_the_holder()
    {
        await RegisterClientsAsync();
        using HttpClient browser = anchor.Following();

        await anchor.StandingBy("elsewhere-auth", async () =>
        {
            HttpResponseMessage page = await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce()));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, page.StatusCode);
            Assert.Contains("elsewhere-auth", await page.Content.ReadAsStringAsync(), StringComparison.Ordinal);

            HttpResponseMessage token = await ExchangeAsync("anything", NewPkce());
            Assert.Equal("temporarily_unavailable", (await Json(token)).GetProperty("error").GetString());
        });
    }

    // ── Clients ───────────────────────────────────────────────────────────────

    private async Task<string> AdminBearerAsync()
    {
        (KgsmUser admin, string password) = await AccountAsync(tier: KgsmTier.Admin);
        HttpResponseMessage signIn = await anchor.Client.PostAsync("/auth/sign-in",
            new StringContent(JsonSerializer.Serialize(new { username = admin.Username, password }), Encoding.UTF8, "application/json"));
        return (await Json(signIn)).GetProperty("token").GetString()!;
    }

    [Fact]
    public async Task An_administrator_registers_lists_and_removes_a_client()
    {
        string bearer = await AdminBearerAsync();
        string id = "hand-" + Guid.NewGuid().ToString("N")[..8];

        using var create = new HttpRequestMessage(HttpMethod.Post, "/auth/cluster/clients")
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                clientId = id,
                name = "A bucket panel",
                redirectUris = new[] { "https://bucket.test/" },
                postLogoutRedirectUris = new[] { "https://bucket.test/" },
            }), Encoding.UTF8, "application/json"),
        };
        create.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        HttpResponseMessage created = await anchor.Client.SendAsync(create);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal("admin", (await Json(created)).GetProperty("source").GetString());

        using var list = new HttpRequestMessage(HttpMethod.Get, "/auth/cluster/clients");
        list.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        JsonElement page = await Json(await anchor.Client.SendAsync(list));
        Assert.Contains(page.GetProperty("data").EnumerateArray(), c => c.GetProperty("clientId").GetString() == id);

        using var remove = new HttpRequestMessage(HttpMethod.Delete, $"/auth/cluster/clients/{id}");
        remove.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        Assert.Equal(HttpStatusCode.NoContent, (await anchor.Client.SendAsync(remove)).StatusCode);
        Assert.Null(anchor.Service<ClientRegistry>().Find(id));
    }

    [Theory]
    [InlineData("http://bucket.test/")]
    [InlineData("https://bucket.test/#fragment")]
    [InlineData("https://user@bucket.test/")]
    [InlineData("not a url")]
    public async Task A_redirect_that_could_leak_a_code_cannot_be_registered(string uri)
    {
        var (outcome, _, _) = await anchor.Service<ClientRegistry>().RegisterAsync(
            new ClientRegistration(null, "Bad", [uri], []), DateTimeOffset.UtcNow, CancellationToken.None);
        Assert.Equal(ClientRegistry.RegisterOutcome.Invalid, outcome);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8080/signed-in")]
    [InlineData("http://192.168.1.10:8080/signed-in")]
    [InlineData("http://10.44.0.4:8080/signed-in")]
    [InlineData("http://gamebox.lan:8080/signed-in")]
    public void A_panel_on_this_machine_or_a_private_network_can_be_registered_over_plain_http(string uri)
    {
        // A cluster of one on a LAN serves its panel over plain HTTP; the operator owns that wire, and a
        // code seen on it is worthless without the verifier the browser holds.
        Assert.Null(ClientRegistry.Problem(uri));
    }

    [Fact]
    public async Task A_member_announces_a_surface_on_its_own_address_and_nowhere_else()
    {
        var registry = anchor.Service<ClientRegistry>();
        string member = "node-" + Guid.NewGuid().ToString("N")[..6];

        MemberRow row = MemberRow.New(member, "node") with
        {
            Candidates = MemberCandidates.Encode([new MemberCandidate("https://node.test", Client: true)]),
            Published = PublishedFacts.Encode(new Dictionary<string, string>
            {
                [ClusterClientAnnouncement.FactKey] = new ClusterClientAnnouncement(
                    "Control Panel", ["/", "//evil.test/", "/signed-in"], ["/"]).ToJson(),
            }),
        };

        Assert.True(await registry.SyncMembersAsync([row], DateTimeOffset.UtcNow, CancellationToken.None));
        RegisteredClient client = registry.Find(member)!;
        Assert.Equal(ClientSources.Member, client.Source);
        Assert.Equal(["https://node.test/", "https://node.test/signed-in"], client.RedirectUris);
        Assert.True(registry.IsClientOrigin("https://node.test"));

        // It leaves when the member stops announcing it.
        Assert.True(await registry.SyncMembersAsync([], DateTimeOffset.UtcNow, CancellationToken.None));
        Assert.Null(registry.Find(member));

        // And an administrator's client of the same id is never taken over by an announcement.
        await registry.RegisterAsync(new ClientRegistration(member, "By hand", ["https://hand.test/"], []),
            DateTimeOffset.UtcNow, CancellationToken.None);
        await registry.SyncMembersAsync([row], DateTimeOffset.UtcNow, CancellationToken.None);
        Assert.Equal(ClientSources.Admin, registry.Find(member)!.Source);
        await registry.RemoveAsync(member, CancellationToken.None);
    }

    [Fact]
    public async Task A_client_origin_may_exchange_codes_across_origins_but_never_with_credentials()
    {
        await RegisterClientsAsync();

        using var preflight = new HttpRequestMessage(HttpMethod.Options, "/token");
        preflight.Headers.Add("Origin", "https://chat.test");
        preflight.Headers.Add("Access-Control-Request-Method", "POST");
        HttpResponseMessage allowed = await anchor.Client.SendAsync(preflight);
        Assert.Equal("https://chat.test", allowed.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.False(allowed.Headers.Contains("Access-Control-Allow-Credentials"));

        // Nothing that reads the provider's cookie answers another origin.
        using var credentials = new HttpRequestMessage(HttpMethod.Options, "/authorize/credentials");
        credentials.Headers.Add("Origin", "https://chat.test");
        credentials.Headers.Add("Access-Control-Request-Method", "POST");
        HttpResponseMessage refused = await anchor.Client.SendAsync(credentials);
        Assert.False(refused.Headers.Contains("Access-Control-Allow-Origin"));
    }

    // ── An external provider ──────────────────────────────────────────────────

    [Fact]
    public async Task A_provider_round_trip_from_the_page_returns_to_the_page_not_the_panel()
    {
        await RegisterClientsAsync();
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce()));

        HttpResponseMessage start = await browser.GetAsync("/authorize/discord");
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        string upstream = QueryOf(start.Headers.Location!)["state"];

        // The provider comes back without a code — denied at its own screen. The request in flight is
        // this one, so the refusal lands on the sign-in page, never on the provider door's panel handoff.
        HttpResponseMessage back = await browser.GetAsync($"/auth/discord/callback?state={Uri.EscapeDataString(upstream)}");
        Assert.Equal(HttpStatusCode.BadRequest, back.StatusCode);
        Assert.Null(back.Headers.Location);
        Assert.Contains("/authorize/credentials", await back.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_provider_door_sign_in_is_not_captured_by_an_abandoned_request()
    {
        await RegisterClientsAsync();
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl(Panel, PanelRedirect, NewPkce()));

        // Started at the provider door, not from the page: its state is not the one the request recorded.
        HttpResponseMessage start = await browser.GetAsync("/auth/discord/start");
        string upstream = QueryOf(start.Headers.Location!)["state"];

        HttpResponseMessage back = await browser.GetAsync($"/auth/discord/callback?state={Uri.EscapeDataString(upstream)}");
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        Assert.StartsWith(AnchorFixture.PanelUrl, back.Headers.Location!.ToString(), StringComparison.Ordinal);
    }
}
