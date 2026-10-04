using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.WebUtilities;

using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// Plumbing shared by the suites that drive a sign-in from the provider's own page.
/// </summary>
internal static class SignInPage
{
    public const string Client = "door-client";
    public const string Redirect = "https://door.test/callback";

    public static async Task RegisterClientAsync(AnchorFixture anchor)
    {
        var registry = anchor.Service<ClientRegistry>();
        if (registry.Find(Client) is null)
        {
            await registry.RegisterAsync(new ClientRegistration(Client, "Door client", [Redirect], []),
                DateTimeOffset.UtcNow, CancellationToken.None);
        }
    }

    /// <summary>A browser with a request in flight: it has opened the provider's sign-in page for the client.</summary>
    public static async Task<HttpClient> OpenAsync(AnchorFixture anchor) => (await OpenWithVerifierAsync(anchor)).Browser;

    private static async Task<(HttpClient Browser, string Verifier)> OpenWithVerifierAsync(AnchorFixture anchor)
    {
        await RegisterClientAsync(anchor);
        HttpClient browser = anchor.Following();

        string verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        string challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        HttpResponseMessage page = await browser.GetAsync(QueryHelpers.AddQueryString("/authorize",
            new Dictionary<string, string?>
            {
                ["client_id"] = Client, ["redirect_uri"] = Redirect, ["response_type"] = "code",
                ["scope"] = "openid", ["state"] = "s", ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            }));
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        return (browser, verifier);
    }

    /// <summary>What a client holds after a sign-in, and the browser that signed in.</summary>
    public sealed record SignedIn(HttpClient Browser, string Access, string Refresh, string IdToken);

    /// <summary>
    /// Sign in with a password the whole way a browser and a client do: the page, the credential, the
    /// code, and the exchange that mints the session.
    /// </summary>
    public static async Task<SignedIn> ThroughThePagesAsync(AnchorFixture anchor, string username, string password)
    {
        (HttpClient browser, string verifier) = await OpenWithVerifierAsync(anchor);

        HttpResponseMessage answer = await browser.SendAsync(Post("/authorize/credentials", new { username, password }));
        Assert.Equal(HttpStatusCode.OK, answer.StatusCode);
        var redirect = new Uri((await Json(answer)).GetProperty("redirect").GetString()!);
        string code = QueryHelpers.ParseQuery(redirect.Query)["code"]!;

        HttpResponseMessage token = await anchor.Client.PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = Redirect,
                ["client_id"] = Client, ["code_verifier"] = verifier,
            }));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);

        JsonElement set = await Json(token);
        return new SignedIn(browser, set.GetProperty("access_token").GetString()!,
            set.GetProperty("refresh_token").GetString()!, set.GetProperty("id_token").GetString()!);
    }

    /// <summary>Sign out at the provider with the id token as the hint, as a client does.</summary>
    public static Task<HttpResponseMessage> SignOutAsync(SignedIn session) =>
        session.Browser.GetAsync(QueryHelpers.AddQueryString("/sign-out", new Dictionary<string, string?>
        {
            ["id_token_hint"] = session.IdToken, ["client_id"] = Client,
        }));

    /// <summary>A post the provider's own pages make: same-origin, answered as JSON.</summary>
    public static HttpRequestMessage Post(string path, object body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("Sec-Fetch-Site", "same-origin");
        request.Headers.Add("Accept", "application/json");
        return request;
    }

    public static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>
/// Signing in with an account somebody already holds elsewhere: the round trip the sign-in page starts,
/// and the callback it comes back through.
/// </summary>
/// <remarks>
/// Nothing here reaches a provider, and that is not a gap in the coverage — every case below is decided
/// <b>before</b> an exchange is attempted. The bounce, the CSRF gate and the refusals are the whole of
/// what this anchor decides on its own; what a provider says about a code is the provider's package to
/// test, and it does.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class ProviderDoorTests(AnchorFixture anchor)
{
    private static string VerifierCookie(HttpResponseMessage response) =>
        response.Headers.GetValues("Set-Cookie")
            .First(c => c.StartsWith("kgsm_oauth_state=", StringComparison.Ordinal)).Split(';')[0];

    // ── The bounce ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Starting_a_provider_sign_in_sends_the_browser_to_the_provider()
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);
        HttpResponseMessage response = await browser.GetAsync("/authorize/discord");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        string url = response.Headers.Location!.ToString();
        Assert.StartsWith("https://discord.com/", url, StringComparison.Ordinal);

        // The callback the provider is told to come back to is built from this anchor's own public
        // address, so the URI registered on the application and the one presented at the exchange
        // cannot come to differ.
        Assert.Contains(
            Uri.EscapeDataString($"{AnchorFixture.SignInUrl}/auth/discord/callback"), url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_bounce_carries_a_challenge_and_never_the_verifier()
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);
        HttpResponseMessage response = await browser.GetAsync("/authorize/discord");

        string url = response.Headers.Location!.ToString();
        Assert.Contains("code_challenge=", url, StringComparison.Ordinal);
        Assert.Contains("code_challenge_method=S256", url, StringComparison.Ordinal);
        Assert.Contains("state=", url, StringComparison.Ordinal);

        // The verifier stays in the cookie. A URL is written to logs, to history, and to the Referer
        // header of whatever the provider's page loads next, so a verifier in one is a PKCE exchange
        // anybody who reads any of those can complete.
        string cookie = Assert.Single(
            response.Headers.GetValues("Set-Cookie"),
            c => c.StartsWith("kgsm_oauth_state=", StringComparison.Ordinal));
        string verifier = cookie.Split(';')[0].Split('.')[^1];
        Assert.NotEmpty(verifier);
        Assert.DoesNotContain(verifier, url, StringComparison.Ordinal);

        // HttpOnly, so no script reads the handshake it is part of. Lax rather than Strict, because
        // Strict suppresses the cookie on the top-level redirect back from the provider and would break
        // every sign-in.
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
    }

    // ── The CSRF gate, which runs before any exchange ─────────────────────────

    [Fact]
    public async Task A_callback_with_no_handshake_cookie_is_refused_here()
    {
        using HttpClient browser = anchor.Following();

        // What a login CSRF looks like: an attacker's code and state delivered to a browser that never
        // started a sign-in here. There is no cookie to match it against, so it is refused before this
        // anchor talks to anybody — on this anchor's own page, since there is no client to send it to.
        HttpResponseMessage response = await browser.GetAsync("/auth/discord/callback?code=abc&state=xyz");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A_callback_whose_state_does_not_match_the_cookie_is_refused_here()
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);
        await browser.GetAsync("/authorize/discord");

        HttpResponseMessage response =
            await browser.GetAsync("/auth/discord/callback?code=abc&state=not-the-issued-one");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A_callback_carrying_no_code_goes_back_to_the_sign_in_page()
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);
        HttpResponseMessage started = await browser.GetAsync("/authorize/discord");
        string state = QueryHelpers.ParseQuery(started.Headers.Location!.Query)["state"]!;

        // Declined at the provider's own screen. The request is still in flight, so the person is put
        // back on the page they started from with the reason, rather than on a page of its own.
        HttpResponseMessage response =
            await browser.GetAsync($"/auth/discord/callback?state={Uri.EscapeDataString(state)}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("/authorize/credentials", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_callback_for_a_request_no_longer_waiting_completes_nothing()
    {
        using HttpClient browser = anchor.Following();

        // Started in one browser, returned to another that has no request in flight — the state that
        // returns matches the handshake cookie and no request here.
        using HttpClient first = await SignInPage.OpenAsync(anchor);
        HttpResponseMessage started = await first.GetAsync("/authorize/discord");
        string state = QueryHelpers.ParseQuery(started.Headers.Location!.Query)["state"]!;
        string cookie = VerifierCookie(started);

        var back = new HttpRequestMessage(HttpMethod.Get, $"/auth/discord/callback?code=abc&state={Uri.EscapeDataString(state)}");
        back.Headers.Add("Cookie", cookie);
        HttpResponseMessage response = await browser.SendAsync(back);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // ── Providers this anchor does not offer ──────────────────────────────────

    [Theory]
    [InlineData("github")]
    [InlineData("nonesuch")]
    public async Task A_provider_this_anchor_does_not_offer_is_one_answer(string provider)
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);

        // A provider nobody wired up and a provider nobody has heard of answer identically, so the set
        // of providers a build knows about cannot be learned by asking about them one at a time.
        HttpResponseMessage response = await browser.GetAsync($"/authorize/{provider}");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("is not set up here", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    // ── Standing by ───────────────────────────────────────────────────────────

    [Fact]
    public async Task A_member_that_does_not_hold_the_accounts_starts_no_sign_in()
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);

        await anchor.StandingBy("some-other-anchor", async () =>
        {
            // Bouncing somebody to a provider on a member that could not finish the sign-in would spend
            // their time to arrive at a refusal. It is refused before the bounce instead.
            HttpResponseMessage response = await browser.GetAsync("/authorize/discord");

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Contains("some-other-anchor", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        });
    }

    // ── What the door is for ──────────────────────────────────────────────────

    [Fact]
    public async Task An_account_reached_through_a_provider_is_the_same_account_as_ever()
    {
        // The property the whole door exists to have: a provider identity resolves to the account
        // that already carries it, with everything it already holds. Nobody is migrated, nothing is
        // matched on a username, and a person who has been using this cluster keeps being the same
        // person when they arrive through a different door.
        var identity = new KgsmIdentity("discord", "9001", "haru", "Haru", null, []);
        KgsmUser seeded = await anchor.SeedAsync("haru-provider", "unused-password", owner: true);

        await anchor.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), seeded.UserId, CredentialKind.Identity,
            identity.Handle, Secret: null, "haru", DateTimeOffset.UtcNow, null));

        var linking = new IdentityLinkService(anchor.Store);
        LinkResult link = await linking.ResolveOrProvisionAsync(
            identity, DateTimeOffset.UtcNow, new PendingPolicy(25, TimeSpan.FromDays(14)));

        Assert.Equal(LinkOutcome.Existing, link.Outcome);
        Assert.Equal(seeded.UserId, link.User!.UserId);
        Assert.True((await anchor.Store.LoadAsync()).IsOwner(link.User.UserId));
    }
}

/// <summary>
/// Making an account nobody has yet, on the provider's registration page.
/// </summary>
/// <remarks>
/// An unauthenticated write, so what bounds it is the interesting part: it is off unless a cluster
/// says otherwise, it creates an account holding nothing, and it is capped by the same policy the
/// provider door is — one queue, not two counts that can disagree about how full it is.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class RegisterTests(AnchorFixture anchor)
{
    private static string Code(JsonElement body) => body.GetProperty("error").GetProperty("code").GetString()!;

    private async Task<HttpResponseMessage> RegisterAsync(object body)
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);
        return await browser.SendAsync(SignInPage.Post("/authorize/register", body));
    }

    [Fact]
    public async Task Somebody_with_no_account_gets_one_that_waits_and_reaches_nothing()
    {
        string name = "newcomer" + Guid.NewGuid().ToString("N")[..8];
        HttpResponseMessage response = await RegisterAsync(new { username = name, password = "a-long-enough-password" });

        // The wait, never a code and never a session: an account nobody has approved gets nothing a
        // client could spend.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement body = await SignInPage.Json(response);
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("wait").GetString()));

        KgsmUser? stored = await anchor.Store.FindByUsernameAsync(name);
        Assert.NotNull(stored);
        Assert.Equal(UserStatus.Pending, stored.Status);
        Assert.Empty((await anchor.Store.LoadAsync()).AssignmentsOf(stored.UserId));

        // Arrived, not admitted: nobody made it, and expiry reads that difference to tell an account
        // that arrived on its own from one somebody made.
        Assert.Equal(AccountOrigin.Arrived, stored.Origin);
    }

    [Fact]
    public async Task The_password_it_sets_is_the_one_that_signs_in()
    {
        string name = "roundtrip" + Guid.NewGuid().ToString("N")[..8];
        const string password = "a-long-enough-password";
        await RegisterAsync(new { username = name, password });

        using HttpClient browser = await SignInPage.OpenAsync(anchor);
        HttpResponseMessage signIn = await browser.SendAsync(
            SignInPage.Post("/authorize/credentials", new { username = name, password }));

        // Proven, and still waiting: the credential is right and the account holds nothing yet.
        Assert.Equal(HttpStatusCode.OK, signIn.StatusCode);
        Assert.False(string.IsNullOrWhiteSpace((await SignInPage.Json(signIn)).GetProperty("wait").GetString()));
    }

    [Theory]
    [InlineData("", "a-long-enough-password")]
    [InlineData("no spaces allowed", "a-long-enough-password")]
    [InlineData("fine-name", "short")]
    [InlineData("fine-name", "")]
    public async Task A_username_or_password_that_will_not_do_is_refused(string username, string password)
    {
        HttpResponseMessage response = await RegisterAsync(new { username, password });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("bad_request", Code(await SignInPage.Json(response)));
    }

    [Fact]
    public async Task A_username_somebody_already_has_is_refused_rather_than_taken()
    {
        string name = "taken" + Guid.NewGuid().ToString("N")[..8];
        await RegisterAsync(new { username = name, password = "a-long-enough-password" });

        HttpResponseMessage second = await RegisterAsync(new { username = name, password = "another-long-password" });

        // Never merged onto the existing account: matching a stranger onto somebody else's account by
        // name is the documented route to handing one person another's access.
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal("username_taken", Code(await SignInPage.Json(second)));
    }

    [Fact]
    public async Task Nothing_on_the_wire_can_ask_for_access_or_standing()
    {
        string name = "ambitious" + Guid.NewGuid().ToString("N")[..8];

        // The shape has no role and no status, so a caller sending them is sending fields that bind to
        // nothing. Asserted rather than assumed, because "the DTO does not have it" is exactly the kind
        // of thing a later edit quietly changes.
        await RegisterAsync(new { username = name, password = "a-long-enough-password", role = "role_owner", status = "active" });

        KgsmUser? stored = await anchor.Store.FindByUsernameAsync(name);
        Assert.Equal(UserStatus.Pending, stored!.Status);
        Assert.Equal(AccountOrigin.Arrived, stored.Origin);
        Assert.Empty((await anchor.Store.LoadAsync()).AssignmentsOf(stored.UserId));
    }

    [Fact]
    public async Task A_refused_registration_is_the_frozen_envelope()
    {
        // The page renders the anchor's own sentence rather than keeping a second copy of the rules, so
        // the code and the message are both part of the contract.
        HttpResponseMessage response = await RegisterAsync(
            new { username = "capped" + Guid.NewGuid().ToString("N")[..8], password = "short" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        JsonElement body = await SignInPage.Json(response);
        Assert.True(body.TryGetProperty("error", out JsonElement error));
        Assert.False(string.IsNullOrWhiteSpace(error.GetProperty("code").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(error.GetProperty("message").GetString()));
    }

    [Fact]
    public void A_cluster_that_has_not_decided_to_take_strangers_does_not()
    {
        // Off unless a cluster says otherwise. It is an unauthenticated write, and a default that
        // opened it would take strangers on every install that never thought about the question.
        // Asserted against the settings-to-options step, because that is where the answer is decided.
        AnchorOptions defaults = AnchorOptions.FromSettings(new AnchorSettings());

        Assert.False(defaults.AllowSelfRegistration);
    }

    [Fact]
    public void The_callback_names_the_capability_name_this_anchor_serves_when_none_is_configured()
    {
        AnchorOptions unconfigured = AnchorOptions.FromSettings(new AnchorSettings { PublicBaseUrl = "" });
        var served = new Served("https://auth.anchors.example.com");
        var address = new AnchorAddress(unconfigured, [served]);

        Assert.Equal("https://auth.anchors.example.com/auth/discord/callback", address.RedirectUri("discord"));
        Assert.Equal(
            "https://auth.anchors.example.com/auth/identities/discord/callback", address.LinkRedirectUri("discord"));

        // Standing by, or before the certificate is installed, the name answers nobody here: a bounce
        // built from it would send a person to a handshake that fails, so there is no callback at all.
        served.Now = [];
        Assert.Null(address.RedirectUri("discord"));

        // An operator's address wins over the served name.
        AnchorOptions configured = AnchorOptions.FromSettings(new AnchorSettings { PublicBaseUrl = "https://sign-in.example.com/" });
        Assert.Equal(
            "https://sign-in.example.com/auth/discord/callback",
            new AnchorAddress(configured, [new Served("https://auth.anchors.example.com")]).RedirectUri("discord"));
    }

    private sealed class Served(params string[] addresses) : TheKrystalShip.KGSM.Cluster.Membership.ISelfAddressSource
    {
        public IReadOnlyList<string> Now { get; set; } = addresses;
        public IReadOnlyList<string> Addresses => Now;
    }

    [Fact]
    public async Task A_member_that_does_not_hold_the_accounts_creates_none()
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);
        string name = "standby" + Guid.NewGuid().ToString("N")[..8];

        await anchor.StandingBy("some-other-anchor", async () =>
        {
            // Writing here would create an account the holder has never heard of and will overwrite at
            // the next snapshot — an account somebody was told they had, that quietly stops existing.
            HttpResponseMessage response = await browser.SendAsync(
                SignInPage.Post("/authorize/register", new { username = name, password = "a-long-enough-password" }));

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal("not_the_anchor", Code(await SignInPage.Json(response)));
        });

        Assert.Null(await anchor.Store.FindByUsernameAsync(name));
    }
}
