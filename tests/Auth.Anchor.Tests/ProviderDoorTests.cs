using System.Net.Http;
using System.Net;
using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Users;
using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// Signing in with an account somebody already holds elsewhere.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here reaches a provider, and that is not a gap in the coverage — every case below is
/// decided <b>before</b> an exchange is attempted. The bounce, the CSRF gate and the refusals are the
/// whole of what this anchor decides on its own; what a provider says about a code is the provider's
/// package to test, and it does.
/// </para>
/// <para>
/// The one thing worth stating about the shape: what this door mints is what the password door
/// mints. A session audienced to the cluster, signed with a key no member can reproduce. The two
/// differ in what proves a person and in nothing after that.
/// </para>
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class ProviderDoorTests(AnchorFixture anchor)
{
    private static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    /// <summary>
    /// Assert a handoff back to the panel carrying <paramref name="fragment"/>.
    /// </summary>
    /// <remarks>
    /// The origin and the fragment are asserted separately because the exact string is not this
    /// anchor's to control: a bare authority gains a path when anything parses it as a URI, so
    /// pinning the whole string would be testing the parser.
    /// </remarks>
    private static void RedirectedToPanel(HttpResponseMessage response, string fragment)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Uri location = response.Headers.Location!;
        Assert.StartsWith(AnchorFixture.PanelUrl, location.ToString(), StringComparison.Ordinal);
        Assert.Equal(fragment, location.Fragment);
    }

    // ── What a sign-in page is told ───────────────────────────────────────────

    [Fact]
    public async Task The_providers_a_person_can_use_are_readable_without_signing_in()
    {
        // A sign-in page draws its buttons before anybody has signed in, so this cannot be gated on
        // having done so. What it discloses is which doors exist, never anything behind one.
        HttpResponseMessage response = await anchor.Client.GetAsync("/auth/providers");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        JsonElement body = await Json(response);
        Assert.Contains(
            "discord",
            body.GetProperty("providers").EnumerateArray().Select(p => p.GetString()));
        Assert.True(body.GetProperty("redirects").GetBoolean());
    }

    // ── The bounce ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Starting_a_sign_in_sends_the_browser_to_the_provider()
    {
        using HttpClient client = anchor.Following();
        HttpResponseMessage response = await client.GetAsync("/auth/discord/start");

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
        using HttpClient client = anchor.Following();
        HttpResponseMessage response = await client.GetAsync("/auth/discord/start");

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

        // HttpOnly, so script on the panel's origin cannot read the handshake it is part of. Lax
        // rather than Strict, because Strict suppresses the cookie on the top-level redirect back
        // from the provider and would break every sign-in.
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("", "none")]
    [InlineData("consent", "consent")]
    [InlineData("none", "none")]
    public async Task The_prompt_a_caller_asks_for_is_the_prompt_it_gets(string asked, string expected)
    {
        using HttpClient client = anchor.Following();
        string query = asked.Length == 0 ? "" : $"?prompt={asked}";

        HttpResponseMessage response = await client.GetAsync($"/auth/discord/start{query}");

        // A door that takes an explicit request for a screen and silently sends the opposite is
        // wrong however the provider happens to treat it.
        Assert.Contains($"prompt={expected}", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    // ── The CSRF gate, which runs before any exchange ─────────────────────────

    [Fact]
    public async Task A_callback_with_no_handshake_cookie_is_refused()
    {
        using HttpClient client = anchor.Following();

        // What a login CSRF looks like: an attacker's code and state delivered to a browser that
        // never started a sign-in here. There is no cookie to match it against, so it is refused
        // before this anchor talks to anybody.
        HttpResponseMessage response = await client.GetAsync("/auth/discord/callback?code=abc&state=xyz");

        RedirectedToPanel(response, "#error=invalid_state");
    }

    [Fact]
    public async Task A_callback_whose_state_does_not_match_the_cookie_is_refused()
    {
        using HttpClient client = anchor.Following();

        HttpResponseMessage started = await client.GetAsync("/auth/discord/start");
        string cookie = started.Headers.GetValues("Set-Cookie")
            .First(c => c.StartsWith("kgsm_oauth_state=", StringComparison.Ordinal)).Split(';')[0];

        var request = new HttpRequestMessage(
            HttpMethod.Get, "/auth/discord/callback?code=abc&state=not-the-issued-one");
        request.Headers.Add("Cookie", cookie);

        HttpResponseMessage response = await client.SendAsync(request);

        RedirectedToPanel(response, "#error=invalid_state");
    }

    [Fact]
    public async Task A_callback_carrying_no_code_is_refused()
    {
        using HttpClient client = anchor.Following();

        HttpResponseMessage started = await client.GetAsync("/auth/discord/start");
        string raw = started.Headers.GetValues("Set-Cookie")
            .First(c => c.StartsWith("kgsm_oauth_state=", StringComparison.Ordinal)).Split(';')[0];
        string state = raw["kgsm_oauth_state=".Length..].Split('.')[0];

        var request = new HttpRequestMessage(HttpMethod.Get, $"/auth/discord/callback?state={state}");
        request.Headers.Add("Cookie", raw);

        HttpResponseMessage response = await client.SendAsync(request);

        RedirectedToPanel(response, "#error=bad_request");
    }

    // ── Providers this anchor does not offer ──────────────────────────────────

    [Theory]
    [InlineData("github")]
    [InlineData("nonesuch")]
    public async Task A_provider_this_anchor_does_not_offer_is_one_answer(string provider)
    {
        using HttpClient client = anchor.Following();

        // A provider nobody wired up and a provider nobody has heard of answer identically, so the
        // set of providers a build knows about cannot be learned by asking about them one at a time.
        HttpResponseMessage response = await client.GetAsync($"/auth/{provider}/start");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("auth_unconfigured", (await Json(response)).GetProperty("error").GetProperty("code").GetString());
    }

    // ── Standing by ───────────────────────────────────────────────────────────

    [Fact]
    public async Task A_member_that_does_not_hold_the_accounts_starts_no_sign_in()
    {
        using HttpClient client = anchor.Following();

        await anchor.StandingBy("some-other-anchor", async () =>
        {
            // Bouncing somebody to a provider on a member that could not finish the sign-in would
            // spend their time to arrive at a refusal. It is refused at the door instead.
            HttpResponseMessage response = await client.GetAsync("/auth/discord/start");

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal(
                "not_the_anchor", (await Json(response)).GetProperty("error").GetProperty("code").GetString());
        });
    }

    // ── What the door is for ──────────────────────────────────────────────────

    [Fact]
    public async Task An_account_reached_through_a_provider_is_the_same_account_as_ever()
    {
        // The property the whole door exists to have: a provider identity resolves to the account
        // that already carries it, with the tier it already has. Nobody is migrated, nothing is
        // matched on a username, and a person who has been using this cluster keeps being the same
        // person when they arrive through a different door.
        var identity = new KgsmIdentity("discord", "9001", "haru", "Haru", null, []);
        KgsmUser seeded = await anchor.SeedAsync("haru-provider", "unused-password", KgsmTier.Operator);

        await anchor.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), seeded.UserId, CredentialKind.Identity,
            identity.Handle, Secret: null, "haru", DateTimeOffset.UtcNow, null));

        var linking = new IdentityLinkService(anchor.Store);
        LinkResult link = await linking.ResolveOrProvisionAsync(
            identity, DateTimeOffset.UtcNow, new PendingPolicy(25, TimeSpan.FromDays(14)));

        Assert.Equal(LinkOutcome.Existing, link.Outcome);
        Assert.Equal(seeded.UserId, link.User!.UserId);
        Assert.Equal(KgsmTier.Operator, link.User.Tier);
    }
}

/// <summary>
/// Making an account nobody has yet.
/// </summary>
/// <remarks>
/// An unauthenticated write, so what bounds it is the interesting part: it is off unless a cluster
/// says otherwise, it creates an account holding nothing, and it is capped by the same policy the
/// provider door is — one queue, not two counts that can disagree about how full it is.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class RegisterTests(AnchorFixture anchor)
{
    private static StringContent Body(string? username, string? password, string? display = null) =>
        new(JsonSerializer.Serialize(new { username, password, displayName = display }),
            System.Text.Encoding.UTF8, "application/json");

    private static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static string Code(JsonElement body) => body.GetProperty("error").GetProperty("code").GetString()!;

    [Fact]
    public async Task Somebody_with_no_account_gets_one_and_a_session_that_reaches_nothing()
    {
        string name = "newcomer" + Guid.NewGuid().ToString("N")[..8];
        HttpResponseMessage response = await anchor.Client.PostAsync("/auth/register", Body(name, "a-long-enough-password"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        JsonElement body = await Json(response);

        // A real session, deliberately. A bare refusal tells somebody who has just made an account
        // nothing about what happens next; this lets a surface say they are waiting on an admin.
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("token").GetString()));
        Assert.Equal("pending", body.GetProperty("status").GetString());
        Assert.Equal("none", body.GetProperty("tier").GetString());

        // Scoped to the cluster like every other session this anchor mints — the doors differ in
        // what proves a person and in nothing after that.
        Assert.Equal(AnchorFixture.ClusterId, body.GetProperty("cluster").GetString());

        KgsmUser? stored = await anchor.Store.FindByUsernameAsync(name);
        Assert.NotNull(stored);
        Assert.Equal(KgsmTier.None, stored.Tier);
        Assert.Equal(UserStatus.Pending, stored.Status);

        // Derived, not granted: nobody chose this tier, and expiry reads that difference to tell an
        // account that arrived on its own from one an admin made.
        Assert.Equal(TierSource.Derived, stored.TierSource);
    }

    [Fact]
    public async Task The_password_it_sets_is_the_one_that_signs_in()
    {
        string name = "roundtrip" + Guid.NewGuid().ToString("N")[..8];
        const string password = "a-long-enough-password";

        Assert.Equal(
            HttpStatusCode.Created,
            (await anchor.Client.PostAsync("/auth/register", Body(name, password))).StatusCode);

        HttpResponseMessage signIn = await anchor.Client.PostAsync(
            "/auth/sign-in",
            new StringContent(
                JsonSerializer.Serialize(new { username = name, password }),
                System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, signIn.StatusCode);
        Assert.Equal("pending", (await Json(signIn)).GetProperty("status").GetString());
    }

    [Theory]
    [InlineData("", "a-long-enough-password")]
    [InlineData("no spaces allowed", "a-long-enough-password")]
    [InlineData("fine-name", "short")]
    [InlineData("fine-name", "")]
    public async Task A_username_or_password_that_will_not_do_is_refused(string username, string password)
    {
        HttpResponseMessage response = await anchor.Client.PostAsync("/auth/register", Body(username, password));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("bad_request", Code(await Json(response)));
    }

    [Fact]
    public async Task A_username_somebody_already_has_is_refused_rather_than_taken()
    {
        string name = "taken" + Guid.NewGuid().ToString("N")[..8];
        await anchor.Client.PostAsync("/auth/register", Body(name, "a-long-enough-password"));

        HttpResponseMessage second = await anchor.Client.PostAsync("/auth/register", Body(name, "another-long-password"));

        // Never merged onto the existing account: matching a stranger onto somebody else's account by
        // name is the documented route to handing one person another's access.
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal("username_taken", Code(await Json(second)));
    }

    [Fact]
    public async Task Nothing_on_the_wire_can_ask_for_a_tier()
    {
        string name = "ambitious" + Guid.NewGuid().ToString("N")[..8];

        // The shape has no tier and no status, so a caller sending them is sending fields that bind
        // to nothing. Asserted rather than assumed, because "the DTO does not have it" is exactly the
        // kind of thing a later edit quietly changes.
        var content = new StringContent(
            JsonSerializer.Serialize(new
            {
                username = name,
                password = "a-long-enough-password",
                tier = "admin",
                status = "active",
            }),
            System.Text.Encoding.UTF8, "application/json");

        Assert.Equal(HttpStatusCode.Created, (await anchor.Client.PostAsync("/auth/register", content)).StatusCode);

        KgsmUser? stored = await anchor.Store.FindByUsernameAsync(name);
        Assert.Equal(KgsmTier.None, stored!.Tier);
        Assert.Equal(UserStatus.Pending, stored.Status);
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
    public async Task A_member_that_does_not_hold_the_accounts_creates_none()
    {
        await anchor.StandingBy("some-other-anchor", async () =>
        {
            // Writing here would create an account the holder has never heard of and will overwrite
            // at the next snapshot — an account somebody was told they had, that quietly stops
            // existing.
            HttpResponseMessage response = await anchor.Client.PostAsync(
                "/auth/register", Body("standby" + Guid.NewGuid().ToString("N")[..8], "a-long-enough-password"));

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal("not_the_anchor", Code(await Json(response)));
        });
    }
}
