using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using Microsoft.IdentityModel.JsonWebTokens;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// Changing what proves an account.
/// </summary>
/// <remarks>
/// <para>
/// These doors ask for a credential again and the rest of the anchor does not, so what they are
/// really about is the gap between holding a session and having proved you own it. Every case here is
/// decided <em>before</em> anything reaches a provider — a test that needed discord.com would be
/// testing discord.com.
/// </para>
/// <para>
/// The pair that matters most is attach and detach existing together. A detach with no attach behind
/// it strands somebody: signing in again with the provider they just removed does not give the
/// account back, it creates a second one.
/// </para>
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class IdentityDoorTests(AnchorFixture anchor)
{
    private const string Long = "a long enough password";
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private sealed record Session(string Bearer, string Sid);

    private async Task<Session> SignInAsync(string username, string password)
    {
        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password }, Wire);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string bearer = (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("token").GetString()!;

        var token = new JsonWebToken(bearer);
        return new Session(bearer, token.GetClaim(KgsmAuthClaims.SessionId).Value);
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string path, string bearer, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null)
            request.Content = JsonContent.Create(body, options: Wire);

        return await anchor.Client.SendAsync(request);
    }

    /// <summary>A session that has gone cold — the week-old tab, without waiting a week.</summary>
    private void Lapse(string sid) => anchor.Service<ReauthGate>().Forget(sid);

    private async Task<string> AttachAsync(KgsmUser user, string provider, string handle)
    {
        string credentialId = UserIds.NewCredentialId();
        await anchor.Store.AddCredentialAsync(new UserCredential(
            credentialId, user.UserId, CredentialKind.Identity, handle, Secret: null,
            Label: provider, Created: DateTimeOffset.UtcNow, LastUsed: null));

        return credentialId;
    }

    // ── Arriving counts as proving ────────────────────────────────────────────

    [Fact]
    public async Task Signing_in_proves_a_credential_so_a_new_arrival_is_not_asked_again()
    {
        string username = Unique("arrived-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username, Long);

        JsonElement body = await (await SendAsync(HttpMethod.Get, "/auth/identities", session.Bearer))
            .Content.ReadFromJsonAsync<JsonElement>();

        JsonElement reauth = body.GetProperty("reauth");
        Assert.True(reauth.GetProperty("fresh").GetBoolean());
        Assert.True(reauth.GetProperty("expiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow);

        // The window is stated so a surface can say how long they have rather than guessing.
        Assert.True(reauth.GetProperty("windowMinutes").GetInt32() > 0);
    }

    [Fact]
    public async Task A_session_that_has_gone_cold_is_asked_again()
    {
        string username = Unique("returned-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username, Long);

        Lapse(session.Sid);

        JsonElement body = await (await SendAsync(HttpMethod.Get, "/auth/identities", session.Bearer))
            .Content.ReadFromJsonAsync<JsonElement>();

        Assert.False(body.GetProperty("reauth").GetProperty("fresh").GetBoolean());

        // Absent rather than null: this surface omits what it has no value for, so a client reads
        // `fresh` and never has to tell a missing key from a null one.
        Assert.False(body.GetProperty("reauth").TryGetProperty("expiresAt", out _));

        // Read BEFORE anything is attempted, so a surface asks for the password rather than bouncing
        // somebody to a provider and refusing them on the way back.
        Assert.Equal(
            HttpStatusCode.Forbidden,
            (await SendAsync(HttpMethod.Post, "/auth/identities/discord/start", session.Bearer)).StatusCode);
    }

    [Fact]
    public async Task Proving_the_password_again_reopens_the_window()
    {
        string username = Unique("proves-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username, Long);
        Lapse(session.Sid);

        HttpResponseMessage wrong = await SendAsync(
            HttpMethod.Post, "/auth/reauth", session.Bearer, new { password = "not it" });
        Assert.Equal(HttpStatusCode.Forbidden, wrong.StatusCode);

        HttpResponseMessage right = await SendAsync(
            HttpMethod.Post, "/auth/reauth", session.Bearer, new { password = Long });
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);

        JsonElement proof = await right.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(proof.GetProperty("expiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task An_account_with_no_password_is_told_to_sign_in_rather_than_refused()
    {
        string username = Unique("passwordless-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        await AttachAsync(user, "discord", "discord:" + Guid.NewGuid().ToString("N")[..12]);

        Session session = await SignInAsync(username, Long);

        UserCredential password = (await anchor.Store.ListCredentialsAsync(user.UserId))
            .Single(c => c.Kind == CredentialKind.Password);
        await anchor.Store.RemoveCredentialAsync(password.CredentialId);

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/reauth", session.Bearer, new { password = Long });

        // A distinct answer from a wrong password, because the way through is different: there is
        // nothing here to prove, and signing in again stamps the session it mints.
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        JsonElement error = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("no_password", error.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Reauth_is_bounded_by_the_same_lockout_a_sign_in_is()
    {
        string username = Unique("hammered-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username, Long);

        HttpStatusCode last = HttpStatusCode.OK;
        for (int attempt = 0; attempt < 6; attempt++)
        {
            last = (await SendAsync(HttpMethod.Post, "/auth/reauth", session.Bearer,
                new { password = $"wrong-{attempt}" })).StatusCode;
        }

        // This is the same password check the sign-in door makes. An unbounded one here would be the
        // way around the lockout rather than a second door with its own rules.
        Assert.Equal(HttpStatusCode.TooManyRequests, last);
    }

    // ── Attaching ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Starting_a_link_hands_back_an_authorize_url_and_a_one_time_ticket()
    {
        string username = Unique("attaches-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username, Long);

        HttpResponseMessage response =
            await SendAsync(HttpMethod.Post, "/auth/identities/discord/start", session.Bearer);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string url = (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("url").GetString()!;

        // `consent`, never the silent `none` a sign-in uses: somebody attaching an account is
        // choosing WHICH account, and a silent bounce attaches whichever one that browser happens to
        // be signed into without ever showing them which.
        Assert.Contains("prompt=consent", url);

        // The link callback, not the sign-in one. Coming back through the sign-in door would mint a
        // session for the arriving identity instead of attaching it.
        Assert.Contains(
            Uri.EscapeDataString(AnchorFixture.SignInUrl + "/auth/identities/discord/callback"), url);

        // Only the opaque ticket rides in the cookie. A browser carrying its own account id would be
        // the authority on whose account is being attached to.
        string cookie = Assert.Single(
            response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("kgsm_link_ticket="));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(username, cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_second_account_at_the_same_provider_is_refused()
    {
        string username = Unique("doubled-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        await AttachAsync(user, "discord", "discord:" + Guid.NewGuid().ToString("N")[..12]);

        Session session = await SignInAsync(username, Long);

        HttpResponseMessage response =
            await SendAsync(HttpMethod.Post, "/auth/identities/discord/start", session.Bearer);

        // The store's own constraint runs the other way — an identity belongs to exactly one account,
        // table-wide — so it would happily allow a second Discord account here and never say which
        // one signs this person in.
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        JsonElement error = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("already_linked", error.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_provider_this_cluster_does_not_offer_is_named_as_such()
    {
        string username = Unique("nosuch-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username, Long);

        HttpResponseMessage response =
            await SendAsync(HttpMethod.Post, "/auth/identities/nowhere/start", session.Bearer);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        JsonElement error = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("auth_unconfigured", error.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_callback_with_no_ticket_attaches_nothing()
    {
        // A forged or replayed return. Refused before any exchange is attempted, so a stranger cannot
        // spend somebody else's authorization code against an account.
        HttpResponseMessage response = await anchor.Following()
            .GetAsync("/auth/identities/discord/callback?code=whatever&state=whatever");

        // Redirected back to the panel with the reason in the fragment rather than left on a JSON
        // error page at an address nobody typed.
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains("error=invalid_state", response.Headers.Location!.Fragment);
    }

    // ── Detaching ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Detaching_asks_for_the_password_the_same_way_attaching_does()
    {
        string username = Unique("detaching-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        string credentialId = await AttachAsync(
            user, "discord", "discord:" + Guid.NewGuid().ToString("N")[..12]);

        Session session = await SignInAsync(username, Long);
        Lapse(session.Sid);

        HttpResponseMessage cold = await SendAsync(
            HttpMethod.Delete, $"/auth/identities/{credentialId}", session.Bearer);

        // Detaching is the half that locks somebody out rather than the half that lets somebody in,
        // and a session somebody else is holding is exactly what would be used for it.
        Assert.Equal(HttpStatusCode.Forbidden, cold.StatusCode);
        JsonElement error = await cold.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("reauth_required", error.GetProperty("error").GetProperty("code").GetString());

        await SendAsync(HttpMethod.Post, "/auth/reauth", session.Bearer, new { password = Long });

        Assert.Equal(HttpStatusCode.NoContent,
            (await SendAsync(HttpMethod.Delete, $"/auth/identities/{credentialId}", session.Bearer))
                .StatusCode);
    }

    [Fact]
    public async Task Signing_out_ends_the_proof_with_the_session()
    {
        string username = Unique("gone-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username, Long);

        Assert.True(anchor.Service<ReauthGate>().IsFresh(session.Sid));

        await SendAsync(HttpMethod.Post, "/auth/session/sign-out", session.Bearer);

        // A proof belongs to a session. Left standing, a session id reissued or replayed would arrive
        // already trusted to change what proves the account.
        Assert.False(anchor.Service<ReauthGate>().IsFresh(session.Sid));
    }

    // ── What a browser is allowed to send ─────────────────────────────────────

    [Fact]
    public async Task Every_method_a_door_here_answers_is_allowed_across_origins()
    {
        using var preflight = new HttpRequestMessage(HttpMethod.Options, "/auth/identities/anything");
        preflight.Headers.Add("Origin", AnchorFixture.PanelUrl);
        preflight.Headers.Add("Access-Control-Request-Method", "DELETE");

        HttpResponseMessage response = await anchor.Client.SendAsync(preflight);
        string allowed = response.Headers.GetValues("Access-Control-Allow-Methods").Single();

        // A method missing here is refused by the browser at the preflight, which this daemon never
        // sees and no log records — so the door reads as unreachable rather than as not permitted.
        // Detaching an identity and deleting an account are both DELETE, and both are reached from a
        // panel on another origin.
        foreach (string method in new[] { "GET", "POST", "PATCH", "DELETE", "OPTIONS" })
            Assert.Contains(method, allowed);
    }

    // ── What a surface is told ────────────────────────────────────────────────

    [Fact]
    public async Task The_providers_a_surface_may_offer_are_listed_with_whether_each_is_attached()
    {
        string username = Unique("offered-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username, Long);

        JsonElement before = await (await SendAsync(HttpMethod.Get, "/auth/identities", session.Bearer))
            .Content.ReadFromJsonAsync<JsonElement>();

        JsonElement discord = before.GetProperty("providers").EnumerateArray()
            .Single(p => p.GetProperty("provider").GetString() == "discord");

        Assert.True(discord.GetProperty("configured").GetBoolean());
        Assert.False(discord.GetProperty("linked").GetBoolean());

        await AttachAsync(user, "discord", "discord:" + Guid.NewGuid().ToString("N")[..12]);

        JsonElement after = await (await SendAsync(HttpMethod.Get, "/auth/identities", session.Bearer))
            .Content.ReadFromJsonAsync<JsonElement>();

        Assert.True(after.GetProperty("providers").EnumerateArray()
            .Single(p => p.GetProperty("provider").GetString() == "discord")
            .GetProperty("linked").GetBoolean());
    }
}
