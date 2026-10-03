using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// What the provider's own pages stand on: the documents the anchor serves them in, the calls they make
/// against the request in flight, and the account page's rules about proving it is you.
/// </summary>
/// <remarks>
/// The fixture points the bundle at a folder under its root that is empty unless a test writes one, so
/// every other suite meets the built-in floor. A test that installs pages removes them when it ends.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class ProviderPagesTests(AnchorFixture anchor)
{
    private const string Client = "pages-client";
    private const string Redirect = "https://pages.test/callback";

    private async Task RegisterClientAsync()
    {
        var registry = anchor.Service<ClientRegistry>();
        if (registry.Find(Client) is null)
        {
            await registry.RegisterAsync(new ClientRegistration(Client, "Pages client", [Redirect], []),
                DateTimeOffset.UtcNow, CancellationToken.None);
        }
    }

    private static string AuthorizeUrl()
    {
        string verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = Client, ["redirect_uri"] = Redirect, ["response_type"] = "code", ["scope"] = "openid",
            ["state"] = "s", ["code_challenge"] = challenge, ["code_challenge_method"] = "S256",
        });
    }

    private static HttpRequestMessage Json(HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("Sec-Fetch-Site", "same-origin");
        request.Headers.Add("Accept", "application/json");
        if (body is not null)
            request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        return request;
    }

    private static async Task<JsonElement> Read(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private async Task<(KgsmUser User, string Password)> AccountAsync(UserStatus status = UserStatus.Active)
    {
        string username = "pages-" + Guid.NewGuid().ToString("N")[..10];
        const string password = "a long enough password";
        return (await anchor.SeedAsync(username, password, owner: false, status), password);
    }

    private string UiRoot => Path.Combine(anchor.Root, "ui");

    private async Task WithBundleAsync(Func<Task> body)
    {
        Directory.CreateDirectory(Path.Combine(UiRoot, "assets"));
        File.WriteAllText(Path.Combine(UiRoot, "auth-sign-in.html"),
            "<!doctype html><title>bundle sign-in</title><form method=\"post\" action=\"/authorize/credentials\"></form>"
            + ProviderBundle.ProvidersMarker);
        File.WriteAllText(Path.Combine(UiRoot, "auth-wait.html"), "<!doctype html><title>bundle wait</title>");
        File.WriteAllText(Path.Combine(UiRoot, "auth-account.html"), "<!doctype html><title>bundle account</title>");
        File.WriteAllText(Path.Combine(UiRoot, "assets", "app-1234.js"), "console.log(1)");
        try
        {
            await body();
        }
        finally
        {
            Directory.Delete(UiRoot, recursive: true);
        }
    }

    private void Sql(string statement)
    {
        using var connection = new SqliteConnection($"Data Source={Path.Combine(anchor.Root, "sessions.db")}");
        connection.Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText = statement;
        cmd.ExecuteNonQuery();
    }

    // ── The documents ─────────────────────────────────────────────────────────

    [Fact]
    public async Task With_the_bundle_installed_its_document_is_served_with_the_providers_filled_in()
    {
        await RegisterClientAsync();
        await WithBundleAsync(async () =>
        {
            using HttpClient browser = anchor.Following();
            HttpResponseMessage page = await browser.GetAsync(AuthorizeUrl());
            string html = await page.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            Assert.Contains("bundle sign-in", html, StringComparison.Ordinal);
            Assert.Contains("href=\"/authorize/discord\"", html, StringComparison.Ordinal);
            Assert.DoesNotContain(ProviderBundle.ProvidersMarker, html, StringComparison.Ordinal);
            Assert.Contains("form-action 'self' https://pages.test",
                page.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task A_failed_plain_post_answers_with_the_reason_on_the_built_in_page()
    {
        // A browser that posted the form rather than fetching is one where the application did not run,
        // and the static document has nowhere to put the reason.
        await RegisterClientAsync();
        (KgsmUser user, _) = await AccountAsync();
        await WithBundleAsync(async () =>
        {
            using HttpClient browser = anchor.Following();
            await browser.GetAsync(AuthorizeUrl());
            var post = new HttpRequestMessage(HttpMethod.Post, "/authorize/credentials")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["username"] = user.Username, ["password"] = "not the password",
                }),
            };
            post.Headers.Add("Sec-Fetch-Site", "same-origin");
            HttpResponseMessage refused = await browser.SendAsync(post);
            string html = await refused.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
            Assert.Contains("do not match an account", html, StringComparison.Ordinal);
            Assert.DoesNotContain("bundle sign-in", html, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Assets_are_served_under_ui_and_nothing_outside_the_bundle_is()
    {
        await WithBundleAsync(async () =>
        {
            HttpResponseMessage asset = await anchor.Client.GetAsync("/ui/assets/app-1234.js");
            Assert.Equal(HttpStatusCode.OK, asset.StatusCode);
            Assert.Contains("immutable", asset.Headers.CacheControl!.ToString(), StringComparison.Ordinal);

            foreach (string attempt in (string[])["/ui/../signing.pem", "/ui/%2e%2e/signing.pem", "/ui/..%2fsigning.pem"])
                Assert.Equal(HttpStatusCode.NotFound, (await anchor.Client.GetAsync(attempt)).StatusCode);
        });
    }

    [Fact]
    public async Task Without_the_bundle_the_floor_still_signs_somebody_in_and_names_it()
    {
        await RegisterClientAsync();
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = anchor.Following();

        HttpResponseMessage page = await browser.GetAsync(AuthorizeUrl());
        Assert.Contains("kgsm-web-auth", await page.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var post = new HttpRequestMessage(HttpMethod.Post, "/authorize/credentials")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = user.Username, ["password"] = password,
            }),
        };
        post.Headers.Add("Sec-Fetch-Site", "same-origin");
        HttpResponseMessage signedIn = await browser.SendAsync(post);
        Assert.Equal(HttpStatusCode.SeeOther, signedIn.StatusCode);
        Assert.StartsWith(Redirect + "?code=", signedIn.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    // ── The request in flight, for the pages ──────────────────────────────────

    [Fact]
    public async Task The_context_names_the_client_and_what_the_page_offers()
    {
        await RegisterClientAsync();
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl());

        JsonElement context = await Read(await browser.SendAsync(Json(HttpMethod.Get, "/authorize/context")));
        Assert.Equal("Pages client", context.GetProperty("client").GetProperty("name").GetString());
        Assert.Contains("discord", context.GetProperty("providers").EnumerateArray().Select(p => p.GetString()));
        Assert.True(context.GetProperty("registration").GetBoolean());
        Assert.False(context.TryGetProperty("account", out _));
    }

    [Fact]
    public async Task Somebody_registered_at_the_provider_waits_and_is_returned_to_the_client_once_approved()
    {
        await RegisterClientAsync();
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl());
        string username = "pages-reg-" + Guid.NewGuid().ToString("N")[..8];

        HttpResponseMessage registered = await browser.SendAsync(Json(HttpMethod.Post, "/authorize/register",
            new { username, password = "a password to register with" }));
        Assert.Equal(HttpStatusCode.OK, registered.StatusCode);
        Assert.Equal("/authorize/wait", (await Read(registered)).GetProperty("wait").GetString());

        JsonElement waiting = await Read(await browser.SendAsync(Json(HttpMethod.Get, "/authorize/wait")));
        Assert.Equal("/authorize/wait", waiting.GetProperty("wait").GetString());

        JsonElement context = await Read(await browser.SendAsync(Json(HttpMethod.Get, "/authorize/context")));
        Assert.Equal("pending", context.GetProperty("account").GetProperty("status").GetString());

        KgsmUser account = (await anchor.Store.FindByUsernameAsync(username))!;
        await anchor.Store.UpdateAsync(account with
        {
            Status = UserStatus.Active, Origin = AccountOrigin.Admitted, Updated = DateTimeOffset.UtcNow,
        });
        await Task.Delay(TimeSpan.FromSeconds(6));

        JsonElement approved = await Read(await browser.SendAsync(Json(HttpMethod.Get, "/authorize/wait")));
        Assert.StartsWith(Redirect + "?code=", approved.GetProperty("redirect").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_cross_site_registration_is_refused()
    {
        await RegisterClientAsync();
        using HttpClient browser = anchor.Following();
        await browser.GetAsync(AuthorizeUrl());

        HttpRequestMessage post = Json(HttpMethod.Post, "/authorize/register",
            new { username = "pages-xs-" + Guid.NewGuid().ToString("N")[..6], password = "a password to register with" });
        post.Headers.Remove("Sec-Fetch-Site");
        post.Headers.Add("Sec-Fetch-Site", "cross-site");
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(post)).StatusCode);
    }

    // ── The account page ──────────────────────────────────────────────────────

    /// <summary>A browser signed in at the anchor through the account page's own sign-in.</summary>
    private async Task<HttpClient> SignedInAsync(KgsmUser user, string password)
    {
        HttpClient browser = anchor.Following();
        HttpResponseMessage first = await browser.GetAsync("/account");
        Assert.Equal("/account/sign-in", first.Headers.Location!.ToString());

        HttpResponseMessage page = await browser.GetAsync("/account/sign-in");
        Assert.Contains("your account", await page.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var post = new HttpRequestMessage(HttpMethod.Post, "/authorize/credentials")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = user.Username, ["password"] = password,
            }),
        };
        post.Headers.Add("Sec-Fetch-Site", "same-origin");
        HttpResponseMessage back = await browser.SendAsync(post);

        // Back to the page, and no code minted for it.
        Assert.Equal(HttpStatusCode.SeeOther, back.StatusCode);
        Assert.Equal(AnchorFixture.Issuer + "/account", back.Headers.Location!.ToString());
        return browser;
    }

    private void AgeTheProof() =>
        Sql($"UPDATE sessions SET credential_at = '{DateTimeOffset.UtcNow.AddHours(-1):O}' WHERE kind = 'provider';");

    [Fact]
    public async Task The_account_page_reads_the_account_this_browser_is_signed_in_to()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        JsonElement me = await Read(await browser.SendAsync(Json(HttpMethod.Get, "/account/me")));
        Assert.Equal(user.UserId, me.GetProperty("userId").GetString());
        Assert.True(me.GetProperty("hasPassword").GetBoolean());
        Assert.Equal(JsonValueKind.String, me.GetProperty("freshUntil").ValueKind);
        JsonElement current = Assert.Single(me.GetProperty("sessions").EnumerateArray(), s => s.GetProperty("current").GetBoolean());
        Assert.Equal("provider", current.GetProperty("kind").GetString());
    }

    /// <summary>Attach an external identity to an account, as a provider sign-in would have.</summary>
    private async Task<string> AttachAsync(KgsmUser user, string handle)
    {
        string credentialId = UserIds.NewCredentialId();
        await anchor.Store.AddCredentialAsync(new UserCredential(
            credentialId, user.UserId, CredentialKind.Identity, handle, Secret: null,
            Label: "discord", Created: DateTimeOffset.UtcNow, LastUsed: null));
        return credentialId;
    }

    [Fact]
    public async Task Your_own_password_is_changed_here_recorded_as_yours_and_held_to_the_floor()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        HttpResponseMessage shortOne = await browser.SendAsync(
            Json(HttpMethod.Post, "/account/password", new { password = "short" }));

        // The floor is read from the one constant every door reads, so it cannot drift low in one of
        // them. The message says the number, because a refusal that does not is a guess.
        Assert.Equal(HttpStatusCode.BadRequest, shortOne.StatusCode);
        JsonElement error = (await Read(shortOne)).GetProperty("error");
        Assert.Equal("password_too_short", error.GetProperty("code").GetString());
        Assert.Contains(Passwords.MinLength.ToString(), error.GetProperty("message").GetString());

        Assert.Equal(HttpStatusCode.NoContent, (await browser.SendAsync(
            Json(HttpMethod.Post, "/account/password", new { password = "a different long password" }))).StatusCode);

        // The whole point of recording it: somebody else setting your password reads completely
        // differently from you setting it, and a line that could not tell them apart would report a
        // takeover and a routine rotation identically.
        JsonElement data = Assert.Single(
            anchor.Journal(TheKrystalShip.KGSM.Auth.Journal.AuthEvents.UserPasswordChanged),
            e => e.GetProperty("Data").GetProperty("Username").GetString() == user.Username)
            .GetProperty("Data");
        Assert.True(data.GetProperty("ByHolder").GetBoolean());
    }

    [Fact]
    public async Task The_ways_into_an_account_are_listed_with_the_id_a_detach_names()
    {
        (KgsmUser user, string password) = await AccountAsync();
        await AttachAsync(user, "discord:1234567890");
        using HttpClient browser = await SignedInAsync(user, password);

        JsonElement me = await Read(await browser.SendAsync(Json(HttpMethod.Get, "/account/me")));
        JsonElement identity = Assert.Single(me.GetProperty("identities").EnumerateArray());

        // The credential id, because a detach is addressed by id — an id a caller cannot learn makes
        // the door unreachable.
        Assert.False(string.IsNullOrEmpty(identity.GetProperty("id").GetString()));
        Assert.Equal("discord", identity.GetProperty("provider").GetString());
        Assert.Equal("discord:1234567890", identity.GetProperty("handle").GetString());
    }

    [Fact]
    public async Task Detaching_an_identity_records_which_one_it_was()
    {
        (KgsmUser user, string password) = await AccountAsync();
        string credentialId = await AttachAsync(user, "discord:2233445566");
        using HttpClient browser = await SignedInAsync(user, password);

        Assert.Equal(HttpStatusCode.NoContent,
            (await browser.SendAsync(Json(HttpMethod.Delete, $"/account/identities/{credentialId}"))).StatusCode);

        JsonElement data = Assert.Single(
            anchor.Journal(TheKrystalShip.KGSM.Auth.Journal.AuthEvents.IdentityUnlinked),
            e => e.GetProperty("Data").GetProperty("Username").GetString() == user.Username)
            .GetProperty("Data");

        // Read before it was detached: afterwards there is nothing left to say which identity this was.
        Assert.Equal("discord", data.GetProperty("Provider").GetString());
        Assert.Equal("discord:2233445566", data.GetProperty("Handle").GetString());
    }

    [Fact]
    public async Task The_last_way_into_an_account_is_refused()
    {
        (KgsmUser user, _) = await AccountAsync();
        string credentialId = await AttachAsync(user, "discord:9988776655");

        // The password goes, leaving the identity as the only way in — and the browser signed in with
        // that identity, since a sign-in is known by the handle it arrived with.
        UserCredential held = (await anchor.Store.ListCredentialsAsync(user.UserId))
            .Single(c => c.Kind == CredentialKind.Password);
        await anchor.Store.RemoveCredentialAsync(held.CredentialId);
        AnchorFixture.Session session = await anchor.SignInAsync(
            user, arrivedAs: new KgsmIdentity("discord", "9988776655", user.Username, user.Username, null, []));

        HttpResponseMessage response = await anchor.Client.SendAsync(
            session.AtTheAccountPage(HttpMethod.Delete, $"/account/identities/{credentialId}"));

        // An account with nothing attached is one its own holder cannot sign in to, and only somebody
        // else can rescue.
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.NotEmpty(await anchor.Store.ListCredentialsAsync(user.UserId));
    }

    [Fact]
    public async Task Somebody_elses_credential_answers_the_same_as_one_that_does_not_exist()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        (KgsmUser stranger, _) = await AccountAsync();
        string theirs = await AttachAsync(stranger, "discord:1122334455");

        HttpResponseMessage response = await browser.SendAsync(Json(HttpMethod.Delete, $"/account/identities/{theirs}"));

        // 404, the same as an id that is not real. Telling those apart would say whether an id exists,
        // and the id is the whole of what a caller supplies.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains(await anchor.Store.ListCredentialsAsync(stranger.UserId), c => c.CredentialId == theirs);
    }

    [Fact]
    public async Task A_password_change_asks_for_the_password_when_the_proof_is_old_and_not_otherwise()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        // Just signed in: recent, so the change goes through without asking.
        Assert.Equal(HttpStatusCode.NoContent, (await browser.SendAsync(
            Json(HttpMethod.Post, "/account/password", new { password = "a second long password" }))).StatusCode);

        AgeTheProof();
        HttpResponseMessage asked = await browser.SendAsync(
            Json(HttpMethod.Post, "/account/password", new { password = "a third long password" }));
        Assert.Equal(HttpStatusCode.Forbidden, asked.StatusCode);
        Assert.Equal("reauth_required", (await Read(asked)).GetProperty("error").GetProperty("code").GetString());

        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(
            Json(HttpMethod.Post, "/account/reauth", new { password = "not it" }))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(
            Json(HttpMethod.Post, "/account/reauth", new { password = "a second long password" }))).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await browser.SendAsync(
            Json(HttpMethod.Post, "/account/password", new { password = "a third long password" }))).StatusCode);
    }

    [Fact]
    public async Task Linking_asks_for_the_password_when_the_proof_is_old_and_not_otherwise()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        HttpResponseMessage started = await browser.SendAsync(Json(HttpMethod.Post, "/account/identities/discord/start"));
        Assert.Equal(HttpStatusCode.OK, started.StatusCode);
        Assert.StartsWith("https://discord.com/", (await Read(started)).GetProperty("url").GetString(), StringComparison.Ordinal);
        Assert.Contains(started.Headers.GetValues("Set-Cookie"), c => c.StartsWith("kgsm_link_ticket=", StringComparison.Ordinal));

        AgeTheProof();
        HttpResponseMessage asked = await browser.SendAsync(Json(HttpMethod.Post, "/account/identities/discord/start"));
        Assert.Equal(HttpStatusCode.Forbidden, asked.StatusCode);
        Assert.Equal("reauth_required", (await Read(asked)).GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_link_begun_on_the_account_page_returns_to_the_account_page()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        JsonElement started = await Read(await browser.SendAsync(Json(HttpMethod.Post, "/account/identities/discord/start")));
        string state = QueryHelpers.ParseQuery(new Uri(started.GetProperty("url").GetString()!).Query)["state"]!;

        // Denied at the provider's screen: no code comes back.
        HttpResponseMessage back = await browser.GetAsync($"/auth/identities/discord/callback?state={Uri.EscapeDataString(state)}");
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        Assert.StartsWith("/account#link_error=", back.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_link_callback_with_no_ticket_attaches_nothing()
    {
        // A forged or replayed return. Refused before any exchange is attempted, so a stranger cannot
        // spend somebody else's authorization code against an account — and the reason goes back to the
        // account page as link_error, which a page never reads as a failed sign-in.
        HttpResponseMessage response = await anchor.Following()
            .GetAsync("/auth/identities/discord/callback?code=whatever&state=whatever");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/account#link_error=invalid_state", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task A_provider_reauth_round_trip_returns_to_the_account_page_and_signs_nobody_in()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        HttpResponseMessage start = await browser.GetAsync("/account/reauth/discord");
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        Uri toProvider = start.Headers.Location!;
        Assert.Equal("consent", QueryHelpers.ParseQuery(toProvider.Query)["prompt"]);
        string state = QueryHelpers.ParseQuery(toProvider.Query)["state"]!;

        HttpResponseMessage back = await browser.GetAsync($"/auth/discord/callback?state={Uri.EscapeDataString(state)}");
        Assert.Equal("/account#reauth_error=login_required", back.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Account_writes_are_same_origin_only()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        HttpRequestMessage forged = Json(HttpMethod.Post, "/account/password", new { password = "a hijacked password" });
        forged.Headers.Remove("Sec-Fetch-Site");
        forged.Headers.Add("Sec-Fetch-Site", "cross-site");
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(forged)).StatusCode);
    }

    [Fact]
    public async Task Signing_out_everywhere_from_the_account_page_ends_this_browser_too()
    {
        (KgsmUser user, string password) = await AccountAsync();
        using HttpClient browser = await SignedInAsync(user, password);

        JsonElement ended = await Read(await browser.SendAsync(Json(HttpMethod.Post, "/account/sessions/revoke", new { all = true })));
        Assert.True(ended.GetProperty("revoked").GetInt32() >= 1);

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.SendAsync(Json(HttpMethod.Get, "/account/me"))).StatusCode);
        Assert.Equal("/account/sign-in", (await browser.GetAsync("/account")).Headers.Location!.ToString());
    }
}
