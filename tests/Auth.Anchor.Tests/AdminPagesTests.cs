using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.WebUtilities;

using TheKrystalShip.Auth.Minting;
using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// tks-auth's own admin pages: a built-in public client on the issuer's origin, signed in to like any
/// client, holding a token for the provider's own application that its admin routes accept — and that no
/// other application's token stands in for.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AdminPagesTests(AnchorFixture anchor)
{
    private const string Password = "a long enough password";
    private const string Pages = AnchorFixture.Issuer + Application.ProviderPagesPath;

    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    // ── Plumbing ──────────────────────────────────────────────────────────────

    private sealed record Pkce(string Verifier, string Challenge);

    private static Pkce NewPkce()
    {
        string verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return new Pkce(verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static JsonElement Claims(string jwt)
    {
        string part = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + (4 - part.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(part)).RootElement;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string bearer, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null)
            request.Content = JsonContent.Create(body, options: Wire);
        return await anchor.Client.SendAsync(request);
    }

    /// <summary>A browser signs <paramref name="user"/> in for a client and the code is exchanged.</summary>
    private async Task<JsonElement> SignInAsync(KgsmUser user, string client, string redirect)
    {
        Pkce pkce = NewPkce();
        HttpClient browser = anchor.Following();
        string authorize = QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = client,
            ["redirect_uri"] = redirect,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["state"] = "s",
            ["code_challenge"] = pkce.Challenge,
            ["code_challenge_method"] = "S256",
        });
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(authorize)).StatusCode);

        var post = new HttpRequestMessage(HttpMethod.Post, "/authorize/credentials")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = user.Username,
                ["password"] = Password,
            }),
        };
        post.Headers.Add("Sec-Fetch-Site", "same-origin");
        HttpResponseMessage answer = await browser.SendAsync(post);
        Assert.Equal(HttpStatusCode.SeeOther, answer.StatusCode);
        Assert.StartsWith(redirect, answer.Headers.Location!.ToString(), StringComparison.Ordinal);
        string code = QueryHelpers.ParseQuery(answer.Headers.Location!.Query)["code"].ToString();

        HttpResponseMessage token = await anchor.Client.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirect,
            ["client_id"] = client,
            ["code_verifier"] = pkce.Verifier,
        }));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        return JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement;
    }

    private async Task<KgsmUser> AccountAsync(bool owner) =>
        await anchor.SeedAsync("admin-pages-" + Guid.NewGuid().ToString("N")[..8], Password, owner);

    private string UiRoot => Path.Combine(anchor.Root, "ui");

    // ── The client ────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_admin_pages_are_a_built_in_client_on_the_issuer_s_origin_that_nothing_replaces()
    {
        var clients = anchor.Service<ClientRegistry>();
        RegisteredClient client = clients.Find(Application.ProviderClientId)!;

        Assert.Equal([Pages], client.RedirectUris);
        Assert.Equal([Pages], client.PostLogoutRedirectUris);
        Assert.False(client.Confidential);
        Assert.Same(anchor.Service<ApplicationRegistry>().Provider, anchor.Service<ApplicationRegistry>().Of(client));
        Assert.DoesNotContain(clients.Kgsm, c => c.ClientId == Application.ProviderClientId);

        string owner = (await anchor.SignedInAsync(owner: true, prefix: "admin-pages-owner")).Session.Access;
        HttpResponseMessage over = await SendAsync(HttpMethod.Post, "/auth/cluster/clients", owner, new
        {
            clientId = Application.ProviderClientId,
            name = "Somebody else",
            redirectUris = new[] { "https://elsewhere.test/admin/" },
        });
        Assert.Equal(HttpStatusCode.Conflict, over.StatusCode);
        Assert.NotEqual(HttpStatusCode.NoContent,
            (await SendAsync(HttpMethod.Delete, "/auth/cluster/clients/" + Application.ProviderClientId, owner)).StatusCode);
    }

    [Fact]
    public async Task The_provider_s_own_application_is_listed_built_in_and_its_audience_is_nobody_else_s()
    {
        string owner = (await anchor.SignedInAsync(owner: true, prefix: "admin-pages-owner")).Session.Access;

        JsonElement list = JsonDocument.Parse(
            await (await SendAsync(HttpMethod.Get, ApplicationEndpoints.Route, owner)).Content.ReadAsStringAsync()).RootElement;
        JsonElement provider = list.GetProperty("data").EnumerateArray().Single(a => a.GetProperty("id").GetString() == "auth");
        Assert.Equal(Application.ProviderAudience, provider.GetProperty("audience").GetString());
        Assert.Equal(ApplicationSources.Builtin, provider.GetProperty("source").GetString());
        Assert.Equal(Application.ProviderClientId,
            provider.GetProperty("clients").EnumerateArray().Single().GetProperty("clientId").GetString());

        HttpResponseMessage change = await SendAsync(HttpMethod.Patch, ApplicationEndpoints.Route + "/auth", owner, new { name = "Mine" });
        Assert.Equal(HttpStatusCode.Conflict, change.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await SendAsync(HttpMethod.Delete, ApplicationEndpoints.Route + "/auth", owner)).StatusCode);

        string id = "tst" + Guid.NewGuid().ToString("N")[..8];
        HttpResponseMessage taken = await SendAsync(HttpMethod.Post, ApplicationEndpoints.Route, owner,
            new { id, name = "Taker", audience = Application.ProviderAudience });
        Assert.Equal(HttpStatusCode.BadRequest, taken.StatusCode);
    }

    // ── The session ───────────────────────────────────────────────────────────

    [Fact]
    public async Task An_admin_pages_session_is_a_caller_at_the_admin_routes_and_renews()
    {
        KgsmUser owner = await AccountAsync(owner: true);
        JsonElement tokens = await SignInAsync(owner, Application.ProviderClientId, Pages);
        string access = tokens.GetProperty("access_token").GetString()!;

        JsonElement claims = Claims(access);
        Assert.Equal(Application.ProviderAudience, claims.GetProperty("aud").GetString());
        Assert.Equal(owner.UserId, claims.GetProperty("sub").GetString());
        Assert.Equal(JsonValueKind.Array, claims.GetProperty(ApplicationClaims.Actions).ValueKind);

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Get, "/auth/cluster/users", access)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Get, "/auth/cluster/authority", access)).StatusCode);
        JsonElement me = JsonDocument.Parse(
            await (await SendAsync(HttpMethod.Get, "/me/access", access)).Content.ReadAsStringAsync()).RootElement;
        Assert.True(me.GetProperty("owner").GetBoolean());

        // A change made with it is the person's, as the journal names them.
        HttpResponseMessage made = await SendAsync(HttpMethod.Post, "/auth/cluster/users", access, new
        {
            username = "admin-made-" + Guid.NewGuid().ToString("N")[..8],
            password = Password,
            status = "active",
        });
        Assert.Equal(HttpStatusCode.Created, made.StatusCode);

        HttpResponseMessage renewed = await anchor.Client.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!,
            ["client_id"] = Application.ProviderClientId,
        }));
        Assert.Equal(HttpStatusCode.OK, renewed.StatusCode);
        string next = JsonDocument.Parse(await renewed.Content.ReadAsStringAsync()).RootElement.GetProperty("access_token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Get, "/auth/cluster/users", next)).StatusCode);
    }

    [Fact]
    public async Task Somebody_holding_no_auth_action_is_refused_the_admin_routes_with_the_pages_session()
    {
        KgsmUser person = await AccountAsync(owner: false);
        string access = (await SignInAsync(person, Application.ProviderClientId, Pages)).GetProperty("access_token").GetString()!;

        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(HttpMethod.Get, "/auth/cluster/users", access)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Get, "/me/access", access)).StatusCode);
    }

    [Fact]
    public async Task Another_application_s_token_is_no_caller_at_the_admin_routes()
    {
        string owner = (await anchor.SignedInAsync(owner: true, prefix: "admin-pages-owner")).Session.Access;
        string id = "tst" + Guid.NewGuid().ToString("N")[..8];
        string redirect = $"https://{id}.test/signin";
        HttpResponseMessage registered = await SendAsync(HttpMethod.Post, ApplicationEndpoints.Route, owner, new
        {
            id,
            name = "Test " + id,
            clients = new[] { new { clientId = id + "-site", redirectUris = new[] { redirect } } },
        });
        Assert.Equal(HttpStatusCode.Created, registered.StatusCode);

        KgsmUser person = await AccountAsync(owner: true);
        string access = (await SignInAsync(person, id + "-site", redirect)).GetProperty("access_token").GetString()!;

        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(HttpMethod.Get, "/auth/cluster/users", access)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(HttpMethod.Get, "/me/access", access)).StatusCode);
    }

    // ── The document ──────────────────────────────────────────────────────────

    [Fact]
    public async Task The_admin_document_is_served_under_the_provider_s_policy_and_only_when_installed()
    {
        using HttpClient browser = anchor.Following();

        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync(Application.ProviderPagesPath)).StatusCode);

        Directory.CreateDirectory(UiRoot);
        File.WriteAllText(Path.Combine(UiRoot, "admin.html"), "<!doctype html><title>bundle admin</title>");
        try
        {
            HttpResponseMessage page = await browser.GetAsync(Application.ProviderPagesPath + "?code=c&state=s");
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            Assert.Contains("bundle admin", await page.Content.ReadAsStringAsync(), StringComparison.Ordinal);

            string policy = page.Headers.GetValues("Content-Security-Policy").Single();
            Assert.Contains("script-src 'self'", policy, StringComparison.Ordinal);
            Assert.Contains("connect-src 'self'", policy, StringComparison.Ordinal);
            Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);

            Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/admin")).StatusCode);
        }
        finally
        {
            Directory.Delete(UiRoot, recursive: true);
        }
    }
}
