using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Cluster;
using TheKrystalShip.Auth.Journal;
using TheKrystalShip.Auth.Minting;
using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// Applications outside KGSM: registered by the host command and by the admin surface, their manifests
/// pulled into the catalog, their tokens audienced to them and listing the actions their roles grant, and
/// their confidential clients authenticating at <c>/token</c>.
/// </summary>
/// <remarks>
/// Each test registers an application of its own, with a fresh id, because the store is shared across the
/// collection. The manifests are served by a real HTTP listener on the loopback, which is what the daemon
/// reads them from on a host.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class ApplicationTests(AnchorFixture anchor) : IAsyncLifetime
{
    private const string Password = "a long enough password";

    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private ManifestServer _manifests = null!;

    public async Task InitializeAsync() => _manifests = await ManifestServer.StartAsync();

    public async Task DisposeAsync() => await _manifests.DisposeAsync();

    // ── Plumbing ──────────────────────────────────────────────────────────────

    private static string NewId() => "tst" + Guid.NewGuid().ToString("N")[..8];

    private static string Manifest(string component, string version = "1.0.0", string? requires = null, params (string Id, string Title, bool Self)[] actions) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            component,
            version,
            actions = actions.Select(a => new Dictionary<string, object?>
            {
                ["id"] = a.Id,
                ["title"] = a.Title,
                ["effect"] = "execute",
                ["scope"] = "cluster",
                ["self"] = a.Self ? true : null,
            }).ToArray(),
            requires = requires is null
                ? Array.Empty<object>()
                : [new { action = requires, scope = "cluster", why = "because" }],
        });

    /// <summary>The three actions every test application declares, the last of them a self action.</summary>
    private string ServeStandardManifest(string id) =>
        _manifests.Serve(id, Manifest(id, actions: [("watch", "Watch", false), ("download", "Download", false), ("history", "Own history", true)]));

    private AnchorOptions CommandOptions() => AnchorOptions.FromSettings(new AnchorSettings
    {
        UserStorePath = Path.Combine(anchor.Root, "users.db"),
        SessionStorePath = Path.Combine(anchor.Root, "sessions.db"),
        ClusterId = AnchorFixture.ClusterId,
        Issuer = AnchorFixture.Issuer,
        PanelOrigins = AnchorFixture.PanelUrl,
    });

    private async Task<(int Exit, string Output)> CommandAsync(params string[] args)
    {
        var output = new StringWriter();
        int exit = await ApplicationCommand.RunAsync(args, CommandOptions(), output);
        return (exit, output.ToString());
    }

    /// <summary>The daemon's view of an application, waited for: a command's write reaches it by the generation.</summary>
    private async Task<Application> DaemonSeesAsync(string id)
    {
        var registry = anchor.Service<ApplicationRegistry>();
        for (int attempt = 0; attempt < 50; attempt++)
        {
            if (registry.Find(id) is { } application)
                return application;
            await Task.Delay(100);
        }

        throw new InvalidOperationException($"the daemon never saw {id}");
    }

    private async Task<string> OwnerBearerAsync() => (await anchor.SignedInAsync(owner: true, prefix: "apps-owner")).Session.Access;

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string bearer, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null)
            request.Content = JsonContent.Create(body, options: Wire);
        return await anchor.Client.SendAsync(request);
    }

    private static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static JsonElement Claims(string jwt) => Part(jwt, 1);

    private static JsonElement Header(string jwt) => Part(jwt, 0);

    private static JsonElement Part(string jwt, int index)
    {
        string part = jwt.Split('.')[index].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + (4 - part.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(part)).RootElement;
    }

    private static string[] Actions(string jwt) =>
        [.. Claims(jwt).GetProperty(ApplicationClaims.Actions).EnumerateArray().Select(e => e.GetString()!)];

    /// <summary>Register an application with a public client by the admin surface, its manifest served.</summary>
    private async Task<(string Id, string Client, string Redirect)> PublicApplicationAsync(string? audience = null)
    {
        string id = NewId();
        string client = id + "-site";
        string redirect = $"https://{id}.test/signin";

        HttpResponseMessage response = await SendAsync(HttpMethod.Post, ApplicationEndpoints.Route, await OwnerBearerAsync(), new
        {
            id,
            name = "Test " + id,
            audience,
            manifestUrl = ServeStandardManifest(id),
            clients = new[] { new { clientId = client, redirectUris = new[] { redirect } } },
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (id, client, redirect);
    }

    /// <summary>A role holding <paramref name="actions"/>, assigned to <paramref name="user"/> across the organization.</summary>
    private async Task GrantAsync(KgsmUser user, params string[] actions)
    {
        string owner = (await anchor.SeedAsync("grantor-" + Guid.NewGuid().ToString("N")[..8], Password, owner: true)).UserId;
        async Task<AuthorityWrite> Apply(AuthorityEdit edit) =>
            await anchor.Store.ApplyAsync(owner, edit, await anchor.Store.VersionAsync(), DateTimeOffset.UtcNow);

        string permission = (await Apply(new CreatePermission("P-" + Guid.NewGuid().ToString("N")[..8]))).CreatedId!;
        await Apply(new SetPermissionActions(permission, actions.ToHashSet(StringComparer.Ordinal)));
        string role = (await Apply(new CreateRole("R-" + Guid.NewGuid().ToString("N")[..8]))).CreatedId!;
        await Apply(new SetRolePermissions(role, new HashSet<string> { permission }));
        await Apply(new Assign(user.UserId, role, AccessScope.Cluster));
    }

    private sealed record Pkce(string Verifier, string Challenge);

    private static Pkce NewPkce()
    {
        string verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return new Pkce(verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A browser signs <paramref name="user"/> in for <paramref name="client"/> and comes back with a code.</summary>
    private async Task<string> CodeAsync(KgsmUser user, string client, string redirect, Pkce pkce)
    {
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
        return QueryHelpers.ParseQuery(answer.Headers.Location!.Query)["code"].ToString();
    }

    private async Task<HttpResponseMessage> TokenAsync(
        Dictionary<string, string> form, (string Id, string Secret)? basic = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/token") { Content = new FormUrlEncodedContent(form) };
        if (basic is { } credentials)
        {
            string pair = Uri.EscapeDataString(credentials.Id) + ":" + Uri.EscapeDataString(credentials.Secret);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(pair)));
        }
        return await anchor.Client.SendAsync(request);
    }

    private static Dictionary<string, string> CodeForm(string code, string client, string redirect, Pkce pkce) => new()
    {
        ["grant_type"] = "authorization_code",
        ["code"] = code,
        ["redirect_uri"] = redirect,
        ["client_id"] = client,
        ["code_verifier"] = pkce.Verifier,
    };

    private static Dictionary<string, string> RefreshForm(string refresh) => new()
    {
        ["grant_type"] = "refresh_token",
        ["refresh_token"] = refresh,
    };

    /// <summary>
    /// What a resource server outside KGSM checks — the issuer, the key, ES256 and its own audience — and
    /// nothing else: the plain OpenID Connect validation an application's API performs.
    /// </summary>
    private async Task<bool> ApplicationAcceptsAsync(string token, string audience)
    {
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = AnchorFixture.Issuer,
            ValidAudience = audience,
            IssuerSigningKey = anchor.Service<EcdsaSessionSigner>().VerificationKey,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            ValidateLifetime = true,
        };
        return (await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters)).IsValid;
    }

    /// <summary>What a KGSM member has been told about its cluster's sessions.</summary>
    private sealed record ClusterKeys(string? Audience, string? Issuer, IReadOnlyList<SecurityKey> Keys) : IClusterSessionKeys;

    private async Task<bool> KgsmMemberAcceptsAsync(string token)
    {
        var keys = new ClusterKeys(AnchorFixture.ClusterId, AnchorFixture.Issuer,
            SessionKeys.VerificationKeysFrom(anchor.Service<EcdsaSessionSigner>().PublicKeys));
        return (await new JsonWebTokenHandler().ValidateTokenAsync(token, ClusterSessionValidation.Accepting(keys))).IsValid;
    }

    private async Task<IReadOnlyList<CatalogEntry>> DeclaredByAsync(string id) =>
        [.. (await anchor.Store.CatalogAsync()).Where(e => e.DeclaredBy.Any(d => d.Member == Application.CatalogMemberPrefix + id))];

    // ── Registering ───────────────────────────────────────────────────────────

    [Fact]
    public async Task The_host_command_registers_an_application_and_pulls_its_manifest_unmapped()
    {
        string id = NewId();
        string manifest = ServeStandardManifest(id);

        (int exit, string output) = await CommandAsync(
            "app", "add", id, "--name", "Command app", "--manifest", manifest,
            "--client-id", id + "-site", "--redirect", $"https://{id}.test/signin");

        Assert.Equal(0, exit);
        Assert.Contains("manifest read: 3 action(s)", output);

        Application seen = await DaemonSeesAsync(id);
        Assert.Equal(id, seen.Audience);
        Assert.Equal(TimeSpan.FromMinutes(5), seen.AccessLifetime);
        Assert.Equal(id, anchor.Service<ClientRegistry>().Find(id + "-site")!.ApplicationId);

        IReadOnlyList<CatalogEntry> declared = await DeclaredByAsync(id);
        Assert.Equal([$"{id}:download", $"{id}:history", $"{id}:watch"], declared.Select(e => e.Action.Id));

        AuthoritySnapshot snapshot = await anchor.Store.LoadAsync();
        Assert.DoesNotContain(snapshot.Permissions.Values, p => p.Actions.Any(a => a.StartsWith(id + ":", StringComparison.Ordinal)));

        JsonElement line = Assert.Single(anchor.Journal(AuthEvents.ApplicationChanged),
            e => e.GetProperty("Data").GetProperty("Id").GetString() == id
                 && e.GetProperty("Data").GetProperty("Client").ValueKind == JsonValueKind.Null);
        Assert.Equal($"local:{Environment.UserName}", line.GetProperty("Actor").GetString());
    }

    [Fact]
    public async Task The_admin_surface_registers_an_application_and_shows_its_secret_once()
    {
        string id = NewId();
        string bearer = await OwnerBearerAsync();

        HttpResponseMessage response = await SendAsync(HttpMethod.Post, ApplicationEndpoints.Route, bearer, new
        {
            id,
            name = "Surface app",
            audience = id + "-api",
            manifestUrl = ServeStandardManifest(id),
            clients = new object[]
            {
                new { clientId = id + "-site", redirectUris = new[] { $"https://{id}.test/signin" } },
                new { clientId = id + "-api", confidential = true },
            },
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        JsonElement body = await Json(response);
        JsonElement secret = Assert.Single(body.GetProperty("secrets").EnumerateArray());
        Assert.Equal(id + "-api", secret.GetProperty("clientId").GetString());
        Assert.True(secret.GetProperty("secret").GetString()!.Length >= 43);
        Assert.Equal(3, body.GetProperty("application").GetProperty("manifest").GetProperty("actions").GetInt32());
        Assert.Equal(ApplicationClaims.Actions, body.GetProperty("application").GetProperty("actionsClaim").GetString());

        Assert.Equal(3, (await DeclaredByAsync(id)).Count);

        // Listed afterwards with no secret in any form.
        string list = await (await SendAsync(HttpMethod.Get, ApplicationEndpoints.Route, bearer)).Content.ReadAsStringAsync();
        Assert.Contains(id + "-api", list);
        Assert.DoesNotContain(secret.GetProperty("secret").GetString()!, list);
        Assert.DoesNotContain(ProviderCookies.Hash(secret.GetProperty("secret").GetString()!), list);

        Assert.Contains(anchor.Journal(AuthEvents.ApplicationChanged),
            e => e.GetProperty("Data").GetProperty("Client").GetString() == id + "-api"
                 && e.GetProperty("Origin").GetString() == AnchorJournal.OriginUi);
    }

    [Fact]
    public async Task Administering_applications_takes_its_own_action_and_is_published()
    {
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(prefix: "apps-nobody");
        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(HttpMethod.Get, ApplicationEndpoints.Route, session.Access)).StatusCode);

        JsonElement operations = await Json(await anchor.Client.GetAsync("/auth/cluster/operations"));
        Assert.Contains(operations.GetProperty("operations").EnumerateArray(),
            o => o.GetProperty("method").GetString() == "POST"
                 && o.GetProperty("route").GetString() == ApplicationEndpoints.Route
                 && o.GetProperty("action").GetString() == AuthActions.ApplicationsManage);
    }

    [Fact]
    public async Task KGSM_and_its_namespaces_are_not_application_ids()
    {
        string bearer = await OwnerBearerAsync();
        foreach (string id in (string[])[Application.KgsmId, ActionIds.AuthComponent])
        {
            HttpResponseMessage response = await SendAsync(HttpMethod.Post, ApplicationEndpoints.Route, bearer,
                new { id, name = "Impostor" });
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        }

        HttpResponseMessage builtIn = await SendAsync(HttpMethod.Delete, ApplicationEndpoints.Route + "/kgsm", bearer);
        Assert.Equal(HttpStatusCode.Conflict, builtIn.StatusCode);

        HttpResponseMessage clusterAudience = await SendAsync(HttpMethod.Post, ApplicationEndpoints.Route, bearer,
            new { id = NewId(), name = "Borrower", audience = AnchorFixture.ClusterId });
        Assert.Equal(HttpStatusCode.BadRequest, clusterAudience.StatusCode);
    }

    [Fact]
    public async Task A_manifest_outside_its_application_s_namespace_is_refused_whole()
    {
        string id = NewId();
        string other = _manifests.Serve(id + "-other", Manifest("kgsm", actions: [("server.stop", "Stop", false)]));
        string foreign = _manifests.Serve(id + "-foreign", Manifest(id + "x", actions: [("watch", "Watch", false)]));
        string requiring = _manifests.Serve(id + "-requires", Manifest(id, requires: "kgsm:server.stop", actions: [("watch", "Watch", false)]));

        (int exit, string output) = await CommandAsync("app", "add", id, "--name", "Refused", "--manifest", other);
        Assert.Equal(0, exit);
        Assert.Contains("manifest not taken", output);

        Assert.Equal(0, (await CommandAsync("app", "set", id, "--manifest", foreign)).Exit);
        Assert.Equal(0, (await CommandAsync("app", "set", id, "--manifest", requiring)).Exit);

        string instanceScoped = _manifests.Serve(id + "-instance", Manifest(id, actions: [("watch", "Watch", false)])
            .Replace("\"cluster\"", "\"instance\"", StringComparison.Ordinal));
        Assert.Equal(0, (await CommandAsync("app", "set", id, "--manifest", instanceScoped)).Exit);

        Assert.Empty(await DeclaredByAsync(id));
        Assert.DoesNotContain((await anchor.Store.CatalogAsync()), e => e.Action.Id == "kgsm:server.stop"
            && e.DeclaredBy.Any(d => d.Member.StartsWith(Application.CatalogMemberPrefix, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task A_report_from_the_bus_under_an_application_s_name_is_refused()
    {
        string id = NewId();
        var report = new MemberCatalogReport(false,
            [new ActionManifest(1, id, "1.0.0", [new ManifestAction("watch", "Watch", "read", "cluster", null)], [])],
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var envelope = new TheKrystalShip.KGSM.Cluster.Messaging.ClusterEnvelope(
            Guid.NewGuid().ToString("N"), AuthorityMessages.CatalogDeclared, Application.CatalogMemberPrefix + id,
            DateTimeOffset.UtcNow, JsonSerializer.SerializeToElement(report, AccessJsonContext.Default.MemberCatalogReport));

        await new CatalogDeclaredHandler(anchor.Service<AuthorityIntake>(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<CatalogDeclaredHandler>.Instance)
            .HandleAsync(envelope, CancellationToken.None);

        Assert.Empty(await DeclaredByAsync(id));
    }

    [Fact]
    public async Task Removing_an_application_takes_its_actions_and_its_sessions()
    {
        (string id, string client, string redirect) = await PublicApplicationAsync();
        KgsmUser user = await anchor.SeedAsync("leaver-" + Guid.NewGuid().ToString("N")[..8], Password);
        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await TokenAsync(CodeForm(await CodeAsync(user, client, redirect, pkce), client, redirect, pkce)));

        Assert.Equal(0, (await CommandAsync("app", "remove", id)).Exit);
        await Task.Delay(1100);

        Assert.Empty(await DeclaredByAsync(id));
        Assert.Null(anchor.Service<ClientRegistry>().Find(client));
        HttpResponseMessage refresh = await TokenAsync(RefreshForm(tokens.GetProperty("refresh_token").GetString()!));
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
        Assert.Contains(anchor.Journal(AuthEvents.ApplicationRemoved), e => e.GetProperty("Data").GetProperty("Id").GetString() == id);
    }

    // ── Its tokens ────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_token_lists_exactly_the_actions_its_roles_grant_and_refresh_evaluates_again()
    {
        (string id, string client, string redirect) = await PublicApplicationAsync();
        KgsmUser user = await anchor.SeedAsync("viewer-" + Guid.NewGuid().ToString("N")[..8], Password);
        await GrantAsync(user, $"{id}:watch");

        Pkce pkce = NewPkce();
        HttpResponseMessage exchanged = await TokenAsync(CodeForm(await CodeAsync(user, client, redirect, pkce), client, redirect, pkce));
        Assert.Equal(HttpStatusCode.OK, exchanged.StatusCode);
        JsonElement tokens = await Json(exchanged);
        string access = tokens.GetProperty("access_token").GetString()!;

        // The self action is held by every active person; download is held by nobody yet.
        Assert.Equal([$"{id}:history", $"{id}:watch"], Actions(access));

        JsonElement claims = Claims(access);
        Assert.Equal(id, claims.GetProperty("aud").GetString());
        Assert.Equal(user.UserId, claims.GetProperty("sub").GetString());
        Assert.Equal(client, claims.GetProperty("client_id").GetString());
        Assert.Equal(AnchorFixture.Issuer, claims.GetProperty("iss").GetString());
        Assert.Equal(300, claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64());
        Assert.Equal(300, tokens.GetProperty("expires_in").GetInt64(), tolerance: 2);
        Assert.Equal(ApplicationClaims.AccessTokenType, Header(access).GetProperty("typ").GetString());

        // The id_token beside it names the same person the same way.
        Assert.Equal(user.UserId, Claims(tokens.GetProperty("id_token").GetString()!).GetProperty("sub").GetString());

        await GrantAsync(user, $"{id}:download");
        HttpResponseMessage refreshed = await TokenAsync(RefreshForm(tokens.GetProperty("refresh_token").GetString()!));
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        string next = (await Json(refreshed)).GetProperty("access_token").GetString()!;

        Assert.Equal([$"{id}:download", $"{id}:history", $"{id}:watch"], Actions(next));
        Assert.Equal(id, Claims(next).GetProperty("aud").GetString());
    }

    [Fact]
    public async Task An_application_s_lifetime_is_its_own_setting()
    {
        (string id, string client, string redirect) = await PublicApplicationAsync();
        Assert.Equal(0, (await CommandAsync("app", "set", id, "--lifetime", "2")).Exit);
        await Task.Delay(1100);

        KgsmUser user = await anchor.SeedAsync("brief-" + Guid.NewGuid().ToString("N")[..8], Password);
        Pkce pkce = NewPkce();
        string access = (await Json(await TokenAsync(CodeForm(await CodeAsync(user, client, redirect, pkce), client, redirect, pkce))))
            .GetProperty("access_token").GetString()!;

        JsonElement claims = Claims(access);
        Assert.Equal(120, claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64());
    }

    [Fact]
    public async Task One_application_s_token_is_refused_at_every_other()
    {
        (string id, string client, string redirect) = await PublicApplicationAsync(audience: null);
        KgsmUser user = await anchor.SeedAsync("crosser-" + Guid.NewGuid().ToString("N")[..8], Password);
        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await TokenAsync(CodeForm(await CodeAsync(user, client, redirect, pkce), client, redirect, pkce)));
        string access = tokens.GetProperty("access_token").GetString()!;
        string refresh = tokens.GetProperty("refresh_token").GetString()!;

        // Its own resource server takes it, and nothing else does.
        Assert.True(await ApplicationAcceptsAsync(access, id));
        Assert.False(await KgsmMemberAcceptsAsync(access));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await SendAsync(HttpMethod.Get, "/auth/cluster/authority", access)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(HttpMethod.Get, "/me/access", access)).StatusCode);

        // Its refresh token is this provider's alone, and no resource server takes it as a bearer.
        Assert.False(await ApplicationAcceptsAsync(refresh, id));
        Assert.False(await KgsmMemberAcceptsAsync(refresh));

        // KGSM's session is refused by the application.
        (_, AnchorFixture.Session kgsm) = await anchor.SignedInAsync(prefix: "kgsm-crosser");
        Assert.True(await KgsmMemberAcceptsAsync(kgsm.Access));
        Assert.False(await ApplicationAcceptsAsync(kgsm.Access, id));
    }

    [Fact]
    public async Task KGSM_s_tokens_carry_no_actions_and_keep_the_cluster_audience_and_lifetime()
    {
        var registry = anchor.Service<ClientRegistry>();
        const string panel = "apps-kgsm-panel";
        const string redirect = "https://apps-kgsm.test/callback";
        if (registry.Find(panel) is null)
        {
            await registry.RegisterAsync(new ClientRegistration(panel, "KGSM panel", [redirect], []),
                DateTimeOffset.UtcNow, CancellationToken.None);
        }

        KgsmUser user = await anchor.SeedAsync("kgsm-" + Guid.NewGuid().ToString("N")[..8], Password);
        Pkce pkce = NewPkce();
        JsonElement tokens = await Json(await TokenAsync(CodeForm(await CodeAsync(user, panel, redirect, pkce), panel, redirect, pkce)));
        string access = tokens.GetProperty("access_token").GetString()!;

        JsonElement claims = Claims(access);
        Assert.Equal(AnchorFixture.ClusterId, claims.GetProperty("aud").GetString());
        Assert.False(claims.TryGetProperty(ApplicationClaims.Actions, out _));
        Assert.Equal(user.AsIdentity().Handle, claims.GetProperty("sub").GetString());
        Assert.Equal(15 * 60, claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64());
        Assert.True(await KgsmMemberAcceptsAsync(access));

        string next = (await Json(await TokenAsync(RefreshForm(tokens.GetProperty("refresh_token").GetString()!))))
            .GetProperty("access_token").GetString()!;
        Assert.Equal(AnchorFixture.ClusterId, Claims(next).GetProperty("aud").GetString());
        Assert.True(await KgsmMemberAcceptsAsync(next));
    }

    // ── Confidential clients ──────────────────────────────────────────────────

    private async Task<(string Id, string Client, string Redirect, string Secret)> ConfidentialApplicationAsync()
    {
        string id = NewId();
        string client = id + "-api";
        string redirect = $"https://{id}.test/callback";

        (int exit, string output) = await CommandAsync(
            "app", "add", id, "--name", "Confidential", "--manifest", ServeStandardManifest(id),
            "--client-id", client, "--redirect", redirect, "--confidential");
        Assert.Equal(0, exit);
        string secret = output.Split('\n').Single(l => l.StartsWith($"client {client} secret: ", StringComparison.Ordinal))
            [$"client {client} secret: ".Length..].Split(' ')[0];

        await DaemonSeesAsync(id);
        for (int attempt = 0; attempt < 50 && anchor.Service<ClientRegistry>().Find(client) is null; attempt++)
            await Task.Delay(100);
        return (id, client, redirect, secret);
    }

    [Fact]
    public async Task A_confidential_client_authenticates_with_basic_and_a_wrong_secret_is_invalid_client()
    {
        (string id, string client, string redirect, string secret) = await ConfidentialApplicationAsync();
        KgsmUser user = await anchor.SeedAsync("basic-" + Guid.NewGuid().ToString("N")[..8], Password);
        Pkce pkce = NewPkce();
        string code = await CodeAsync(user, client, redirect, pkce);

        // Refused before the code is looked at, so the same code still serves the client that can prove itself.
        HttpResponseMessage wrong = await TokenAsync(CodeForm(code, client, redirect, pkce), basic: (client, "not-the-secret"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal("invalid_client", (await Json(wrong)).GetProperty("error").GetString());
        Assert.Equal("Basic", Assert.Single(wrong.Headers.WwwAuthenticate).Scheme);

        HttpResponseMessage none = await TokenAsync(CodeForm(code, client, redirect, pkce));
        Assert.Equal(HttpStatusCode.Unauthorized, none.StatusCode);
        Assert.Equal("invalid_client", (await Json(none)).GetProperty("error").GetString());

        HttpResponseMessage both = await TokenAsync(
            new Dictionary<string, string>(CodeForm(code, client, redirect, pkce)) { ["client_secret"] = secret },
            basic: (client, secret));
        Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);
        Assert.Equal("invalid_request", (await Json(both)).GetProperty("error").GetString());

        HttpResponseMessage right = await TokenAsync(CodeForm(code, client, redirect, pkce), basic: (client, secret));
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);
        JsonElement tokens = await Json(right);
        Assert.Equal(id, Claims(tokens.GetProperty("access_token").GetString()!).GetProperty("aud").GetString());

        // Its session is continued only by the client proving itself again.
        string refresh = tokens.GetProperty("refresh_token").GetString()!;
        HttpResponseMessage anonymous = await TokenAsync(RefreshForm(refresh));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Equal("invalid_client", (await Json(anonymous)).GetProperty("error").GetString());

        HttpResponseMessage continued = await TokenAsync(RefreshForm(refresh), basic: (client, secret));
        Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
    }

    [Fact]
    public async Task A_confidential_client_authenticates_in_the_form_and_a_wrong_secret_has_no_challenge()
    {
        (_, string client, string redirect, string secret) = await ConfidentialApplicationAsync();
        KgsmUser user = await anchor.SeedAsync("post-" + Guid.NewGuid().ToString("N")[..8], Password);
        Pkce pkce = NewPkce();
        string code = await CodeAsync(user, client, redirect, pkce);

        HttpResponseMessage wrong = await TokenAsync(
            new Dictionary<string, string>(CodeForm(code, client, redirect, pkce)) { ["client_secret"] = "not-the-secret" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal("invalid_client", (await Json(wrong)).GetProperty("error").GetString());
        Assert.Empty(wrong.Headers.WwwAuthenticate);

        HttpResponseMessage right = await TokenAsync(
            new Dictionary<string, string>(CodeForm(code, client, redirect, pkce)) { ["client_secret"] = secret });
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);
    }

    [Fact]
    public async Task Rotating_a_secret_ends_the_old_one()
    {
        (string id, string client, string redirect, string old) = await ConfidentialApplicationAsync();

        HttpResponseMessage rotated = await SendAsync(HttpMethod.Post,
            $"{ApplicationEndpoints.Route}/{id}/clients/{client}/secret", await OwnerBearerAsync());
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        string secret = Assert.Single((await Json(rotated)).GetProperty("secrets").EnumerateArray()).GetProperty("secret").GetString()!;
        Assert.NotEqual(old, secret);

        KgsmUser user = await anchor.SeedAsync("rotated-" + Guid.NewGuid().ToString("N")[..8], Password);
        Pkce pkce = NewPkce();
        string code = await CodeAsync(user, client, redirect, pkce);

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await TokenAsync(CodeForm(code, client, redirect, pkce), basic: (client, old))).StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await TokenAsync(CodeForm(code, client, redirect, pkce), basic: (client, secret))).StatusCode);
        Assert.Contains(anchor.Journal(AuthEvents.ClientSecretRotated), e => e.GetProperty("Data").GetProperty("Client").GetString() == client);
    }

    [Fact]
    public async Task A_secret_presented_for_a_public_client_is_refused()
    {
        (_, string client, string redirect) = await PublicApplicationAsync();
        KgsmUser user = await anchor.SeedAsync("public-" + Guid.NewGuid().ToString("N")[..8], Password);
        Pkce pkce = NewPkce();
        string code = await CodeAsync(user, client, redirect, pkce);

        HttpResponseMessage response = await TokenAsync(
            new Dictionary<string, string>(CodeForm(code, client, redirect, pkce)) { ["client_secret"] = "anything" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", (await Json(response)).GetProperty("error").GetString());
    }

    /// <summary>Serves manifests on the loopback, as an application serves its own.</summary>
    internal sealed class ManifestServer : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly Dictionary<string, string> _documents = new(StringComparer.Ordinal);
        private readonly string _base;

        private ManifestServer(WebApplication app, string address)
        {
            _app = app;
            _base = address;
        }

        public static async Task<ManifestServer> StartAsync()
        {
            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            WebApplication app = builder.Build();

            ManifestServer? server = null;
            app.MapGet("/{name}/.well-known/tks-actions.json", (HttpContext ctx) =>
            {
                string name = (string)ctx.Request.RouteValues["name"]!;
                lock (server!._documents)
                {
                    return server._documents.TryGetValue(name, out string? json)
                        ? Results.Text(json, "application/json")
                        : Results.NotFound();
                }
            });

            await app.StartAsync();
            server = new ManifestServer(app, app.Urls.First().TrimEnd('/'));
            return server;
        }

        /// <summary>Serve <paramref name="json"/> and say where.</summary>
        public string Serve(string name, string json)
        {
            lock (_documents)
                _documents[name] = json;
            return $"{_base}/{name}/.well-known/tks-actions.json";
        }

        public async ValueTask DisposeAsync() => await _app.DisposeAsync();
    }
}
