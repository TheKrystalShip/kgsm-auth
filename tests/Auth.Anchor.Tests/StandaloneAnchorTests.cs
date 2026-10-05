using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;
using TheKrystalShip.KGSM.Extensions;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// tks-auth started with no KGSM cluster configured: it founds itself, signs somebody in at its issuer,
/// and composes nothing of the KGSM module.
/// </summary>
/// <remarks>
/// <para>
/// Started through the daemon's own <c>Program</c>, like <see cref="AnchorFixture"/>, with no cluster
/// secret. In the anchor's collection because the daemon is configured through process environment
/// variables: they are set for this host while it is built and put back straight after, and no other
/// test in the collection runs meanwhile.
/// </para>
/// <para>
/// Every path is relocated into one temporary root, including the KGSM descriptor path and a
/// <c>kgsm</c> directory beneath it, so what the daemon wrote is exactly what is in that root.
/// </para>
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class StandaloneAnchorTests : IDisposable
{
    private const string Issuer = "https://auth.standalone.test";
    private const string Client = "standalone-app";
    private const string Redirect = "https://app.standalone.test/callback";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "tks-auth-standalone", Guid.NewGuid().ToString("N"));
    private readonly WebApplicationFactory<Program> _factory;

    private string KgsmRoot => Path.Combine(_root, "kgsm");

    public StandaloneAnchorTests()
    {
        Directory.CreateDirectory(_root);

        Dictionary<string, string?> environment = new()
        {
            ["Anchor__UserStorePath"] = Path.Combine(_root, "accounts.db"),
            ["Anchor__SessionStorePath"] = Path.Combine(_root, "sessions.db"),
            ["Anchor__SigningKeyPath"] = Path.Combine(_root, "signing.pem"),
            ["Anchor__ClusterId"] = "standalone-audience",
            ["Anchor__MemberId"] = "standalone-auth",
            ["Anchor__Issuer"] = Issuer,
            ["Anchor__PublicBaseUrl"] = Issuer,
            ["Anchor__PanelOrigins"] = null,
            ["Anchor__AllowSelfRegistration"] = null,
            ["Anchor__UiPath"] = Path.Combine(_root, "ui"),
            ["Anchor__ConfigDescriptorPath"] = Path.Combine(KgsmRoot, "anchors", "auth-anchor.json"),
            ["Anchor__ConfigOverridePath"] = Path.Combine(_root, "config-override.env"),
            [JournalServiceCollectionExtensions.StateRootVariable] = Path.Combine(_root, "state"),
            ["Cluster__Secret"] = null,
            ["Cluster__SecretPrevious"] = null,
            ["Cluster__FoundedPath"] = Path.Combine(KgsmRoot, "cluster-founded"),
        };

        Dictionary<string, string?> previous = environment.Keys.ToDictionary(k => k, Environment.GetEnvironmentVariable);
        try
        {
            foreach ((string key, string? value) in environment)
                Environment.SetEnvironmentVariable(key, value);

            _factory = new WebApplicationFactory<Program>();
            // Building the host is what reads the environment; after this the variables are the fixture's again.
            _ = _factory.Services;
        }
        finally
        {
            foreach ((string key, string? value) in previous)
                Environment.SetEnvironmentVariable(key, value);
        }
    }

    public void Dispose()
    {
        _factory.Dispose();
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A file the daemon still holds open. The temp tree is disposable either way.
        }
    }

    private T Service<T>() where T : notnull => _factory.Services.GetRequiredService<T>();

    [Fact]
    public void It_stands_alone_and_composes_nothing_of_the_KGSM_module()
    {
        AnchorRole role = Service<AnchorRole>();
        Assert.Equal(AnchorStanding.Standalone, role.Standing);
        Assert.True(role.IsAuthority);

        IServiceProvider services = _factory.Services;
        Assert.Null(services.GetService<ClusterOptions>());
        Assert.Null(services.GetService<MembersStore>());
        Assert.Null(services.GetService<IClusterBus>());
        Assert.Null(services.GetService<SelfPublications>());
        Assert.Null(services.GetService<TheKrystalShip.Auth.Cluster.AuthorityReporter>());
        Assert.Null(services.GetService<TheKrystalShip.Auth.Cluster.IAuthorityIntake>());
        Assert.Null(services.GetService<SessionBroadcast>());
        Assert.Null(services.GetService<AuthorityBroadcast>());
        Assert.Null(services.GetService<MemberTargets>());
        Assert.Empty(services.GetServices<IClusterMessageHandler>());
        Assert.Empty(services.GetServices<ISelfAddressSource>());

        Assert.IsType<StandaloneAnnouncements>(Service<ISessionAnnouncer>());
        Assert.IsType<StandaloneAnnouncements>(Service<IAuthorityAnnouncer>());

        string[] workers = [.. services.GetServices<IHostedService>().Select(s => s.GetType().FullName ?? "")];
        Assert.DoesNotContain(workers, w => w.StartsWith("TheKrystalShip.KGSM.", StringComparison.Ordinal));
        Assert.DoesNotContain(typeof(ClusterMembershipWorker).FullName, workers);
        Assert.DoesNotContain(typeof(MemberDepartureWorker).FullName, workers);
        Assert.DoesNotContain(typeof(AuthorityBroadcastWorker).FullName, workers);
        Assert.Contains(typeof(StandaloneCatalog).FullName, workers);
    }

    [Fact]
    public async Task It_serves_no_KGSM_door()
    {
        HttpClient client = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/auth/cluster/members")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/auth/cluster/snapshot")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/auth/cluster/public-key")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/auth/config")).StatusCode);

        // The provider's own doors are all there.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/.well-known/openid-configuration")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/cluster/operations")).StatusCode);
    }

    [Fact]
    public async Task Its_own_actions_are_in_its_catalog_and_nothing_else_is()
    {
        var store = Service<AnchorAuthority>().Store!;

        // The report goes in as the host starts; wait it out rather than race it.
        AuthoritySnapshot snapshot = await store.LoadAsync();
        for (int i = 0; i < 50 && !snapshot.Catalog.ContainsKey(AuthActions.RolesEdit); i++)
        {
            await Task.Delay(100);
            snapshot = await store.LoadAsync();
        }

        foreach (CatalogAction declared in AuthActions.Declared)
        {
            Assert.True(snapshot.Catalog.TryGetValue(declared.Id, out CatalogAction? held), $"{declared.Id} is not in the catalog");
            Assert.Equal(declared.Title, held!.Title);
            Assert.Equal(declared.Effect, held.Effect);
            Assert.Equal(declared.Scope, held.Scope);
        }

        // The component surface's actions are a cluster's; standalone there is no surface to grant them on.
        Assert.DoesNotContain(snapshot.Catalog.Keys, id => id.StartsWith("auth:config.", StringComparison.Ordinal));

        // A write owes the cluster nothing when there is none: the outbox is settled, not kept.
        Assert.Empty(await store.PendingAnnouncementsAsync());
    }

    [Fact]
    public async Task It_founds_itself_and_signs_the_Owner_in_at_its_issuer()
    {
        // The Owner, with its one-time password, as the first start on an empty store leaves it.
        string passwordFile = Service<AnchorOptions>().InitialAdminPasswordPath;
        Assert.StartsWith(_root, passwordFile, StringComparison.Ordinal);
        string[] lines = await File.ReadAllLinesAsync(passwordFile);
        string username = lines.Single(l => l.StartsWith("username:", StringComparison.Ordinal))["username:".Length..].Trim();
        string password = lines.Single(l => l.StartsWith("password:", StringComparison.Ordinal))["password:".Length..].Trim();
        Assert.Equal(FirstAdmin.DefaultUsername, username);

        SqliteAuthorityStore store = Service<AnchorAuthority>().Store!;
        KgsmUser owner = (await store.FindByUsernameAsync(username))!;
        Assert.True((await store.LoadAsync()).IsOwner(owner.UserId));

        // A client, registered by hand: with no cluster nothing announces one.
        var (outcome, _, problem) = await Service<ClientRegistry>().RegisterAsync(
            new ClientRegistration(Client, "Standalone app", [Redirect], []), DateTimeOffset.UtcNow, CancellationToken.None);
        Assert.True(outcome == ClientRegistry.RegisterOutcome.Registered, problem);

        // The authorization-code flow with PKCE, as a browser and a client library drive it.
        string verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        string challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        HttpClient browser = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        HttpResponseMessage page = await browser.GetAsync(QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = Client,
            ["redirect_uri"] = Redirect,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["state"] = "standalone-state",
            ["nonce"] = "standalone-nonce",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        }));
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);

        using var credentials = new HttpRequestMessage(HttpMethod.Post, "/authorize/credentials")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = username,
                ["password"] = password,
            }),
        };
        credentials.Headers.Add("Sec-Fetch-Site", "same-origin");
        HttpResponseMessage answer = await browser.SendAsync(credentials);
        Assert.Equal(HttpStatusCode.SeeOther, answer.StatusCode);

        Uri back = answer.Headers.Location!;
        Assert.StartsWith(Redirect + "?", back.ToString(), StringComparison.Ordinal);
        Dictionary<string, string> query = QueryHelpers.ParseQuery(back.Query).ToDictionary(kv => kv.Key, kv => kv.Value.ToString());
        Assert.Equal("standalone-state", query["state"]);
        Assert.Equal(Issuer, query["iss"]);

        HttpResponseMessage exchanged = await _factory.CreateClient().PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = query["code"],
                ["redirect_uri"] = Redirect,
                ["client_id"] = Client,
                ["code_verifier"] = verifier,
            }));
        Assert.Equal(HttpStatusCode.OK, exchanged.StatusCode);

        JsonElement tokens = JsonDocument.Parse(await exchanged.Content.ReadAsStringAsync()).RootElement;
        string access = tokens.GetProperty("access_token").GetString()!;
        Assert.False(string.IsNullOrEmpty(tokens.GetProperty("refresh_token").GetString()));

        JsonElement idToken = Claims(tokens.GetProperty("id_token").GetString()!);
        Assert.Equal(Issuer, idToken.GetProperty("iss").GetString());
        Assert.Equal(owner.UserId, idToken.GetProperty("sub").GetString());
        Assert.Equal(Client, idToken.GetProperty("aud").GetString());
        Assert.Equal("standalone-nonce", idToken.GetProperty("nonce").GetString());

        Assert.Equal(Issuer, Claims(access).GetProperty("iss").GetString());

        using var userinfo = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
        userinfo.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateClient().SendAsync(userinfo)).StatusCode);

        // Signing in is what the one-time password was for.
        Assert.False(File.Exists(passwordFile));

        // And through all of it, nothing KGSM's: no member store beside the sessions, nothing under the
        // KGSM paths this daemon was pointed at.
        Assert.False(File.Exists(Path.Combine(_root, "cluster.db")));
        Assert.False(Directory.Exists(KgsmRoot));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static JsonElement Claims(string jwt)
    {
        string payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(payload)).RootElement;
    }
}
