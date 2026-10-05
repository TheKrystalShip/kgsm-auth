using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Journal;
using TheKrystalShip.Auth.Minting;
using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// The token-exchange grant (RFC 8693): an Activity's Discord access token, and a bot acting for a Discord
/// user, each traded at <c>/token</c> by a confidential client for an application's access token.
/// </summary>
/// <remarks>
/// Discord is <see cref="FakeDiscord"/>, behind the directory's own typed client, so what is under test is
/// the composition that ships down to the request it sends. Each test registers its own application, with
/// fresh Discord ids, because the store and the journal are shared across the collection.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class TokenExchangeTests(AnchorFixture anchor) : IAsyncLifetime
{
    private const string Password = "a long enough password";

    private ApplicationTests.ManifestServer _manifests = null!;

    public async Task InitializeAsync() => _manifests = await ApplicationTests.ManifestServer.StartAsync();

    public async Task DisposeAsync() => await _manifests.DisposeAsync();

    // ── Plumbing ──────────────────────────────────────────────────────────────

    private static string NewId() => "tx" + Guid.NewGuid().ToString("N")[..8];

    /// <summary>A fresh Discord id, eighteen digits as Discord's are.</summary>
    private static string Snowflake() =>
        $"{RandomNumberGenerator.GetInt32(100_000_000, 1_000_000_000)}{RandomNumberGenerator.GetInt32(100_000_000, 1_000_000_000)}";

    private sealed record Registered(string Id, string Client, string Secret, string DiscordApplication);

    /// <summary>
    /// An application with one confidential client, registered by the host command, declaring
    /// <c>watch</c> and <c>download</c>; presenting one Discord application's tokens, and acting for Discord
    /// users when <paramref name="actForDiscord"/>.
    /// </summary>
    private async Task<Registered> ApplicationAsync(bool presentsDiscord = true, bool actForDiscord = false)
    {
        string id = NewId();
        string client = id + "-api";
        string discordApplication = Snowflake();
        string manifest = _manifests.Serve(id, JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            component = id,
            version = "1.0.0",
            actions = new[]
            {
                new { id = "watch", title = "Watch", effect = "execute", scope = "cluster" },
                new { id = "download", title = "Download", effect = "execute", scope = "cluster" },
            },
            requires = Array.Empty<object>(),
        }));

        List<string> args = ["app", "add", id, "--name", "Exchange " + id, "--manifest", manifest,
            "--client-id", client, "--confidential"];
        if (presentsDiscord)
            args.AddRange(["--discord-app", discordApplication]);
        if (actForDiscord)
            args.Add("--act-for-discord");

        var output = new StringWriter();
        int exit = await ApplicationCommand.RunAsync([.. args], AnchorOptions.FromSettings(new AnchorSettings
        {
            UserStorePath = Path.Combine(anchor.Root, "users.db"),
            SessionStorePath = Path.Combine(anchor.Root, "sessions.db"),
            ClusterId = AnchorFixture.ClusterId,
            Issuer = AnchorFixture.Issuer,
            PanelOrigins = AnchorFixture.PanelUrl,
        }), output);
        Assert.Equal(0, exit);

        string prefix = $"client {client} secret: ";
        string secret = output.ToString().Split('\n').Single(l => l.StartsWith(prefix, StringComparison.Ordinal))[prefix.Length..].Split(' ')[0];

        var registry = anchor.Service<ApplicationRegistry>();
        for (int attempt = 0; attempt < 50 && registry.Find(id) is null; attempt++)
            await Task.Delay(100);
        Assert.NotNull(registry.Find(id));

        return new Registered(id, client, secret, discordApplication);
    }

    /// <summary>An account holding a Discord identity, as a person who signed in with Discord holds one.</summary>
    private async Task<(KgsmUser User, string DiscordId)> DiscordAccountAsync(UserStatus status = UserStatus.Active)
    {
        string discordId = Snowflake();
        KgsmUser user = await anchor.SeedAsync("tx-" + Guid.NewGuid().ToString("N")[..10], Password, status: status);
        await anchor.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Identity,
            KgsmActor.Format(KgsmActorProvider.Discord, discordId), Secret: null, "discord-name", DateTimeOffset.UtcNow, null));
        return (user, discordId);
    }

    /// <summary>A role holding <paramref name="actions"/>, assigned to <paramref name="user"/> across the organization.</summary>
    private async Task GrantAsync(KgsmUser user, params string[] actions)
    {
        string owner = (await anchor.SeedAsync("tx-grantor-" + Guid.NewGuid().ToString("N")[..8], Password, owner: true)).UserId;
        async Task<AuthorityWrite> Apply(AuthorityEdit edit) =>
            await anchor.Store.ApplyAsync(owner, edit, await anchor.Store.VersionAsync(), DateTimeOffset.UtcNow);

        string permission = (await Apply(new CreatePermission("P-" + Guid.NewGuid().ToString("N")[..8]))).CreatedId!;
        await Apply(new SetPermissionActions(permission, actions.ToHashSet(StringComparer.Ordinal)));
        string role = (await Apply(new CreateRole("R-" + Guid.NewGuid().ToString("N")[..8]))).CreatedId!;
        await Apply(new SetRolePermissions(role, new HashSet<string> { permission }));
        await Apply(new Assign(user.UserId, role, AccessScope.Cluster));
    }

    private static Dictionary<string, string> Form(string subject, string type, params (string Key, string Value)[] more)
    {
        Dictionary<string, string> form = new()
        {
            ["grant_type"] = TokenExchange.GrantType,
            ["subject_token"] = subject,
            ["subject_token_type"] = type,
        };
        foreach ((string key, string value) in more)
            form[key] = value;
        return form;
    }

    private async Task<HttpResponseMessage> ExchangeAsync(Dictionary<string, string> form, (string Id, string Secret)? basic)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/token") { Content = new FormUrlEncodedContent(form) };
        if (basic is { } credentials)
        {
            string pair = Uri.EscapeDataString(credentials.Id) + ":" + Uri.EscapeDataString(credentials.Secret);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(pair)));
        }
        return await anchor.Client.SendAsync(request);
    }

    private Task<HttpResponseMessage> ExchangeAsync(Registered app, Dictionary<string, string> form) =>
        ExchangeAsync(form, (app.Client, app.Secret));

    private static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static JsonElement Part(string jwt, int index)
    {
        string part = jwt.Split('.')[index].Replace('-', '+').Replace('_', '/');
        part = part.PadRight(part.Length + (4 - part.Length % 4) % 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(part)).RootElement;
    }

    private static async Task AssertAccountRefusedAsync(HttpResponseMessage response, string status)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        JsonElement body = await Json(response);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        Assert.Equal(status, body.GetProperty("account_status").GetString());
        Assert.False(body.TryGetProperty("access_token", out _));
    }

    private static async Task AssertErrorAsync(HttpResponseMessage response, HttpStatusCode status, string error)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal(error, (await Json(response)).GetProperty("error").GetString());
    }

    /// <summary>The one line this application's exchanges wrote of <paramref name="type"/>.</summary>
    private JsonElement Line(string type, Registered app) =>
        Assert.Single(anchor.Journal(type), e => e.GetProperty("Data").GetProperty("Application").GetString() == app.Id).GetProperty("Data");

    // ── The Activity: a Discord access token ──────────────────────────────────

    [Fact]
    public async Task A_Discord_token_from_an_allowed_application_is_exchanged_for_the_account_s_token()
    {
        Registered app = await ApplicationAsync();
        (KgsmUser user, string discordId) = await DiscordAccountAsync();
        await GrantAsync(user, $"{app.Id}:watch");
        string token = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Issue(token, app.DiscordApplication, discordId, "haru");

        HttpResponseMessage response = await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        JsonElement body = await Json(response);
        Assert.Equal(TokenExchange.AccessTokenType, body.GetProperty("issued_token_type").GetString());
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.InRange(body.GetProperty("expires_in").GetInt64(), 280, 300);
        Assert.False(body.TryGetProperty("refresh_token", out _));
        Assert.False(body.TryGetProperty("id_token", out _));

        string access = body.GetProperty("access_token").GetString()!;
        Assert.Equal(ApplicationClaims.AccessTokenType, Part(access, 0).GetProperty("typ").GetString());
        JsonElement claims = Part(access, 1);
        Assert.Equal(app.Id, claims.GetProperty("aud").GetString());
        Assert.Equal(AnchorFixture.Issuer, claims.GetProperty("iss").GetString());
        Assert.Equal(user.UserId, claims.GetProperty("sub").GetString());
        Assert.Equal(app.Client, claims.GetProperty(ApplicationClaims.ClientId).GetString());
        Assert.Equal([$"{app.Id}:watch"], claims.GetProperty(ApplicationClaims.Actions).EnumerateArray().Select(e => e.GetString()));
        Assert.False(claims.TryGetProperty(ApplicationClaims.Actor, out _));
        Assert.False(claims.TryGetProperty("sid", out _));

        JsonElement line = Line(AuthEvents.TokenExchanged, app);
        Assert.Equal(app.Client, line.GetProperty("Client").GetString());
        Assert.Equal($"discord:{discordId}", line.GetProperty("Identity").GetString());
        Assert.Equal(user.UserId, line.GetProperty("UserId").GetString());
        Assert.Equal(JsonValueKind.Null, line.GetProperty("ActedBy").ValueKind);
        Assert.Equal(JsonValueKind.Null, line.GetProperty("Reason").ValueKind);
    }

    [Fact]
    public async Task A_Discord_token_from_another_Discord_application_is_refused()
    {
        Registered app = await ApplicationAsync();
        (_, string discordId) = await DiscordAccountAsync();
        string token = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Issue(token, Snowflake(), discordId, "haru");

        await AssertErrorAsync(await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken)),
            HttpStatusCode.BadRequest, "invalid_grant");

        JsonElement line = Line(AuthEvents.TokenExchangeRefused, app);
        Assert.Equal(TokenExchangeRefusals.DiscordApplication, line.GetProperty("Reason").GetString());
        Assert.Equal($"discord:{discordId}", line.GetProperty("Identity").GetString());
    }

    [Fact]
    public async Task An_application_presenting_no_Discord_application_is_not_allowed_the_exchange()
    {
        Registered app = await ApplicationAsync(presentsDiscord: false);
        string token = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Issue(token, Snowflake(), Snowflake(), "haru");

        await AssertErrorAsync(await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken)),
            HttpStatusCode.BadRequest, "unauthorized_client");
        Assert.Equal(0, anchor.Discord.Asked(token));
        Assert.Equal(TokenExchangeRefusals.ClientNotAllowed, Line(AuthEvents.TokenExchangeRefused, app).GetProperty("Reason").GetString());
    }

    [Fact]
    public async Task An_unknown_Discord_identity_is_provisioned_pending_and_told_so()
    {
        Registered app = await ApplicationAsync();
        string discordId = Snowflake();
        string token = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Issue(token, app.DiscordApplication, discordId, "newcomer" + discordId[^4..]);

        await AssertAccountRefusedAsync(await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken)), TokenExchange.AccountStatus.Pending);

        KgsmUser? provisioned = await anchor.Store.FindByCredentialAsync($"discord:{discordId}");
        Assert.NotNull(provisioned);
        Assert.Equal(UserStatus.Pending, provisioned.Status);
        Assert.Equal(AccountOrigin.Arrived, provisioned.Origin);

        Assert.Contains(anchor.Journal(AuthEvents.UserProvisioned),
            e => e.GetProperty("Data").GetProperty("UserId").GetString() == provisioned.UserId
                 && e.GetProperty("Origin").GetString() == AnchorJournal.OriginDiscord);
        JsonElement line = Line(AuthEvents.TokenExchangeRefused, app);
        Assert.Equal(TokenExchangeRefusals.AccountPending, line.GetProperty("Reason").GetString());
        Assert.Equal(provisioned.UserId, line.GetProperty("UserId").GetString());

        // Exchanged again, it is the same account still waiting, not a second one.
        await AssertAccountRefusedAsync(await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken)), TokenExchange.AccountStatus.Pending);
        Assert.Equal(provisioned.UserId, (await anchor.Store.FindByCredentialAsync($"discord:{discordId}"))!.UserId);
    }

    [Fact]
    public async Task A_disabled_account_is_refused_and_told_so()
    {
        Registered app = await ApplicationAsync();
        (KgsmUser user, string discordId) = await DiscordAccountAsync(UserStatus.Disabled);
        string token = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Issue(token, app.DiscordApplication, discordId, "haru");

        await AssertAccountRefusedAsync(await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken)), TokenExchange.AccountStatus.Disabled);

        JsonElement line = Line(AuthEvents.TokenExchangeRefused, app);
        Assert.Equal(TokenExchangeRefusals.AccountDisabled, line.GetProperty("Reason").GetString());
        Assert.Equal(user.UserId, line.GetProperty("UserId").GetString());
    }

    [Fact]
    public async Task A_token_Discord_does_not_honour_is_invalid_grant()
    {
        Registered app = await ApplicationAsync();
        string token = "dsc-" + Guid.NewGuid().ToString("N");

        await AssertErrorAsync(await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken)),
            HttpStatusCode.BadRequest, "invalid_grant");
        Assert.Equal(TokenExchangeRefusals.SubjectInvalid, Line(AuthEvents.TokenExchangeRefused, app).GetProperty("Reason").GetString());
    }

    // ── What Discord says is remembered, and what it refuses is not ───────────

    [Fact]
    public async Task Discord_is_asked_once_for_a_token_while_its_answer_is_held()
    {
        Registered app = await ApplicationAsync();
        (_, string discordId) = await DiscordAccountAsync();
        string token = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Issue(token, app.DiscordApplication, discordId, "haru");

        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken))).StatusCode);

        Assert.Equal(1, anchor.Discord.Asked(token));
        Assert.Equal(2, anchor.Journal(AuthEvents.TokenExchanged)
            .Count(e => e.GetProperty("Data").GetProperty("Application").GetString() == app.Id));
    }

    [Fact]
    public async Task A_token_about_to_expire_is_held_no_longer_than_it_lives()
    {
        Registered app = await ApplicationAsync();
        (_, string discordId) = await DiscordAccountAsync();
        string token = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Issue(token, app.DiscordApplication, discordId, "haru", expires: DateTimeOffset.UtcNow.AddSeconds(1));

        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken))).StatusCode);
        await Task.Delay(1500);
        await ExchangeAsync(app, Form(token, TokenExchange.DiscordAccessToken));

        Assert.Equal(2, anchor.Discord.Asked(token));
    }

    [Fact]
    public async Task A_refusal_and_an_outage_are_never_held()
    {
        Registered app = await ApplicationAsync();
        string refused = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Fail(refused, HttpStatusCode.Unauthorized);
        string down = "dsc-" + Guid.NewGuid().ToString("N");
        anchor.Discord.Fail(down, HttpStatusCode.ServiceUnavailable);

        for (int i = 0; i < 2; i++)
        {
            await AssertErrorAsync(await ExchangeAsync(app, Form(refused, TokenExchange.DiscordAccessToken)),
                HttpStatusCode.BadRequest, "invalid_grant");
            await AssertErrorAsync(await ExchangeAsync(app, Form(down, TokenExchange.DiscordAccessToken)),
                HttpStatusCode.BadGateway, "temporarily_unavailable");
        }

        Assert.Equal(2, anchor.Discord.Asked(refused));
        Assert.Equal(2, anchor.Discord.Asked(down));

        // An outage decided nothing, so it records nothing; the refusals are each a line.
        Assert.Equal(2, anchor.Journal(AuthEvents.TokenExchangeRefused)
            .Count(e => e.GetProperty("Data").GetProperty("Application").GetString() == app.Id));
    }

    // ── The bot: acting for a Discord user ────────────────────────────────────

    [Fact]
    public async Task A_client_registered_to_act_for_Discord_users_gets_a_token_naming_the_person_with_itself_as_actor()
    {
        Registered app = await ApplicationAsync(presentsDiscord: false, actForDiscord: true);
        (KgsmUser user, string discordId) = await DiscordAccountAsync();
        await GrantAsync(user, $"{app.Id}:download");

        HttpResponseMessage response = await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement body = await Json(response);
        Assert.False(body.TryGetProperty("refresh_token", out _));
        JsonElement claims = Part(body.GetProperty("access_token").GetString()!, 1);
        Assert.Equal(user.UserId, claims.GetProperty("sub").GetString());
        Assert.Equal(app.Id, claims.GetProperty("aud").GetString());
        Assert.Equal(app.Client, claims.GetProperty(ApplicationClaims.Actor).GetProperty("sub").GetString());
        Assert.Equal([$"{app.Id}:download"], claims.GetProperty(ApplicationClaims.Actions).EnumerateArray().Select(e => e.GetString()));

        // Nothing about a Discord user id is asked of Discord.
        Assert.Equal(0, anchor.Discord.Asked(discordId));

        JsonElement line = Line(AuthEvents.TokenExchanged, app);
        Assert.Equal(app.Client, line.GetProperty("ActedBy").GetString());
        Assert.Equal(user.UserId, line.GetProperty("UserId").GetString());
        Assert.Equal($"discord:{discordId}", line.GetProperty("Identity").GetString());
    }

    [Fact]
    public async Task A_client_not_registered_to_act_for_Discord_users_is_refused()
    {
        Registered app = await ApplicationAsync();
        (_, string discordId) = await DiscordAccountAsync();

        await AssertErrorAsync(await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId)),
            HttpStatusCode.BadRequest, "unauthorized_client");

        JsonElement line = Line(AuthEvents.TokenExchangeRefused, app);
        Assert.Equal(TokenExchangeRefusals.ClientNotAllowed, line.GetProperty("Reason").GetString());
        Assert.Equal(app.Client, line.GetProperty("ActedBy").GetString());
    }

    [Fact]
    public async Task Acting_for_a_Discord_user_nobody_holds_provisions_nothing()
    {
        Registered app = await ApplicationAsync(presentsDiscord: false, actForDiscord: true);
        string discordId = Snowflake();

        await AssertAccountRefusedAsync(await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId)), TokenExchange.AccountStatus.Unknown);

        Assert.Null(await anchor.Store.FindByCredentialAsync($"discord:{discordId}"));
        Assert.Equal(TokenExchangeRefusals.AccountUnknown, Line(AuthEvents.TokenExchangeRefused, app).GetProperty("Reason").GetString());
    }

    [Fact]
    public async Task Acting_for_a_pending_Discord_user_is_refused_and_told_so()
    {
        Registered app = await ApplicationAsync(presentsDiscord: false, actForDiscord: true);
        (_, string discordId) = await DiscordAccountAsync(UserStatus.Pending);

        await AssertAccountRefusedAsync(await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId)), TokenExchange.AccountStatus.Pending);
    }

    // ── The client, and the request ───────────────────────────────────────────

    [Fact]
    public async Task Only_an_authenticated_confidential_client_may_exchange()
    {
        Registered app = await ApplicationAsync(actForDiscord: true);
        (_, string discordId) = await DiscordAccountAsync();

        // A public client names itself and is not the kind of client the grant is for.
        string publicId = NewId();
        var output = new StringWriter();
        Assert.Equal(0, await ApplicationCommand.RunAsync(
            ["app", "add", publicId, "--name", "Public " + publicId, "--client-id", publicId + "-site",
             "--redirect", $"https://{publicId}.test/signin", "--act-for-discord"],
            AnchorOptions.FromSettings(new AnchorSettings
            {
                UserStorePath = Path.Combine(anchor.Root, "users.db"),
                SessionStorePath = Path.Combine(anchor.Root, "sessions.db"),
                ClusterId = AnchorFixture.ClusterId,
                Issuer = AnchorFixture.Issuer,
            }), output));
        for (int attempt = 0; attempt < 50 && anchor.Service<ClientRegistry>().Find(publicId + "-site") is null; attempt++)
            await Task.Delay(100);

        await AssertErrorAsync(await ExchangeAsync(
                Form(discordId, TokenExchange.DiscordUserId, ("client_id", publicId + "-site")), basic: null),
            HttpStatusCode.BadRequest, "unauthorized_client");

        // A confidential client that does not prove its secret, a wrong secret, and nobody at all.
        HttpResponseMessage unproved = await ExchangeAsync(Form(discordId, TokenExchange.DiscordUserId, ("client_id", app.Client)), basic: null);
        await AssertErrorAsync(unproved, HttpStatusCode.Unauthorized, "invalid_client");

        HttpResponseMessage wrong = await ExchangeAsync(Form(discordId, TokenExchange.DiscordUserId), (app.Client, "not-the-secret"));
        await AssertErrorAsync(wrong, HttpStatusCode.Unauthorized, "invalid_client");
        Assert.Contains("Basic", wrong.Headers.WwwAuthenticate.ToString());

        await AssertErrorAsync(await ExchangeAsync(Form(discordId, TokenExchange.DiscordUserId), basic: null),
            HttpStatusCode.Unauthorized, "invalid_client");

        Assert.DoesNotContain(anchor.Journal(), e => e.GetProperty("EventType").GetString()!.StartsWith("auth.token.", StringComparison.Ordinal)
            && e.GetProperty("Data").GetProperty("Application").GetString() == publicId);
    }

    [Fact]
    public async Task What_the_exchange_issues_is_the_application_s_access_token_and_nothing_else()
    {
        Registered app = await ApplicationAsync(presentsDiscord: false, actForDiscord: true);
        (_, string discordId) = await DiscordAccountAsync();

        await AssertErrorAsync(await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId, ("audience", "someone-else"))),
            HttpStatusCode.BadRequest, "invalid_target");
        await AssertErrorAsync(await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId, ("resource", "https://elsewhere.test"))),
            HttpStatusCode.BadRequest, "invalid_target");
        await AssertErrorAsync(await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId, ("scope", "openid"))),
            HttpStatusCode.BadRequest, "invalid_scope");
        await AssertErrorAsync(await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId,
                ("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"))),
            HttpStatusCode.BadRequest, "invalid_request");
        await AssertErrorAsync(await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId, ("actor_token", "x"))),
            HttpStatusCode.BadRequest, "invalid_request");
        await AssertErrorAsync(await ExchangeAsync(app, Form(discordId, "urn:ietf:params:oauth:token-type:jwt")),
            HttpStatusCode.BadRequest, "invalid_request");
        await AssertErrorAsync(await ExchangeAsync(app, Form("not-a-snowflake", TokenExchange.DiscordUserId)),
            HttpStatusCode.BadRequest, "invalid_request");

        // Naming its own audience and the access-token type is the same request as naming neither.
        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(app, Form(discordId, TokenExchange.DiscordUserId,
            ("audience", app.Id), ("requested_token_type", TokenExchange.AccessTokenType)))).StatusCode);
    }

    [Fact]
    public async Task Discovery_advertises_the_exchange()
    {
        JsonElement discovery = await Json(await anchor.Client.GetAsync("/.well-known/openid-configuration"));
        Assert.Contains(TokenExchange.GrantType,
            discovery.GetProperty("grant_types_supported").EnumerateArray().Select(e => e.GetString()));
    }
}
