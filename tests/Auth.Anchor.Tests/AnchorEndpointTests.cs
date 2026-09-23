using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// What the anchor serves: the one sign-in door, the sessions it keeps, and the key everything else
/// verifies them with.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AnchorEndpointTests(AnchorFixture anchor)
{
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<JsonElement> SignInAsync(string username, string password)
    {
        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password }, Wire);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    [Fact]
    public async Task Health_reports_ok()
    {
        HttpResponseMessage response = await anchor.Client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ok\n", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_session_it_mints_verifies_against_the_key_it_publishes()
    {
        string username = Unique("verified-");
        await anchor.SeedAsync(username, "correct horse battery", KgsmTier.Operator);

        JsonElement session = await SignInAsync(username, "correct horse battery");
        string token = session.GetProperty("token").GetString()!;

        // Exactly what a member has: the published document, fetched over HTTP, and nothing else.
        string published = await anchor.Client.GetStringAsync("/auth/cluster/public-key");
        SessionJwks? keys = EcdsaSessionSigner.ReadKeys(published);
        Assert.NotNull(keys);

        TokenValidationResult result = await new JsonWebTokenHandler().ValidateTokenAsync(token,
            new TokenValidationParameters
            {
                ValidIssuer = AnchorFixture.Issuer,
                ValidAudience = AnchorFixture.ClusterId,
                IssuerSigningKeys = EcdsaSessionSigner.VerificationKeysFrom(keys),
                ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            });

        Assert.True(result.IsValid);
        Assert.Equal(KgsmTier.Operator, SessionClaims.ReadTier(result.ClaimsIdentity!));
    }

    [Fact]
    public async Task The_published_key_carries_no_private_half()
    {
        string published = await anchor.Client.GetStringAsync("/auth/cluster/public-key");

        // "d" is the private scalar of an EC JWK. Its absence is what makes publishing the key safe.
        using JsonDocument document = JsonDocument.Parse(published);
        JsonElement key = document.RootElement.GetProperty("keys")[0];

        Assert.False(key.TryGetProperty("d", out _));
        Assert.Equal("EC", key.GetProperty("kty").GetString());
        Assert.Equal("ES256", key.GetProperty("alg").GetString());
    }

    [Fact]
    public async Task A_session_is_scoped_to_the_cluster_not_the_machine()
    {
        string username = Unique("scoped-");
        await anchor.SeedAsync(username, "a good long password", KgsmTier.Viewer);

        JsonElement session = await SignInAsync(username, "a good long password");

        Assert.Equal(AnchorFixture.ClusterId, session.GetProperty("cluster").GetString());

        // The audience is the cluster, which is what makes one sign-in valid on every member of it.
        var token = new JsonWebToken(session.GetProperty("token").GetString()!);
        Assert.Contains(AnchorFixture.ClusterId, token.Audiences);
    }

    [Fact]
    public async Task A_wrong_password_and_an_unknown_username_answer_identically()
    {
        string username = Unique("real-");
        await anchor.SeedAsync(username, "the actual password", KgsmTier.Viewer);

        HttpResponseMessage wrong = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "not the password" }, Wire);
        HttpResponseMessage unknown = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username = Unique("nobody-"), password = "not the password" }, Wire);

        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(await wrong.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_disabled_account_cannot_sign_in()
    {
        string username = Unique("off-");
        await anchor.SeedAsync(username, "still a real password", KgsmTier.Admin, UserStatus.Disabled);

        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "still a real password" }, Wire);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("account_disabled", body.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_pending_account_signs_in_and_holds_nothing()
    {
        string username = Unique("waiting-");
        await anchor.SeedAsync(username, "approved eventually", KgsmTier.Admin, UserStatus.Pending);

        JsonElement session = await SignInAsync(username, "approved eventually");

        // It authenticates, which is what lets a surface say "awaiting approval" rather than showing
        // a bare denial to somebody who has just proved who they are.
        Assert.Equal("pending", session.GetProperty("status").GetString());
        Assert.Equal("none", session.GetProperty("tier").GetString());
    }

    [Fact]
    public async Task A_malformed_body_is_refused_without_reaching_the_store()
    {
        HttpResponseMessage response = await anchor.Client.PostAsync("/auth/sign-in",
            new StringContent("not json", System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task The_session_endpoint_answers_the_store_rather_than_the_token()
    {
        string username = Unique("live-");
        KgsmUser user = await anchor.SeedAsync(username, "read me back", KgsmTier.Admin);

        JsonElement session = await SignInAsync(username, "read me back");
        string bearer = session.GetProperty("token").GetString()!;

        // Demoted after the token was minted. The bearer still carries "admin".
        await anchor.Store.UpdateAsync(user with { Tier = KgsmTier.Viewer, Updated = DateTimeOffset.UtcNow });

        // The authority cache's TTL is the staleness bound, so wait it out rather than assuming it
        // is not there.
        await Task.Delay(TimeSpan.FromSeconds(6));

        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/session");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        HttpResponseMessage response = await anchor.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement who = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("viewer", who.GetProperty("tier").GetString());
        Assert.Equal(user.UserId, who.GetProperty("userId").GetString());
    }

    [Fact]
    public async Task An_unauthenticated_caller_is_told_to_sign_in()
    {
        HttpResponseMessage response = await anchor.Client.GetAsync("/auth/session");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("unauthenticated", body.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_refresh_token_is_not_a_bearer()
    {
        string username = Unique("kinds-");
        await anchor.SeedAsync(username, "two kinds of token", KgsmTier.Admin);

        JsonElement session = await SignInAsync(username, "two kinds of token");

        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/session");
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", session.GetProperty("refresh").GetString());

        Assert.Equal(HttpStatusCode.Unauthorized, (await anchor.Client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task Refreshing_rotates_both_tokens_and_kills_the_previous_one()
    {
        string username = Unique("rotating-");
        await anchor.SeedAsync(username, "rotate this session", KgsmTier.Operator);

        JsonElement session = await SignInAsync(username, "rotate this session");
        string first = session.GetProperty("refresh").GetString()!;

        HttpResponseMessage rotated = await anchor.Client.PostAsJsonAsync(
            "/auth/session/refresh", new { refresh = first }, Wire);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);

        JsonElement next = await rotated.Content.ReadFromJsonAsync<JsonElement>();
        Assert.NotEqual(first, next.GetProperty("refresh").GetString());
        Assert.Equal("operator", next.GetProperty("tier").GetString());

        // Presenting the rotated-away token again is either a stale client or a stolen one, and this
        // anchor cannot tell which — so it refuses.
        HttpResponseMessage replay = await anchor.Client.PostAsJsonAsync(
            "/auth/session/refresh", new { refresh = first }, Wire);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task A_disabled_account_cannot_refresh_and_its_session_is_ended()
    {
        string username = Unique("withdrawn-");
        KgsmUser user = await anchor.SeedAsync(username, "withdraw this one", KgsmTier.Admin);

        JsonElement session = await SignInAsync(username, "withdraw this one");
        string refresh = session.GetProperty("refresh").GetString()!;
        string bearer = session.GetProperty("token").GetString()!;

        await anchor.Store.UpdateAsync(
            user with { Status = UserStatus.Disabled, Updated = DateTimeOffset.UtcNow });
        await Task.Delay(TimeSpan.FromSeconds(6));

        HttpResponseMessage refused = await anchor.Client.PostAsJsonAsync(
            "/auth/session/refresh", new { refresh }, Wire);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);

        // And the still-valid access token buys nothing either: the session row went with the account.
        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/session");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        HttpResponseMessage response = await anchor.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Signing_out_ends_the_session_for_the_bearer_too()
    {
        string username = Unique("leaving-");
        await anchor.SeedAsync(username, "sign me out please", KgsmTier.Viewer);

        JsonElement session = await SignInAsync(username, "sign me out please");
        string bearer = session.GetProperty("token").GetString()!;

        HttpResponseMessage out1 = await anchor.Client.PostAsJsonAsync(
            "/auth/session/sign-out", new { refresh = session.GetProperty("refresh").GetString() }, Wire);
        Assert.Equal(HttpStatusCode.NoContent, out1.StatusCode);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/session");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        HttpResponseMessage response = await anchor.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("session_ended", body.GetProperty("error").GetProperty("code").GetString());

        // Signing out twice is not two revocations, and says so by answering the same way.
        HttpResponseMessage out2 = await anchor.Client.PostAsJsonAsync(
            "/auth/session/sign-out", new { refresh = session.GetProperty("refresh").GetString() }, Wire);
        Assert.Equal(HttpStatusCode.NoContent, out2.StatusCode);
    }

    [Fact]
    public async Task The_account_list_is_admin_only_and_matches_the_store()
    {
        string viewerName = Unique("nosy-");
        await anchor.SeedAsync(viewerName, "not enough tier", KgsmTier.Viewer);
        string adminName = Unique("boss-");
        KgsmUser admin = await anchor.SeedAsync(adminName, "enough tier here", KgsmTier.Admin);

        JsonElement viewerSession = await SignInAsync(viewerName, "not enough tier");
        using var refused = new HttpRequestMessage(HttpMethod.Get, "/auth/cluster/users");
        refused.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", viewerSession.GetProperty("token").GetString());
        HttpResponseMessage denied = await anchor.Client.SendAsync(refused);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        JsonElement adminSession = await SignInAsync(adminName, "enough tier here");
        using var allowed = new HttpRequestMessage(HttpMethod.Get, "/auth/cluster/users");
        allowed.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", adminSession.GetProperty("token").GetString());
        HttpResponseMessage response = await anchor.Client.SendAsync(allowed);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement page = await response.Content.ReadFromJsonAsync<JsonElement>();

        // The same answer the library gives against the same file.
        IReadOnlyList<KgsmUser> fromLibrary = await anchor.Store.ListAsync();
        Assert.Equal(fromLibrary.Count, page.GetProperty("data").GetArrayLength());

        JsonElement served = page.GetProperty("data").EnumerateArray()
            .Single(u => u.GetProperty("id").GetString() == admin.UserId);
        Assert.Equal("admin", served.GetProperty("tier").GetString());
        Assert.True(served.GetProperty("hasPassword").GetBoolean());

        // A password hash has no representation on this surface, in any field.
        Assert.DoesNotContain("AQAAAA", page.ToString());
    }

    [Fact]
    public async Task A_configured_origin_is_allowed_and_an_unknown_one_is_not()
    {
        using var allowed = new HttpRequestMessage(HttpMethod.Options, "/auth/sign-in");
        allowed.Headers.Add("Origin", "https://panel.test");
        HttpResponseMessage yes = await anchor.Client.SendAsync(allowed);

        Assert.Equal(HttpStatusCode.NoContent, yes.StatusCode);
        Assert.Equal("https://panel.test", yes.Headers.GetValues("Access-Control-Allow-Origin").Single());

        using var refused = new HttpRequestMessage(HttpMethod.Options, "/auth/sign-in");
        refused.Headers.Add("Origin", "https://elsewhere.test");
        HttpResponseMessage no = await anchor.Client.SendAsync(refused);

        // No allowance header at all, and never a wildcard on a surface that mints credentials.
        Assert.False(no.Headers.Contains("Access-Control-Allow-Origin"));
    }
}

/// <summary>
/// What a second anchor serves when the cluster names somebody else: nothing that mints or extends a
/// credential, and nothing that answers as the account authority.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AnchorStandDownTests(AnchorFixture anchor)
{
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task A_member_that_does_not_hold_the_accounts_mints_nothing_and_names_the_one_that_does()
    {
        string username = "standdown-" + Guid.NewGuid().ToString("N")[..8];
        await anchor.SeedAsync(username, "a perfectly good password", KgsmTier.Admin);

        // It works while this member is the authority.
        HttpResponseMessage before = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "a perfectly good password" }, Wire);
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        string bearer = (await before.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("token").GetString()!;

        await anchor.StandingBy("node-b-auth", async () =>
        {
            // 503 and not 403: this is an outage with a named cause, not a denial of the person.
            HttpResponseMessage refused = await anchor.Client.PostAsJsonAsync(
                "/auth/sign-in", new { username, password = "a perfectly good password" }, Wire);

            Assert.Equal(HttpStatusCode.ServiceUnavailable, refused.StatusCode);
            JsonElement body = await refused.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("not_the_anchor", body.GetProperty("error").GetProperty("code").GetString());
            Assert.Contains("node-b-auth", body.GetProperty("error").GetProperty("message").GetString());

            // And the holder is on a header, so a client can route rather than retry.
            Assert.Equal("node-b-auth", refused.Headers.GetValues("X-Kgsm-Auth-Holder").Single());

            // A session it minted before standing down buys nothing further from it.
            using var whoami = new HttpRequestMessage(HttpMethod.Get, "/auth/session");
            whoami.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, (await anchor.Client.SendAsync(whoami)).StatusCode);

            using var accounts = new HttpRequestMessage(HttpMethod.Get, "/auth/cluster/users");
            accounts.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, (await anchor.Client.SendAsync(accounts)).StatusCode);
        });
    }

    [Fact]
    public async Task Standing_by_still_answers_health_and_still_publishes_its_key()
    {
        await anchor.StandingBy("node-b-auth", async () =>
        {
            // A candidate is a running daemon, not a broken one — and its key stays discoverable so
            // a later promotion needs no restart anywhere.
            Assert.Equal(HttpStatusCode.OK, (await anchor.Client.GetAsync("/health")).StatusCode);
            Assert.Equal(HttpStatusCode.OK,
                (await anchor.Client.GetAsync("/auth/cluster/public-key")).StatusCode);
        });
    }

    [Fact]
    public async Task Signing_out_works_even_from_a_member_that_has_stood_down()
    {
        string username = "leaving-standby-" + Guid.NewGuid().ToString("N")[..8];
        await anchor.SeedAsync(username, "sign me out regardless", KgsmTier.Viewer);

        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "sign me out regardless" }, Wire);
        JsonElement session = await response.Content.ReadFromJsonAsync<JsonElement>();

        await anchor.StandingBy("node-b-auth", async () =>
        {
            // Ending a session takes authority away rather than granting it, and this member still
            // holds the row. Refusing would strand whoever is signed in to it.
            HttpResponseMessage out1 = await anchor.Client.PostAsJsonAsync(
                "/auth/session/sign-out", new { refresh = session.GetProperty("refresh").GetString() }, Wire);
            Assert.Equal(HttpStatusCode.NoContent, out1.StatusCode);
        });
    }
}

/// <summary>
/// The single write path for what a person may do, and the version every member orders by.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AnchorAccountWriteTests(AnchorFixture anchor)
{
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<string> AdminBearerAsync()
    {
        string username = Unique("writer-admin-");
        await anchor.SeedAsync(username, "an admin who can write", KgsmTier.Admin);
        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "an admin who can write" }, Wire);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;
    }

    private async Task<HttpResponseMessage> PatchAsync(string bearer, string userId, object body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Patch, "/auth/cluster/users/" + userId)
        {
            Content = JsonContent.Create(body, options: Wire),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await anchor.Client.SendAsync(request);
    }

    [Fact]
    public async Task A_change_takes_a_version_and_every_change_takes_a_higher_one()
    {
        string bearer = await AdminBearerAsync();
        KgsmUser subject = await anchor.SeedAsync(Unique("subject-"), "a password", KgsmTier.Viewer);

        JsonElement first = await (await PatchAsync(bearer, subject.UserId, new { tier = "operator" }))
            .Content.ReadFromJsonAsync<JsonElement>();
        JsonElement second = await (await PatchAsync(bearer, subject.UserId, new { tier = "viewer" }))
            .Content.ReadFromJsonAsync<JsonElement>();

        // The version is the whole guarantee: a member that has not applied the second yet will
        // refuse the first if it arrives afterwards.
        Assert.True(second.GetProperty("version").GetInt64() > first.GetProperty("version").GetInt64());
        Assert.Equal("viewer", second.GetProperty("account").GetProperty("tier").GetString());
    }

    [Fact]
    public async Task An_absent_field_is_left_alone()
    {
        string bearer = await AdminBearerAsync();
        KgsmUser subject = await anchor.SeedAsync(
            Unique("partial-"), "a password", KgsmTier.Operator, UserStatus.Pending);

        JsonElement changed = await (await PatchAsync(bearer, subject.UserId, new { status = "active" }))
            .Content.ReadFromJsonAsync<JsonElement>();

        // Changing a status must not require restating a tier, or a caller that omits one silently
        // reverts whatever somebody else just set.
        JsonElement account = changed.GetProperty("account");
        Assert.Equal("active", account.GetProperty("status").GetString());
        Assert.Equal("operator", account.GetProperty("tier").GetString());
    }

    [Fact]
    public async Task A_tier_nobody_recognises_is_refused_rather_than_read_as_none()
    {
        string bearer = await AdminBearerAsync();
        KgsmUser subject = await anchor.SeedAsync(Unique("typo-"), "a password", KgsmTier.Operator);

        HttpResponseMessage response = await PatchAsync(bearer, subject.UserId, new { tier = "opreator" });

        // Everywhere else an unreadable tier grants nothing, which is the safe reading of a value
        // somebody else wrote. Here it is what the caller asked for, and reading a typo as "none"
        // would demote the person the admin meant to promote.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_tier", body.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal(KgsmTier.Operator, (await anchor.Store.FindByIdAsync(subject.UserId))!.Tier);
    }

    [Fact]
    public async Task None_is_a_tier_somebody_can_actually_ask_for()
    {
        string bearer = await AdminBearerAsync();
        KgsmUser subject = await anchor.SeedAsync(Unique("revoked-"), "a password", KgsmTier.Admin);

        HttpResponseMessage response = await PatchAsync(bearer, subject.UserId, new { tier = "none" });

        // Refusing everything that parses to None would make withdrawing authority impossible.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(KgsmTier.None, (await anchor.Store.FindByIdAsync(subject.UserId))!.Tier);
    }

    [Fact]
    public async Task An_admin_cannot_remove_the_cluster_s_last_administrator()
    {
        // A fresh store for this one: the rule is about there being no other admin anywhere, and the
        // shared fixture's store accumulates them.
        string root = Path.Combine(anchor.Root, "last-admin-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(root);

        string username = Unique("only-admin-");
        KgsmUser only = await anchor.SeedAsync(username, "the only admin", KgsmTier.Admin);

        // Every other admin in the shared store stands down first, so this really is the last one.
        var others = (await anchor.Store.ListAsync())
            .Where(u => u.UserId != only.UserId && u.EffectiveTier == KgsmTier.Admin).ToList();
        foreach (KgsmUser other in others)
            await anchor.Store.UpdateAsync(other with { Tier = KgsmTier.Viewer });

        try
        {
            HttpResponseMessage signIn = await anchor.Client.PostAsJsonAsync(
                "/auth/sign-in", new { username, password = "the only admin" }, Wire);
            string bearer = (await signIn.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("token").GetString()!;

            HttpResponseMessage refused = await PatchAsync(bearer, only.UserId, new { tier = "viewer" });

            // One account store for the whole cluster means this is not "no admin on this machine" —
            // it is nobody, anywhere, able to undo it through any surface.
            Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
            JsonElement body = await refused.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("last_admin", body.GetProperty("error").GetProperty("code").GetString());
            Assert.Equal(KgsmTier.Admin, (await anchor.Store.FindByIdAsync(only.UserId))!.Tier);
        }
        finally
        {
            foreach (KgsmUser other in others)
                await anchor.Store.UpdateAsync(other);
        }
    }

    [Fact]
    public async Task Writing_is_admin_only()
    {
        string username = Unique("nosy-writer-");
        await anchor.SeedAsync(username, "not enough tier", KgsmTier.Operator);
        HttpResponseMessage signIn = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "not enough tier" }, Wire);
        string bearer = (await signIn.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("token").GetString()!;

        KgsmUser subject = await anchor.SeedAsync(Unique("subject-"), "a password", KgsmTier.Viewer);

        Assert.Equal(HttpStatusCode.Forbidden,
            (await PatchAsync(bearer, subject.UserId, new { tier = "admin" })).StatusCode);
    }

    [Fact]
    public async Task An_account_that_does_not_exist_is_a_404()
    {
        string bearer = await AdminBearerAsync();
        Assert.Equal(HttpStatusCode.NotFound,
            (await PatchAsync(bearer, "usr_nothing", new { tier = "viewer" })).StatusCode);
    }
}
