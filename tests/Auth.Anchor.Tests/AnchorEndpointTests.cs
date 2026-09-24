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
/// What the anchor serves beside its sign-in: the key everything else verifies sessions with, and the
/// administration of the accounts behind them.
/// </summary>
/// <remarks>
/// Sessions here are minted in process (<see cref="AnchorFixture.SignInAsync"/>); how a browser gets one
/// is the OpenID Connect suite's.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class AnchorEndpointTests(AnchorFixture anchor)
{
    private async Task<HttpResponseMessage> GetAsync(string path, string? bearer)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await anchor.Client.SendAsync(request);
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
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(KgsmTier.Operator, "verified");

        // Exactly what a member has: the published document, fetched over HTTP, and nothing else.
        string published = await anchor.Client.GetStringAsync("/auth/cluster/public-key");
        SessionJwks? keys = EcdsaSessionSigner.ReadKeys(published);
        Assert.NotNull(keys);

        TokenValidationResult result = await new JsonWebTokenHandler().ValidateTokenAsync(session.Access,
            new TokenValidationParameters
            {
                ValidIssuer = AnchorFixture.Issuer,
                ValidAudience = AnchorFixture.ClusterId,
                IssuerSigningKeys = EcdsaSessionSigner.VerificationKeysFrom(keys),
                ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            });

        Assert.True(result.IsValid);
        Assert.Equal(KgsmTier.Operator, SessionClaims.ReadTier(result.ClaimsIdentity!));

        // The audience is the cluster, which is what makes one sign-in valid on every member of it.
        Assert.Contains(AnchorFixture.ClusterId, new JsonWebToken(session.Access).Audiences);
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
    public async Task Authority_is_read_from_the_store_rather_than_the_token()
    {
        (KgsmUser user, AnchorFixture.Session session) = await anchor.SignedInAsync(KgsmTier.Admin, "live");
        Assert.Equal(HttpStatusCode.OK, (await GetAsync("/auth/cluster/users", session.Access)).StatusCode);

        // Demoted after the token was minted. The bearer still carries "admin".
        await anchor.Store.UpdateAsync(user with { Tier = KgsmTier.Viewer, Updated = DateTimeOffset.UtcNow });

        // The authority cache's TTL is the staleness bound, so wait it out rather than assuming it is
        // not there.
        await Task.Delay(TimeSpan.FromSeconds(6));

        Assert.Equal(HttpStatusCode.Forbidden, (await GetAsync("/auth/cluster/users", session.Access)).StatusCode);
    }

    [Fact]
    public async Task An_unauthenticated_caller_is_told_to_sign_in()
    {
        HttpResponseMessage response = await GetAsync("/auth/cluster/users", bearer: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("unauthenticated", body.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_refresh_token_is_not_a_bearer()
    {
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(KgsmTier.Admin, "kinds");

        Assert.Equal(HttpStatusCode.Unauthorized, (await GetAsync("/auth/cluster/users", session.Refresh)).StatusCode);
    }

    [Fact]
    public async Task The_account_list_is_admin_only_and_matches_the_store()
    {
        (_, AnchorFixture.Session viewer) = await anchor.SignedInAsync(KgsmTier.Viewer, "nosy");
        Assert.Equal(HttpStatusCode.Forbidden, (await GetAsync("/auth/cluster/users", viewer.Access)).StatusCode);

        (KgsmUser admin, AnchorFixture.Session session) = await anchor.SignedInAsync(KgsmTier.Admin, "boss");
        HttpResponseMessage response = await GetAsync("/auth/cluster/users", session.Access);

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

    [Theory]
    [InlineData("/auth/sign-in")]
    [InlineData("/auth/register")]
    [InlineData("/auth/session/refresh")]
    [InlineData("/auth/session/sign-out")]
    [InlineData("/auth/reauth")]
    [InlineData("/auth/password")]
    public async Task There_is_no_door_but_the_provider_s(string path)
    {
        HttpResponseMessage response = await anchor.Client.PostAsync(path,
            new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));

        // A person signs in on the provider's pages and nowhere else, so nothing here takes a credential
        // and answers with a session.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}

/// <summary>
/// What a second anchor serves when the cluster names somebody else: nothing that answers as the
/// account authority.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AnchorStandDownTests(AnchorFixture anchor)
{
    [Fact]
    public async Task A_member_that_does_not_hold_the_accounts_answers_for_none_of_them()
    {
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(KgsmTier.Admin, "standdown");

        await anchor.StandingBy("node-b-auth", async () =>
        {
            // 503 and not 403: this is an outage with a named cause, not a denial of the person.
            using var accounts = new HttpRequestMessage(HttpMethod.Get, "/auth/cluster/users");
            accounts.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.Access);
            HttpResponseMessage refused = await anchor.Client.SendAsync(accounts);

            Assert.Equal(HttpStatusCode.ServiceUnavailable, refused.StatusCode);
            JsonElement body = await refused.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("not_the_anchor", body.GetProperty("error").GetProperty("code").GetString());
            Assert.Contains("node-b-auth", body.GetProperty("error").GetProperty("message").GetString());

            // And the holder is on a header, so a client can route rather than retry.
            Assert.Equal("node-b-auth", refused.Headers.GetValues("X-Kgsm-Auth-Holder").Single());
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
}

/// <summary>
/// The single write path for what a person may do, and the version every member orders by.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AnchorAccountWriteTests(AnchorFixture anchor)
{
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<string> AdminBearerAsync() =>
        (await anchor.SignedInAsync(KgsmTier.Admin, "writer-admin")).Session.Access;

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
        (KgsmUser only, AnchorFixture.Session session) = await anchor.SignedInAsync(KgsmTier.Admin, "only-admin");

        // Every other admin in the shared store stands down first, so this really is the last one.
        var others = (await anchor.Store.ListAsync())
            .Where(u => u.UserId != only.UserId && u.EffectiveTier == KgsmTier.Admin).ToList();
        foreach (KgsmUser other in others)
            await anchor.Store.UpdateAsync(other with { Tier = KgsmTier.Viewer });

        try
        {
            HttpResponseMessage refused = await PatchAsync(session.Access, only.UserId, new { tier = "viewer" });

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
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(KgsmTier.Operator, "nosy-writer");
        KgsmUser subject = await anchor.SeedAsync(Unique("subject-"), "a password", KgsmTier.Viewer);

        Assert.Equal(HttpStatusCode.Forbidden,
            (await PatchAsync(session.Access, subject.UserId, new { tier = "admin" })).StatusCode);
    }

    [Fact]
    public async Task An_account_that_does_not_exist_is_a_404()
    {
        string bearer = await AdminBearerAsync();
        Assert.Equal(HttpStatusCode.NotFound,
            (await PatchAsync(bearer, "usr_nothing", new { tier = "viewer" })).StatusCode);
    }
}
