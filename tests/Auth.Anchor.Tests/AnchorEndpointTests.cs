using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Cluster;
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
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(owner: false, "verified");

        // Exactly what a member has: the published document, fetched over HTTP, and nothing else.
        string published = await anchor.Client.GetStringAsync("/auth/cluster/public-key");
        SessionJwks? keys = SessionKeys.Read(published);
        Assert.NotNull(keys);

        TokenValidationResult result = await new JsonWebTokenHandler().ValidateTokenAsync(session.Access,
            new TokenValidationParameters
            {
                ValidIssuer = AnchorFixture.Issuer,
                ValidAudience = AnchorFixture.ClusterId,
                IssuerSigningKeys = SessionKeys.VerificationKeysFrom(keys),
                ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            });

        Assert.True(result.IsValid);

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
        (KgsmUser user, AnchorFixture.Session session) = await anchor.SignedInAsync(owner: true, "live");
        Assert.Equal(HttpStatusCode.OK, (await GetAsync("/auth/cluster/users", session.Access)).StatusCode);

        // Owner taken away after the session was minted — the bootstrap account is still an Owner, so
        // the cluster keeps one.
        Access.AuthoritySnapshot s = await anchor.Store.LoadAsync();
        string ownership = s.AssignmentsOf(user.UserId).Single(a => a.RoleId == Access.BuiltInRoles.OwnerId).AssignmentId;
        await anchor.Store.ApplyAsync(user.UserId, new Access.Revoke(ownership), await anchor.Store.VersionAsync(), DateTimeOffset.UtcNow);

        // The very next request: no cache stands between a revocation and its effect, and no session ended.
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
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(owner: true, "kinds");

        Assert.Equal(HttpStatusCode.Unauthorized, (await GetAsync("/auth/cluster/users", session.Refresh)).StatusCode);
    }

    [Fact]
    public async Task The_account_list_is_admin_only_and_matches_the_store()
    {
        (_, AnchorFixture.Session bystander) = await anchor.SignedInAsync(owner: false, "nosy");
        Assert.Equal(HttpStatusCode.Forbidden, (await GetAsync("/auth/cluster/users", bystander.Access)).StatusCode);

        (KgsmUser owner, AnchorFixture.Session session) = await anchor.SignedInAsync(owner: true, "boss");
        HttpResponseMessage response = await GetAsync("/auth/cluster/users", session.Access);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement page = await response.Content.ReadFromJsonAsync<JsonElement>();

        // The same answer the library gives against the same file.
        IReadOnlyList<KgsmUser> fromLibrary = await anchor.Store.ListAsync();
        Assert.Equal(fromLibrary.Count, page.GetProperty("data").GetArrayLength());

        JsonElement served = page.GetProperty("data").EnumerateArray()
            .Single(u => u.GetProperty("id").GetString() == owner.UserId);
        Assert.Equal("admitted", served.GetProperty("origin").GetString());
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
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(owner: true, "standdown");

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

    private async Task<string> OwnerBearerAsync() =>
        (await anchor.SignedInAsync(owner: true, "writer-owner")).Session.Access;

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
        string bearer = await OwnerBearerAsync();
        KgsmUser subject = await anchor.SeedAsync(Unique("subject-"), "a password", owner: false, UserStatus.Pending);

        JsonElement first = await (await PatchAsync(bearer, subject.UserId, new { status = "active" }))
            .Content.ReadFromJsonAsync<JsonElement>();
        JsonElement second = await (await PatchAsync(bearer, subject.UserId, new { status = "disabled" }))
            .Content.ReadFromJsonAsync<JsonElement>();

        // The version is the whole guarantee: a member that has not applied the second yet will
        // refuse the first if it arrives afterwards.
        Assert.True(second.GetProperty("version").GetInt64() > first.GetProperty("version").GetInt64());
        Assert.Equal("disabled", second.GetProperty("account").GetProperty("status").GetString());
    }

    [Fact]
    public async Task Approving_an_arrival_admits_it()
    {
        string bearer = await OwnerBearerAsync();
        KgsmUser subject = await anchor.SeedAsync(Unique("arrival-"), "a password", owner: false, UserStatus.Pending);
        await anchor.Store.UpdateAsync(subject with { Origin = AccountOrigin.Arrived });

        JsonElement account = (await (await PatchAsync(bearer, subject.UserId, new { status = "active" }))
            .Content.ReadFromJsonAsync<JsonElement>()).GetProperty("account");

        // Approved by somebody, so never expired as an arrival nobody looked at.
        Assert.Equal("active", account.GetProperty("status").GetString());
        Assert.Equal("admitted", account.GetProperty("origin").GetString());
    }

    [Fact]
    public async Task A_status_nobody_recognises_is_refused()
    {
        string bearer = await OwnerBearerAsync();
        KgsmUser subject = await anchor.SeedAsync(Unique("typo-"), "a password", owner: false);

        HttpResponseMessage response = await PatchAsync(bearer, subject.UserId, new { status = "actve" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_status", body.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal(UserStatus.Active, (await anchor.Store.FindByIdAsync(subject.UserId))!.Status);
    }

    [Fact]
    public async Task The_cluster_s_last_active_Owner_cannot_be_switched_off()
    {
        (KgsmUser only, AnchorFixture.Session session) = await anchor.SignedInAsync(owner: true, "only-owner");

        // Every other Owner in the shared store is switched off first, so this really is the last one.
        Access.AuthoritySnapshot s = await anchor.Store.LoadAsync();
        var others = (await anchor.Store.ListAsync())
            .Where(u => u.UserId != only.UserId && u.Status == UserStatus.Active && s.IsOwner(u.UserId)).ToList();
        foreach (KgsmUser other in others)
            await anchor.Store.UpdateAsync(other with { Status = UserStatus.Disabled });

        try
        {
            HttpResponseMessage refused = await PatchAsync(session.Access, only.UserId, new { status = "disabled" });

            // One account store for the whole cluster means this is not "no Owner on this machine" — it
            // is nobody, anywhere, able to undo it through any surface.
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            JsonElement body = await refused.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("last_owner", body.GetProperty("error").GetProperty("code").GetString());
            Assert.Equal(UserStatus.Active, (await anchor.Store.FindByIdAsync(only.UserId))!.Status);
        }
        finally
        {
            foreach (KgsmUser other in others)
                await anchor.Store.UpdateAsync(other);
        }
    }

    [Fact]
    public async Task Approving_takes_the_approve_action()
    {
        (_, AnchorFixture.Session session) = await anchor.SignedInAsync(owner: false, "nosy-writer");
        KgsmUser subject = await anchor.SeedAsync(Unique("subject-"), "a password", owner: false, UserStatus.Pending);

        HttpResponseMessage response = await PatchAsync(session.Access, subject.UserId, new { status = "active" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("not_permitted",
            (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task An_account_that_does_not_exist_is_a_404()
    {
        string bearer = await OwnerBearerAsync();
        Assert.Equal(HttpStatusCode.NotFound,
            (await PatchAsync(bearer, "usr_nothing", new { status = "active" })).StatusCode);
    }
}
