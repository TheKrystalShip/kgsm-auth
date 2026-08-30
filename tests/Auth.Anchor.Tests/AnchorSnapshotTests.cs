using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Identity;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// What this anchor hands another member, and what it refuses to hand anybody.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AnchorSnapshotTests(AnchorFixture anchor)
{
    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    [Fact]
    public async Task A_caller_with_no_member_token_is_refused()
    {
        HttpResponseMessage response = await anchor.Client.GetAsync("/auth/cluster/snapshot");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_cluster_token", body.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_person_s_own_session_does_not_open_this_door()
    {
        string username = Unique("person-");
        await anchor.SeedAsync(username, "an admin session", KgsmTier.Admin);
        HttpResponseMessage signIn = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "an admin session" },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        string bearer = (await signIn.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("token").GetString()!;

        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/cluster/snapshot");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);

        // Two different kinds of caller and two different doors. An admin is a person; this answers
        // to members, and a person's session — however privileged — is not one.
        Assert.Equal(HttpStatusCode.Unauthorized, (await anchor.Client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task A_member_receives_every_account_with_its_version_and_no_secret()
    {
        string username = Unique("replicated-");
        KgsmUser user = await anchor.SeedAsync(username, "a real password", KgsmTier.Operator);
        await anchor.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Identity,
            "discord:" + Guid.NewGuid().ToString("N")[..8], null, "haru", DateTimeOffset.UtcNow, null));

        string token = anchor.MintMemberToken();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/cluster/snapshot");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await anchor.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string json = await response.Content.ReadAsStringAsync();
        AccountSnapshot? snapshot = JsonSerializer.Deserialize(
            json, AccountReplicationJson.Default.AccountSnapshot);

        Assert.NotNull(snapshot);
        AccountChange mine = snapshot.Accounts.Single(a => a.Account.UserId == user.UserId);
        Assert.Equal("operator", mine.Account.Tier);

        // Every account is published at a version a replica can act on: zero is what a replica holds
        // for "never heard of", so nothing at zero could ever be newer than what it has.
        Assert.All(snapshot.Accounts, a => Assert.True(a.Version > 0));

        // Both handles travel, because a session names its holder by one of them and a member that
        // lacks it cannot say who it has just verified — the account arrives, the signature checks,
        // and nothing joins the two. The password's HASH does not travel, which is the property:
        // a replica says what somebody may do and cannot let anybody in.
        Assert.Contains($"local:{user.UserId}", mine.Account.Identities.Select(i => i.Handle));
        Assert.Contains(
            mine.Account.Identities, i => i.Handle.StartsWith("discord:", StringComparison.Ordinal));
        Assert.DoesNotContain("AQAAAA", json);
        Assert.DoesNotContain("secret", json, StringComparison.OrdinalIgnoreCase);
    }

}
