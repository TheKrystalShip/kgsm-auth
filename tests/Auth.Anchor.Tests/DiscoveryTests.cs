using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// What a client learns from one address.
/// </summary>
/// <remarks>
/// A panel deployed anywhere knows about no cluster until somebody types an address into it. What is
/// behind that address has to be establishable before anything else happens, and what the cluster
/// contains has to come from the anchor — because a member of a cluster tells nobody what cluster it
/// is in.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class DiscoveryTests(AnchorFixture anchor)
{
    private const string Long = "a long enough password";
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<string> BearerAsync()
    {
        string username = Unique("looker-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);

        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = Long }, Wire);

        return (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("token").GetString()!;
    }

    private async Task<JsonElement> RosterAsync(string bearer)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/cluster/members");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);

        HttpResponseMessage response = await anchor.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private static async Task Learn(
        AnchorFixture fixture, string memberId, string kind, string provenUrl,
        params MemberCandidate[] advertised)
    {
        await fixture.Service<MembersStore>().UpsertAsync(
            MemberRow.New(memberId, kind) with
            {
                Id = "member_" + memberId,
                Url = provenUrl,
                Candidates = MemberCandidates.Encode(advertised),
                Status = "reachable",
                MembershipState = "alive",
            },
            default);
    }

    // ── What this is ──────────────────────────────────────────────────────────

    [Fact]
    public async Task An_anchor_names_itself_to_anybody_who_asks()
    {
        // No bearer. A caller with no session is exactly who is asking what this is, and requiring one
        // would mean signing in to find out whether this is a thing you can sign in to.
        HttpResponseMessage response = await anchor.Client.GetAsync("/auth/identity");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        JsonElement identity = await response.Content.ReadFromJsonAsync<JsonElement>();

        // The name is what a client matches on. An anchor and a standalone node both answer
        // /auth/providers with a provider list, so that question cannot tell them apart — and
        // guessing wrong sends somebody to sign in at a machine that does not hold their account.
        Assert.Equal("kgsm-auth-anchor", identity.GetProperty("name").GetString());
        Assert.Equal(AnchorFixture.ClusterId, identity.GetProperty("cluster").GetString());
        Assert.True(identity.GetProperty("holding").GetBoolean());
    }

    [Fact]
    public async Task An_anchor_standing_by_says_so_rather_than_inviting_a_sign_in()
    {
        await anchor.StandingBy("somebody-else", async () =>
        {
            JsonElement identity = await (await anchor.Client.GetAsync("/auth/identity"))
                .Content.ReadFromJsonAsync<JsonElement>();

            // A second installation is a promotion candidate, not a second authority. Saying it holds
            // the accounts would send somebody to sign in at a door that refuses them.
            Assert.False(identity.GetProperty("holding").GetBoolean());
            Assert.Equal("kgsm-auth-anchor", identity.GetProperty("name").GetString());
        });
    }

    [Fact]
    public async Task What_this_is_carries_no_member_and_no_address()
    {
        string body = await anchor.Client.GetStringAsync("/auth/identity");

        // Unauthenticated, so it must not be a way to learn which machines exist. Knowing what the
        // cluster contains is behind a session; an address alone does not buy it.
        Assert.DoesNotContain("members", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("http", body, StringComparison.OrdinalIgnoreCase);
    }

    // ── What the cluster contains ─────────────────────────────────────────────

    [Fact]
    public async Task The_roster_is_behind_a_session()
    {
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await anchor.Client.GetAsync("/auth/cluster/members")).StatusCode);
    }

    [Fact]
    public async Task A_member_is_given_by_the_address_a_browser_can_reach()
    {
        await Learn(anchor, Unique("node-"), MemberKind.Node, provenUrl: "http://192.168.1.129:8080",
            new MemberCandidate("https://hotbox.example", true),
            new MemberCandidate("http://192.168.1.129:8080", false));

        JsonElement roster = await RosterAsync(await BearerAsync());

        JsonElement member = roster.GetProperty("members").EnumerateArray()
            .First(m => m.GetProperty("url").GetString() == "https://hotbox.example");

        // Never the address members prove between themselves. A secure page cannot fetch a plaintext
        // origin at all, so a peer-to-peer address registers a connection that can only ever read as
        // down — and a panel then reports a healthy machine as one that did not answer.
        Assert.Equal(MemberKind.Node, member.GetProperty("kind").GetString());
        Assert.Equal(AnchorFixture.ClusterId, roster.GetProperty("cluster").GetString());
    }

    [Fact]
    public async Task A_member_a_browser_cannot_reach_is_left_out_rather_than_given_an_unusable_address()
    {
        string lonely = Unique("lan-only-");
        await Learn(anchor, lonely, MemberKind.Node, provenUrl: "http://10.0.0.9:8080",
            new MemberCandidate("http://10.0.0.9:8080", false));

        JsonElement roster = await RosterAsync(await BearerAsync());

        // Genuinely not drivable from a browser. Saying so by omission is honest; handing over the
        // address it proved to other members is a machine that appears present and never works.
        Assert.DoesNotContain(
            roster.GetProperty("members").EnumerateArray(),
            m => m.GetProperty("memberId").GetString() == lonely);
    }

    [Fact]
    public async Task Other_anchors_are_listed_and_named_as_anchors()
    {
        string second = Unique("assistant-anchor-");
        await Learn(anchor, second, MemberKind.Anchor, provenUrl: "https://assistant.example",
            new MemberCandidate("https://assistant.example", true));

        JsonElement roster = await RosterAsync(await BearerAsync());

        // A cluster holds more than one anchor as capabilities are added, and exactly one of them
        // holds the accounts. The kind is what lets a client drive the others without ever trying to
        // sign in against them.
        JsonElement member = Assert.Single(
            roster.GetProperty("members").EnumerateArray(),
            m => m.GetProperty("memberId").GetString() == second);

        Assert.Equal(MemberKind.Anchor, member.GetProperty("kind").GetString());
    }
}
