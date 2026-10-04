using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using TheKrystalShip.Auth.Journal;
using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// The devices somebody is signed in on, as another person managing accounts reads and ends them.
/// </summary>
/// <remarks>
/// These exist only on the anchor. A member verifies a cluster session offline against a published
/// key and stores nothing, so a member asked what devices an account holds answers honestly with
/// none — which renders as an empty card rather than as a wrong question, and is the failure this
/// surface exists to prevent. A person's own list is the account page's.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class SessionSurfaceTests(AnchorFixture anchor)
{
    private const string Long = "a long enough password";

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string bearer)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await anchor.Client.SendAsync(request);
    }

    /// <summary>The sessions a surface holds for an account — each browser's sign-in here left out.</summary>
    private async Task<JsonElement[]> DevicesAsync(string bearer, string userId)
    {
        HttpResponseMessage response = await SendAsync(HttpMethod.Get, $"/auth/cluster/users/{userId}/sessions", bearer);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();

        return [.. body.GetProperty("data").EnumerateArray()
            .Where(s => !s.TryGetProperty("kind", out JsonElement kind) || kind.ValueKind == JsonValueKind.Null)];
    }

    [Fact]
    public async Task Every_device_is_listed_with_the_calling_one_marked()
    {
        KgsmUser owner = await anchor.SeedAsync(Unique("devices-"), Long, owner: true);
        await anchor.SignInAsync(owner, "a phone");
        AnchorFixture.Session current = await anchor.SignInAsync(owner, "a laptop");

        JsonElement[] sessions = await DevicesAsync(current.Access, owner.UserId);

        Assert.Equal(2, sessions.Length);
        Assert.Contains(sessions, s => s.GetProperty("userAgent").GetString() == "a phone");

        // True on exactly one row, so somebody reading their own account sees which device is
        // the one they are using.
        JsonElement here = Assert.Single(sessions, s => s.GetProperty("current").GetBoolean());
        Assert.Equal(current.Sid, here.GetProperty("sid").GetString());
    }

    [Fact]
    public async Task A_session_reached_through_a_different_door_is_still_listed()
    {
        (_, AnchorFixture.Session owner) = await anchor.SignedInAsync(owner: true, "lister");
        KgsmUser user = await anchor.SeedAsync(Unique("bothdoors-"), Long, owner: false);

        string handle = "discord:" + Guid.NewGuid().ToString("N")[..12];
        await anchor.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Identity, handle, Secret: null,
            Label: "discord", Created: DateTimeOffset.UtcNow, LastUsed: null));

        await anchor.SignInAsync(user, "a laptop");

        // A session is keyed by the handle somebody ARRIVED with, which for a provider is not the one a
        // password sign-in is keyed by. Asking under a single handle would find half the devices and
        // report the other half as nothing.
        await anchor.SignInAsync(user, "a phone", new KgsmIdentity("discord", handle[8..], user.Username, user.Username, null, []));

        JsonElement[] sessions = await DevicesAsync(owner.Access, user.UserId);

        Assert.Equal(2, sessions.Length);
        Assert.Contains(sessions, s => s.GetProperty("userAgent").GetString() == "a phone");
    }

    [Fact]
    public async Task Listing_somebody_s_devices_needs_the_action()
    {
        (_, AnchorFixture.Session bystander) = await anchor.SignedInAsync(owner: false, "curious");
        KgsmUser other = await anchor.SeedAsync(Unique("other-"), Long, owner: false);

        Assert.Equal(HttpStatusCode.Forbidden,
            (await SendAsync(HttpMethod.Get, $"/auth/cluster/users/{other.UserId}/sessions", bystander.Access)).StatusCode);
    }

    [Fact]
    public async Task An_Owner_ends_somebody_elses_sessions_and_they_cannot_end_their_own_this_way()
    {
        (_, AnchorFixture.Session owner) = await anchor.SignedInAsync(owner: true, "cuts");
        KgsmUser user = await anchor.SeedAsync(Unique("cut-"), Long, owner: false);
        AnchorFixture.Session theirs = await anchor.SignInAsync(user, "a phone");

        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{user.UserId}/sessions/revoke-all", theirs.Access)).StatusCode);

        HttpResponseMessage cut = await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{user.UserId}/sessions/revoke-all", owner.Access);

        Assert.Equal(HttpStatusCode.OK, cut.StatusCode);

        // The surface session and the browser's sign-in it was minted under: every way in stops,
        // without waiting for a bearer to expire on each.
        Assert.Equal(2, (await cut.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
        Assert.Empty(await DevicesAsync(owner.Access, user.UserId));
    }

    [Fact]
    public async Task One_session_is_ended_without_ending_the_rest()
    {
        (KgsmUser ownerUser, AnchorFixture.Session owner) = await anchor.SignedInAsync(owner: true, "surgeon");
        KgsmUser user = await anchor.SeedAsync(Unique("patient-"), Long, owner: false);
        AnchorFixture.Session suspicious = await anchor.SignInAsync(user, "a phone");
        await anchor.SignInAsync(user, "a laptop");

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{user.UserId}/sessions/{suspicious.Sid}/revoke", owner.Access);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());

        // The point of the narrow door: one device stops and the person is not disturbed mid-task.
        // Somebody left only "sign them out everywhere" reaches for it because it is what exists.
        JsonElement left = Assert.Single(await DevicesAsync(owner.Access, user.UserId));
        Assert.Equal("a laptop", left.GetProperty("userAgent").GetString());

        JsonElement line = Assert.Single(
            anchor.Journal(AuthEvents.SessionRevoked),
            e => e.GetProperty("Data").GetProperty("UserId").GetString() == user.UserId);

        // Somebody else's, naming the one session. The subject is on the row and the actor is whoever
        // ended it, so "who did this" and "to whom" never have to be told apart by reading a sentence.
        Assert.Equal(SessionRevokeScopes.Other, line.GetProperty("Data").GetProperty("Scope").GetString());
        Assert.Equal(suspicious.Sid, line.GetProperty("Data").GetProperty("Sid").GetString());
        Assert.Equal(ownerUser.AsIdentity().ActorString, line.GetProperty("Actor").GetString());
    }

    [Fact]
    public async Task A_session_belonging_to_a_different_account_is_not_found_under_this_one()
    {
        (_, AnchorFixture.Session owner) = await anchor.SignedInAsync(owner: true, "mistaken");
        KgsmUser one = await anchor.SeedAsync(Unique("one-"), Long, owner: false);
        KgsmUser two = await anchor.SeedAsync(Unique("two-"), Long, owner: false);
        AnchorFixture.Session belongsToTwo = await anchor.SignInAsync(two, "a phone");

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{one.UserId}/sessions/{belongsToTwo.Sid}/revoke", owner.Access);

        // Somebody acting on the wrong account is told they have the wrong account, rather than shown
        // a stranger's session — and the session survives.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Single(await DevicesAsync(owner.Access, two.UserId));
    }

    [Fact]
    public async Task Ending_one_of_somebody_elses_sessions_needs_the_action()
    {
        (_, AnchorFixture.Session bystander) = await anchor.SignedInAsync(owner: false, "meddler");
        (_, AnchorFixture.Session owner) = await anchor.SignedInAsync(owner: true, "witness");
        KgsmUser target = await anchor.SeedAsync(Unique("targeted-"), Long, owner: false);
        AnchorFixture.Session theirs = await anchor.SignInAsync(target, "a phone");

        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{target.UserId}/sessions/{theirs.Sid}/revoke",
            bystander.Access)).StatusCode);

        Assert.Single(await DevicesAsync(owner.Access, target.UserId));
    }

    [Fact]
    public async Task Cutting_an_account_with_nothing_live_is_not_an_error()
    {
        (_, AnchorFixture.Session owner) = await anchor.SignedInAsync(owner: true, "quiet");
        KgsmUser idle = await anchor.SeedAsync(Unique("idle-"), Long, owner: false);

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{idle.UserId}/sessions/revoke-all", owner.Access);

        // Zero is what they wanted. Reporting it as a failure would invite them to try again.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
    }
}
