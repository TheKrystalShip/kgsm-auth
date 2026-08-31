using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using Microsoft.IdentityModel.JsonWebTokens;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// The devices somebody is signed in on, and ending them.
/// </summary>
/// <remarks>
/// These exist only on the anchor. A member verifies a cluster session offline against a published
/// key and stores nothing, so a member asked what devices an account holds answers honestly with
/// none — which renders as an empty card rather than as a wrong question, and is the failure this
/// surface exists to prevent.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class SessionSurfaceTests(AnchorFixture anchor)
{
    private const string Long = "a long enough password";
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private sealed record Session(string Bearer, string Sid);

    private async Task<Session> SignInAsync(string username, string device = "a browser")
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/sign-in")
        {
            Content = JsonContent.Create(new { username, password = Long }, options: Wire),
        };
        request.Headers.UserAgent.ParseAdd(device);

        HttpResponseMessage response = await anchor.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string bearer = (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("token").GetString()!;

        return new Session(bearer, new JsonWebToken(bearer).GetClaim(KgsmAuthClaims.SessionId).Value);
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string path, string bearer, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null)
            request.Content = JsonContent.Create(body, options: Wire);

        return await anchor.Client.SendAsync(request);
    }

    private async Task<JsonElement[]> SessionsAsync(string bearer, string? userId = null)
    {
        string path = userId is null ? "/auth/sessions" : $"/auth/sessions?userId={userId}";
        JsonElement body = await (await SendAsync(HttpMethod.Get, path, bearer))
            .Content.ReadFromJsonAsync<JsonElement>();

        return [.. body.GetProperty("data").EnumerateArray()];
    }

    [Fact]
    public async Task Every_device_is_listed_with_the_calling_one_marked()
    {
        string username = Unique("devices-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);

        await SignInAsync(username, "a phone");
        Session current = await SignInAsync(username, "a laptop");

        JsonElement[] sessions = await SessionsAsync(current.Bearer);

        Assert.Equal(2, sessions.Length);
        Assert.Contains(sessions, s => s.GetProperty("userAgent").GetString() == "a phone");

        // True on exactly one row, so a surface can say "this device" rather than making somebody
        // work out which is theirs.
        JsonElement here = Assert.Single(sessions, s => s.GetProperty("current").GetBoolean());
        Assert.Equal(current.Sid, here.GetProperty("sid").GetString());
    }

    [Fact]
    public async Task A_session_reached_through_a_different_door_is_still_listed()
    {
        string username = Unique("bothdoors-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);

        string handle = "discord:" + Guid.NewGuid().ToString("N")[..12];
        await anchor.Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Identity, handle, Secret: null,
            Label: "discord", Created: DateTimeOffset.UtcNow, LastUsed: null));

        Session password = await SignInAsync(username, "a laptop");

        // What the provider door mints: a session keyed by the handle somebody ARRIVED with, which
        // is not the one a password sign-in is keyed by. Asking under a single handle would find half
        // the devices and report the other half as nothing.
        await anchor.Service<TheKrystalShip.KGSM.Auth.Sessions.ISessionRegistry>().CreateAsync(
            new TheKrystalShip.KGSM.Auth.Sessions.SessionRegistration(
                "sid_" + Guid.NewGuid().ToString("N"), handle, AnchorFixture.ClusterId,
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), "a phone", "jti"));

        JsonElement[] sessions = await SessionsAsync(password.Bearer);

        Assert.Equal(2, sessions.Length);
        Assert.Contains(sessions, s => s.GetProperty("userAgent").GetString() == "a phone");
    }

    [Fact]
    public async Task A_session_that_was_ended_is_no_longer_a_device()
    {
        string username = Unique("ended-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);

        Session other = await SignInAsync(username, "a phone");
        Session current = await SignInAsync(username, "a laptop");

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/session/revoke", current.Bearer, new { sid = other.Sid });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("revoked").GetInt32());

        // A revoked row is kept as a tombstone until the sweep takes it. Listing those would show
        // somebody a device they had already signed out.
        JsonElement remaining = Assert.Single(await SessionsAsync(current.Bearer));
        Assert.Equal(current.Sid, remaining.GetProperty("sid").GetString());
    }

    [Fact]
    public async Task Somebody_elses_session_answers_the_same_as_one_that_does_not_exist()
    {
        string mine = Unique("scoped-");
        await anchor.SeedAsync(mine, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(mine);

        string stranger = Unique("stranger-");
        await anchor.SeedAsync(stranger, Long, KgsmTier.Viewer);
        Session theirs = await SignInAsync(stranger);

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/session/revoke", session.Bearer, new { sid = theirs.Sid });

        // A sid is opaque and unguessable, but one that leaks must not become a way to sign somebody
        // else out — and "not yours" answers the same as "not real", because telling those apart
        // says whether an id exists.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Single(await SessionsAsync(theirs.Bearer));
    }

    [Fact]
    public async Task Logging_out_everywhere_ends_every_device_and_records_the_count()
    {
        string username = Unique("everywhere-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);

        await SignInAsync(username, "a phone");
        await SignInAsync(username, "a tablet");
        Session current = await SignInAsync(username, "a laptop");

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/session/revoke", current.Bearer, new { all = true });

        Assert.Equal(3, (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("revoked").GetInt32());

        JsonElement data = Assert.Single(
            anchor.Journal(AuthEvents.SessionRevoked),
            e => e.GetProperty("Data").GetProperty("UserId").GetString() == user.UserId)
            .GetProperty("Data");

        // A sweep names how many it ended and no single session; one revocation names the session and
        // no count. Neither fabricates the other.
        Assert.Equal(SessionRevokeScopes.All, data.GetProperty("Scope").GetString());
        Assert.Equal(3, data.GetProperty("Count").GetInt32());
        Assert.Equal(JsonValueKind.Null, data.GetProperty("Sid").ValueKind);
    }

    [Fact]
    public async Task An_admin_ends_somebody_elses_sessions_and_a_viewer_cannot()
    {
        string admin = Unique("cuts-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        Session adminSession = await SignInAsync(admin);

        string subject = Unique("cut-");
        KgsmUser user = await anchor.SeedAsync(subject, Long, KgsmTier.Viewer);
        Session theirs = await SignInAsync(subject, "a phone");

        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{user.UserId}/sessions/revoke-all",
            theirs.Bearer)).StatusCode);

        HttpResponseMessage cut = await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{user.UserId}/sessions/revoke-all",
            adminSession.Bearer);

        Assert.Equal(HttpStatusCode.OK, cut.StatusCode);
        Assert.Equal(1, (await cut.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("revoked").GetInt32());

        // The one a person cannot do for themselves, and the one an incident needs: every device
        // stops without waiting for a bearer to expire on each.
        Assert.Empty(await SessionsAsync(adminSession.Bearer, user.UserId));
    }

    [Fact]
    public async Task An_admin_cutting_an_account_with_nothing_live_is_not_an_error()
    {
        string admin = Unique("quiet-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        Session adminSession = await SignInAsync(admin);

        KgsmUser idle = await anchor.SeedAsync(Unique("idle-"), Long, KgsmTier.Viewer);

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{idle.UserId}/sessions/revoke-all",
            adminSession.Bearer);

        // Zero is what the admin wanted. Reporting it as a failure would invite them to try again.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("revoked").GetInt32());
    }

    [Fact]
    public async Task A_viewer_asking_for_somebody_elses_devices_is_given_their_own()
    {
        string username = Unique("curious-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        Session session = await SignInAsync(username);

        KgsmUser other = await anchor.SeedAsync(Unique("other-"), Long, KgsmTier.Viewer);
        await SignInAsync(other.Username, "somebody else's phone");

        JsonElement[] sessions = await SessionsAsync(session.Bearer, other.UserId);

        // Their own, rather than a refusal — a refusal that named the account would confirm it
        // exists, and a viewer has no business learning that from here.
        Assert.All(sessions, s => Assert.NotEqual(
            "somebody else's phone", s.GetProperty("userAgent").GetString()));
    }
}
