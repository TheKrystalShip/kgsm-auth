using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// What the anchor records about the cluster's accounts.
/// </summary>
/// <remarks>
/// <para>
/// The anchor is the only thing that witnesses a sign-in for the whole cluster, so a line it does not
/// write is a fact that exists nowhere. That is what these assert against: not that a call succeeded,
/// but that the record of it is on disk in the shape a reader deserializes.
/// </para>
/// <para>
/// The bytes are read off the file rather than through a reader's own type, deliberately. A consumer
/// establishes the shape by deserializing, and a field spelled wrong lands as a null instead of an
/// error — so a test sharing that deserializer would agree with the writer about a name neither of
/// them has right.
/// </para>
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class AnchorJournalTests(AnchorFixture anchor)
{
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private static string? Text(JsonElement data, string field) =>
        data.GetProperty(field).ValueKind == JsonValueKind.Null
            ? null
            : data.GetProperty(field).GetString();

    /// <summary>The one line of <paramref name="type"/> naming <paramref name="username"/>.</summary>
    private JsonElement Line(string type, string username)
    {
        return Assert.Single(
            anchor.Journal(type), e => Text(e.GetProperty("Data"), "Username") == username);
    }

    // ── A session beginning ───────────────────────────────────────────────────

    [Fact]
    public async Task A_password_sign_in_is_recorded_with_the_session_it_minted()
    {
        string username = Unique("recorded-");
        KgsmUser user = await anchor.SeedAsync(username, "correct horse battery", KgsmTier.Operator);

        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "correct horse battery" }, Wire);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        JsonElement session = await response.Content.ReadFromJsonAsync<JsonElement>();
        JsonElement line = Line(AuthEvents.SignedIn, username);
        JsonElement data = line.GetProperty("Data");

        Assert.Equal(user.UserId, Text(data, "UserId"));

        // The HANDLE, which is keyed on the opaque account id — a username is renameable, and keying
        // on one detaches a person from their own sessions the day they change it. The actor below
        // is the readable half, and the two being different strings is the point of both.
        Assert.Equal($"local:{user.UserId}", Text(data, "Identity"));
        Assert.Equal("local", Text(data, "Provider"));
        Assert.Equal("operator", Text(data, "Tier"));

        // The sid pairs a sign-in with its sign-out. A row that could not be paired would leave a
        // reader unable to say how long anybody was signed in for.
        Assert.False(string.IsNullOrEmpty(Text(data, "Sid")));

        // A vouch is one node asserting an identity to another, and an anchor is the thing that
        // makes vouching unnecessary. Written as a real null, never as an empty string.
        Assert.Equal(JsonValueKind.Null, data.GetProperty("PeerNode").ValueKind);

        // The identity that arrived, not the daemon that minted the token. Naming the component
        // would hide who came through the door.
        Assert.Equal($"local:{username}", line.GetProperty("Actor").GetString());

        Assert.False(string.IsNullOrEmpty(session.GetProperty("token").GetString()));
    }

    [Fact]
    public async Task A_sign_in_that_did_not_happen_is_not_recorded()
    {
        string username = Unique("refused-");
        await anchor.SeedAsync(username, "correct horse battery", KgsmTier.Viewer);

        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "not the password" }, Wire);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // The attempt is in the daemon's log, where an operator can read the name that was tried.
        // It is not in the record, because nobody signed in — and an audit page that showed a
        // failure the same way it shows a success would report an attacker as a visitor.
        Assert.DoesNotContain(
            anchor.Journal(AuthEvents.SignedIn), e => Text(e.GetProperty("Data"), "Username") == username);
    }

    // ── A session ending ──────────────────────────────────────────────────────

    [Fact]
    public async Task A_sign_out_is_recorded_against_the_session_it_ended()
    {
        string username = Unique("left-");
        await anchor.SeedAsync(username, "correct horse battery", KgsmTier.Viewer);

        JsonElement session = await (await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "correct horse battery" }, Wire))
            .Content.ReadFromJsonAsync<JsonElement>();

        string sid = Text(Line(AuthEvents.SignedIn, username).GetProperty("Data"), "Sid")!;

        HttpResponseMessage signedOut = await anchor.Client.PostAsJsonAsync(
            "/auth/session/sign-out", new { refresh = session.GetProperty("refresh").GetString() }, Wire);
        Assert.Equal(HttpStatusCode.NoContent, signedOut.StatusCode);

        // The same session id on both lines. It is the whole reason a sign-out carries one.
        Assert.Equal(sid, Text(Line(AuthEvents.SignedOut, username).GetProperty("Data"), "Sid"));
    }

    [Fact]
    public async Task Signing_out_of_a_session_that_already_ended_records_nothing_more()
    {
        string username = Unique("twice-");
        await anchor.SeedAsync(username, "correct horse battery", KgsmTier.Viewer);

        JsonElement session = await (await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = "correct horse battery" }, Wire))
            .Content.ReadFromJsonAsync<JsonElement>();

        object body = new { refresh = session.GetProperty("refresh").GetString() };
        await anchor.Client.PostAsJsonAsync("/auth/session/sign-out", body, Wire);

        HttpResponseMessage again = await anchor.Client.PostAsJsonAsync(
            "/auth/session/sign-out", body, Wire);

        // Still 204: a caller wanting to be signed out is signed out, and reporting "there was no
        // such session" would tell a stranger holding a stolen token whether it was still live.
        Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);

        // One line, though. A session ends once, and a second would make a reader counting sign-outs
        // against sign-ins find more of the first.
        Assert.Single(
            anchor.Journal(AuthEvents.SignedOut), e => Text(e.GetProperty("Data"), "Username") == username);
    }

    // ── An account arriving ───────────────────────────────────────────────────

    [Fact]
    public async Task Registering_records_the_account_and_the_session_it_was_given()
    {
        string username = Unique("newcomer-");

        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/register", new { username, password = "a long enough password" }, Wire);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        JsonElement data = Line(AuthEvents.UserProvisioned, username).GetProperty("Data");

        // A provision has no "from": the account did not exist a moment ago, and a from/to pair here
        // would invent a previous state to have moved out of.
        Assert.Equal(JsonValueKind.Null, data.GetProperty("FromTier").ValueKind);
        Assert.Equal(JsonValueKind.Null, data.GetProperty("FromStatus").ValueKind);
        Assert.Equal("none", Text(data, "ToTier"));

        // Pending is what a Control Panel raises an approval request from. A provisioning that landed
        // anywhere else is not somebody waiting on an administrator.
        Assert.Equal("pending", Text(data, "ToStatus"));

        // The session it was handed is recorded like any other, because it is one.
        Assert.Equal("none", Text(Line(AuthEvents.SignedIn, username).GetProperty("Data"), "Tier"));
    }

    [Fact]
    public async Task A_registration_that_was_refused_leaves_no_account_line()
    {
        string username = Unique("taken-");
        await anchor.SeedAsync(username, "correct horse battery", KgsmTier.Viewer);

        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/register", new { username, password = "a long enough password" }, Wire);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.DoesNotContain(
            anchor.Journal(AuthEvents.UserProvisioned),
            e => Text(e.GetProperty("Data"), "Username") == username);
    }

    // ── Authority moving ──────────────────────────────────────────────────────

    [Fact]
    public async Task A_tier_change_and_a_status_change_are_two_lines()
    {
        string admin = Unique("mover-");
        await anchor.SeedAsync(admin, "correct horse battery", KgsmTier.Admin);
        string bearer = await BearerAsync(admin, "correct horse battery");

        string subject = Unique("moved-");
        KgsmUser user = await anchor.SeedAsync(
            subject, "correct horse battery", KgsmTier.None, UserStatus.Pending);

        using var request = new HttpRequestMessage(
            HttpMethod.Patch, $"/auth/cluster/users/{user.UserId}")
        {
            Content = JsonContent.Create(new { tier = "operator", status = "active" }, options: Wire),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);

        Assert.Equal(HttpStatusCode.OK, (await anchor.Client.SendAsync(request)).StatusCode);

        // Two facts changed, so two lines. An access review reads for a tier change OR for an
        // approval; one combined line would make both queries a text search over a sentence.
        JsonElement tier = Line(AuthEvents.UserTierChanged, subject).GetProperty("Data");
        Assert.Equal("none", Text(tier, "FromTier"));
        Assert.Equal("operator", Text(tier, "ToTier"));

        JsonElement approved = Line(AuthEvents.UserApproved, subject).GetProperty("Data");
        Assert.Equal("pending", Text(approved, "FromStatus"));
        Assert.Equal("active", Text(approved, "ToStatus"));

        // The admin who acted is the actor; the account acted upon is in the payload. "Who did this"
        // and "to whom" never have to be told apart by reading a sentence.
        Assert.Equal($"local:{admin}",
            Line(AuthEvents.UserTierChanged, subject).GetProperty("Actor").GetString());
    }

    [Fact]
    public async Task A_patch_that_changes_nothing_records_nothing()
    {
        string admin = Unique("still-");
        await anchor.SeedAsync(admin, "correct horse battery", KgsmTier.Admin);
        string bearer = await BearerAsync(admin, "correct horse battery");

        string subject = Unique("unchanged-");
        KgsmUser user = await anchor.SeedAsync(subject, "correct horse battery", KgsmTier.Viewer);

        using var request = new HttpRequestMessage(
            HttpMethod.Patch, $"/auth/cluster/users/{user.UserId}")
        {
            Content = JsonContent.Create(new { tier = "viewer" }, options: Wire),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);

        Assert.Equal(HttpStatusCode.OK, (await anchor.Client.SendAsync(request)).StatusCode);

        // The write happened and the version moved; nothing about the account's authority did. A line
        // per request rather than per change would fill an access review with rows saying nothing.
        Assert.DoesNotContain(
            anchor.Journal(AuthEvents.UserTierChanged),
            e => Text(e.GetProperty("Data"), "Username") == subject);
    }

    // ── A run of guesses ──────────────────────────────────────────────────────

    [Fact]
    public async Task The_attempt_that_locks_an_account_is_recorded_once_however_long_the_run()
    {
        string username = Unique("guessed-");
        KgsmUser user = await anchor.SeedAsync(username, "correct horse battery", KgsmTier.Viewer);

        // Past the policy's threshold, and then well past it. Every attempt after the lock is refused
        // by the lock rather than by the password.
        for (int attempt = 0; attempt < 9; attempt++)
        {
            await anchor.Client.PostAsJsonAsync(
                "/auth/sign-in", new { username, password = $"wrong-{attempt}" }, Wire);
        }

        // One line, not one per guess. Whoever is guessing retries at once, so a line per refusal
        // would be exactly the flood that buries the line reporting the run.
        JsonElement line = Line(AuthEvents.LockedOut, username);
        JsonElement data = line.GetProperty("Data");

        Assert.Equal(user.UserId, Text(data, "UserId"));
        Assert.Equal($"local:{user.UserId}", Text(data, "Identity"));

        // The attempt that tripped it, so the count is the threshold rather than however many times
        // the attacker went on knocking.
        Assert.Equal(4, data.GetProperty("FailedCount").GetInt32());
        Assert.True(data.GetProperty("Until").GetDateTimeOffset() > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task A_username_that_matches_nobody_is_never_recorded()
    {
        string username = Unique("ghost-");

        for (int attempt = 0; attempt < 9; attempt++)
        {
            await anchor.Client.PostAsJsonAsync(
                "/auth/sign-in", new { username, password = $"wrong-{attempt}" }, Wire);
        }

        // There is no account to lock, so there is nothing to name. Recording it would turn the
        // record into a list of strings a stranger chose, and hand anybody who can reach the door a
        // way to write into an audit page.
        Assert.DoesNotContain(
            anchor.Journal(AuthEvents.LockedOut), e => Text(e.GetProperty("Data"), "Username") == username);
    }

    private async Task<string> BearerAsync(string username, string password)
    {
        JsonElement session = await (await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password }, Wire))
            .Content.ReadFromJsonAsync<JsonElement>();

        return session.GetProperty("token").GetString()!;
    }
}
