using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// The doors that change an account rather than open one: a password, an account ending, and the
/// ways into one.
/// </summary>
/// <remarks>
/// They are the anchor's because the accounts are. A member writing any of them would land in that
/// member's replica, unversioned, and be overwritten by the next thing published about the account —
/// appearing to work and then quietly not having happened.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class AccountDoorTests(AnchorFixture anchor)
{
    private const string Long = "a long enough password";
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<string> BearerAsync(string username, string password)
    {
        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password }, Wire);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("token").GetString()!;
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

    private async Task<HttpResponseMessage> SignInRawAsync(string username, string password) =>
        await anchor.Client.PostAsJsonAsync("/auth/sign-in", new { username, password }, Wire);

    // ── A person's own password ───────────────────────────────────────────────

    [Fact]
    public async Task Changing_your_own_password_needs_the_one_you_hold()
    {
        string username = Unique("rotates-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        string bearer = await BearerAsync(username, Long);

        // A bearer left open on a shared machine is otherwise enough to lock somebody out of their
        // own account for good. It is the one door where being signed in is not the whole proof.
        HttpResponseMessage guessed = await SendAsync(HttpMethod.Post, "/auth/password", bearer,
            new { current = "not the password", password = "a different long password" });

        Assert.Equal(HttpStatusCode.Forbidden, guessed.StatusCode);

        HttpResponseMessage changed = await SendAsync(HttpMethod.Post, "/auth/password", bearer,
            new { current = Long, password = "a different long password" });

        Assert.Equal(HttpStatusCode.NoContent, changed.StatusCode);

        // The new one works and the old one does not, which is the whole of what "changed" means.
        Assert.Equal(HttpStatusCode.OK,
            (await SignInRawAsync(username, "a different long password")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SignInRawAsync(username, Long)).StatusCode);
    }

    [Fact]
    public async Task A_password_below_the_floor_is_refused()
    {
        string username = Unique("short-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        string bearer = await BearerAsync(username, Long);

        HttpResponseMessage response = await SendAsync(HttpMethod.Post, "/auth/password", bearer,
            new { current = Long, password = "short" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // The floor is read from the one constant every door reads, so it cannot drift low in one of
        // them. The message says the number, because a refusal that does not is a guess.
        JsonElement error = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("password_too_short", error.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains(
            Passwords.MinLength.ToString(),
            error.GetProperty("error").GetProperty("message").GetString());
    }

    [Fact]
    public async Task Your_own_password_change_is_recorded_as_yours()
    {
        string username = Unique("mine-");
        await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        string bearer = await BearerAsync(username, Long);

        await SendAsync(HttpMethod.Post, "/auth/password", bearer,
            new { current = Long, password = "a different long password" });

        JsonElement data = Assert.Single(
            anchor.Journal(AuthEvents.UserPasswordChanged),
            e => e.GetProperty("Data").GetProperty("Username").GetString() == username)
            .GetProperty("Data");

        // The whole point of recording it: somebody else setting your password reads completely
        // differently from you setting it, and a line that could not tell them apart would report a
        // takeover and a routine rotation identically.
        Assert.True(data.GetProperty("ByHolder").GetBoolean());
    }

    // ── An administrator's reset ──────────────────────────────────────────────

    [Fact]
    public async Task An_admin_sets_a_password_without_knowing_the_old_one()
    {
        string admin = Unique("resetter-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        string subject = Unique("reset-");
        KgsmUser user = await anchor.SeedAsync(subject, Long, KgsmTier.Viewer);

        // The case it exists for is a person who has lost theirs. Requiring the old one would make
        // the door useless for the only situation that reaches it.
        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{user.UserId}/password", bearer,
            new { password = "an administrator set this" });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await SignInRawAsync(subject, "an administrator set this")).StatusCode);

        JsonElement line = Assert.Single(
            anchor.Journal(AuthEvents.UserPasswordChanged),
            e => e.GetProperty("Data").GetProperty("Username").GetString() == subject);

        Assert.False(line.GetProperty("Data").GetProperty("ByHolder").GetBoolean());

        // The admin who acted is the actor; the account acted upon is in the payload.
        Assert.Equal($"local:{admin}", line.GetProperty("Actor").GetString());
    }

    [Fact]
    public async Task An_admin_reset_clears_the_lockout_it_resolves()
    {
        string admin = Unique("rescuer-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        string subject = Unique("locked-");
        KgsmUser user = await anchor.SeedAsync(subject, Long, KgsmTier.Viewer);

        for (int attempt = 0; attempt < 6; attempt++)
            await SignInRawAsync(subject, $"wrong-{attempt}");

        Assert.Equal(HttpStatusCode.TooManyRequests, (await SignInRawAsync(subject, Long)).StatusCode);

        await SendAsync(HttpMethod.Post, $"/auth/cluster/users/{user.UserId}/password", bearer,
            new { password = "an administrator set this" });

        // An admin resetting a password for somebody locked out of their own account has plainly
        // resolved what the lockout existed for. Leaving it standing makes the reset appear not to
        // have worked.
        Assert.Equal(HttpStatusCode.OK,
            (await SignInRawAsync(subject, "an administrator set this")).StatusCode);
    }

    [Fact]
    public async Task Setting_somebody_elses_password_needs_admin()
    {
        string viewer = Unique("nosy-");
        await anchor.SeedAsync(viewer, Long, KgsmTier.Viewer);
        string bearer = await BearerAsync(viewer, Long);

        KgsmUser target = await anchor.SeedAsync(Unique("target-"), Long, KgsmTier.Viewer);

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{target.UserId}/password", bearer,
            new { password = "taking this account" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SignInRawAsync(target.Username, Long)).StatusCode);
    }

    // ── An account ending ─────────────────────────────────────────────────────

    [Fact]
    public async Task Deleting_an_account_ends_it_and_records_what_it_was()
    {
        string admin = Unique("remover-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        string subject = Unique("removed-");
        KgsmUser user = await anchor.SeedAsync(subject, Long, KgsmTier.Operator);

        Assert.Equal(HttpStatusCode.NoContent,
            (await SendAsync(HttpMethod.Delete, $"/auth/cluster/users/{user.UserId}", bearer)).StatusCode);

        Assert.Null(await anchor.Store.FindByIdAsync(user.UserId));
        Assert.Equal(HttpStatusCode.Unauthorized, (await SignInRawAsync(subject, Long)).StatusCode);

        JsonElement data = Assert.Single(
            anchor.Journal(AuthEvents.UserDeleted),
            e => e.GetProperty("Data").GetProperty("Username").GetString() == subject)
            .GetProperty("Data");

        // The line outlives its subject, which is the point of a trail. What the account HELD is on
        // it, because "an operator was deleted" and "a viewer was deleted" are different facts and
        // the account is no longer there to be asked.
        Assert.Equal("operator", data.GetProperty("FromTier").GetString());
        Assert.Equal(JsonValueKind.Null, data.GetProperty("ToTier").ValueKind);
    }

    [Fact]
    public async Task The_only_administrator_cannot_be_deleted()
    {
        // Every other account this suite seeds is disposable; this one has to be the last admin, so
        // it is asserted against the store rather than assumed.
        string admin = Unique("sole-");
        KgsmUser self = await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        IReadOnlyList<KgsmUser> admins =
            [.. (await anchor.Store.ListAsync()).Where(u => u.EffectiveTier == KgsmTier.Admin)];

        if (admins.Count > 1)
        {
            // Another admin exists, so deletion is allowed and this asserts the other half of the
            // rule: the refusal is about the LAST one, not about administrators.
            Assert.Equal(HttpStatusCode.NoContent,
                (await SendAsync(HttpMethod.Delete, $"/auth/cluster/users/{self.UserId}", bearer))
                    .StatusCode);
            return;
        }

        HttpResponseMessage response =
            await SendAsync(HttpMethod.Delete, $"/auth/cluster/users/{self.UserId}", bearer);

        // An account store nobody can administer cannot be repaired through any surface.
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.NotNull(await anchor.Store.FindByIdAsync(self.UserId));
    }

    [Fact]
    public async Task Deleting_an_account_that_is_not_there_is_a_404()
    {
        string admin = Unique("hunter-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        HttpResponseMessage response =
            await SendAsync(HttpMethod.Delete, "/auth/cluster/users/usr_nothinghere", bearer);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain(
            anchor.Journal(AuthEvents.UserDeleted),
            e => e.GetProperty("Data").GetProperty("UserId").GetString() == "usr_nothinghere");
    }

    // ── Ways into an account ──────────────────────────────────────────────────

    [Fact]
    public async Task The_ways_into_an_account_are_listed_with_the_id_a_detach_names()
    {
        string username = Unique("linked-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        await AttachAsync(user, "discord", "discord:1234567890");

        string bearer = await BearerAsync(username, Long);
        JsonElement body = await (await SendAsync(HttpMethod.Get, "/auth/identities", bearer))
            .Content.ReadFromJsonAsync<JsonElement>();

        JsonElement identity = Assert.Single(body.GetProperty("identities").EnumerateArray());

        // The credential id, because a detach is addressed by id — an id a caller cannot learn makes
        // the door unreachable.
        Assert.False(string.IsNullOrEmpty(identity.GetProperty("credentialId").GetString()));
        Assert.Equal("discord", identity.GetProperty("provider").GetString());
        Assert.Equal("discord:1234567890", identity.GetProperty("handle").GetString());

        // The password is not listed as a way in, because there is nothing about it to detach. That
        // it EXISTS is said separately, since it is what decides whether removing the last identity
        // would leave a way in.
        Assert.True(body.GetProperty("hasPassword").GetBoolean());
    }

    [Fact]
    public async Task Detaching_an_identity_records_which_one_it_was()
    {
        string username = Unique("detaches-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        string credentialId = await AttachAsync(user, "discord", "discord:2233445566");

        string bearer = await BearerAsync(username, Long);

        Assert.Equal(HttpStatusCode.NoContent,
            (await SendAsync(HttpMethod.Delete, $"/auth/identities/{credentialId}", bearer)).StatusCode);

        JsonElement data = Assert.Single(
            anchor.Journal(AuthEvents.IdentityUnlinked),
            e => e.GetProperty("Data").GetProperty("Username").GetString() == username)
            .GetProperty("Data");

        // Read before it was detached: afterwards there is nothing left to say which identity this
        // was, and a line naming only an opaque id records that something was removed without saying
        // what.
        Assert.Equal("discord", data.GetProperty("Provider").GetString());
        Assert.Equal("discord:2233445566", data.GetProperty("Handle").GetString());
    }

    [Fact]
    public async Task The_last_way_into_an_account_is_refused()
    {
        string username = Unique("last-");
        KgsmUser user = await anchor.SeedAsync(username, Long, KgsmTier.Viewer);
        string credentialId = await AttachAsync(user, "discord", "discord:9988776655");

        string bearer = await BearerAsync(username, Long);

        // The password goes first, leaving the identity as the only way in.
        UserCredential password = (await anchor.Store.ListCredentialsAsync(user.UserId))
            .Single(c => c.Kind == CredentialKind.Password);
        await anchor.Store.RemoveCredentialAsync(password.CredentialId);

        HttpResponseMessage response =
            await SendAsync(HttpMethod.Delete, $"/auth/identities/{credentialId}", bearer);

        // An account with nothing attached is one its own holder cannot sign in to, and only an admin
        // can rescue. The rule lives at the door so every caller gets it.
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.NotEmpty(await anchor.Store.ListCredentialsAsync(user.UserId));
    }

    [Fact]
    public async Task Somebody_elses_credential_answers_the_same_as_one_that_does_not_exist()
    {
        string mine = Unique("scoped-");
        await anchor.SeedAsync(mine, Long, KgsmTier.Viewer);
        string bearer = await BearerAsync(mine, Long);

        KgsmUser stranger = await anchor.SeedAsync(Unique("stranger-"), Long, KgsmTier.Viewer);
        string theirs = await AttachAsync(stranger, "discord", "discord:1122334455");

        HttpResponseMessage response =
            await SendAsync(HttpMethod.Delete, $"/auth/identities/{theirs}", bearer);

        // 404, the same as an id that is not real. Telling those apart would say whether an id
        // exists, and the id is the whole of what a caller supplies.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains(
            await anchor.Store.ListCredentialsAsync(stranger.UserId),
            c => c.CredentialId == theirs);
    }

    /// <summary>Attach an external identity to an account, as a provider sign-in would have.</summary>
    private async Task<string> AttachAsync(KgsmUser user, string provider, string handle)
    {
        string credentialId = UserIds.NewCredentialId();
        await anchor.Store.AddCredentialAsync(new UserCredential(
            credentialId, user.UserId, CredentialKind.Identity, handle, Secret: null,
            Label: provider, Created: DateTimeOffset.UtcNow, LastUsed: null));

        return credentialId;
    }
}
