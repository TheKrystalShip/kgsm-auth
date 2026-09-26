using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// What an administrator does to somebody's account: making one, setting its password, ending it.
/// </summary>
/// <remarks>
/// They are the anchor's because the accounts are. A member writing any of them would land in that
/// member's replica, unversioned, and be overwritten by the next thing published about the account —
/// appearing to work and then quietly not having happened. What a person changes about their own
/// account is the account page's, and its suite.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class AccountDoorTests(AnchorFixture anchor)
{
    private const string Long = "a long enough password";
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<string> BearerAsync(string username, string password) =>
        (await anchor.SignInAsync((await anchor.Store.FindByUsernameAsync(username))!)).Access;

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string path, string bearer, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null)
            request.Content = JsonContent.Create(body, options: Wire);

        return await anchor.Client.SendAsync(request);
    }

    /// <summary>Whether a password signs in: the provider's credential post, as its page sends it.</summary>
    private async Task<HttpResponseMessage> SignInRawAsync(string username, string password)
    {
        using HttpClient browser = await SignInPage.OpenAsync(anchor);
        return await browser.SendAsync(SignInPage.Post("/authorize/credentials", new { username, password }));
    }

    // ── An account arriving ───────────────────────────────────────────────────

    [Fact]
    public async Task An_admin_creates_an_admitted_account_holding_nothing_yet()
    {
        string admin = Unique("creator-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        string subject = Unique("created-");
        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/cluster/users", bearer,
            new { username = subject, password = Long });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        JsonElement account = await response.Content.ReadFromJsonAsync<JsonElement>();

        // Made by somebody, which is what expiry reads to tell an admitted account from one that
        // arrived on its own and was never looked at.
        Assert.Equal("admitted", account.GetProperty("origin").GetString());
        Assert.True(account.GetProperty("hasPassword").GetBoolean());

        // It holds only everyone: assigning it roles is the next, separate act.
        Assert.Empty((await anchor.Store.LoadAsync()).AssignmentsOf(account.GetProperty("id").GetString()!));

        Assert.Equal(HttpStatusCode.OK, (await SignInRawAsync(subject, Long)).StatusCode);

        JsonElement data = Assert.Single(
            anchor.Journal(AuthEvents.UserProvisioned),
            e => e.GetProperty("Data").GetProperty("Username").GetString() == subject)
            .GetProperty("Data");

        Assert.Equal("active", data.GetProperty("ToStatus").GetString());
        Assert.Equal(JsonValueKind.Null, data.GetProperty("FromStatus").ValueKind);
    }

    [Fact]
    public async Task An_account_can_be_created_for_somebody_who_will_only_arrive_by_provider()
    {
        string admin = Unique("provisioner-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        string subject = Unique("awaited-");
        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/cluster/users", bearer,
            new { username = subject });

        // No password, deliberately. The account exists and is approved before its owner has ever
        // signed in, which is the whole point of an admin creating one.
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.False((await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("hasPassword").GetBoolean());
    }

    [Fact]
    public async Task A_new_account_cannot_be_created_already_switched_off()
    {
        string admin = Unique("offswitch-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/cluster/users", bearer,
            new { username = Unique("stillborn-"), status = "disabled" });

        // A shape with no use: an admin wanting that creates it and disables it, and the trail then
        // says both things happened rather than one thing that reads like neither.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_weak_password_is_refused_at_creation_like_everywhere_else()
    {
        string admin = Unique("floor-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/cluster/users", bearer,
            new { username = Unique("weak-"), password = "short" });

        // Or the door with the least scrutiny becomes the one that admits the weakest password on
        // the cluster.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Creating_an_account_takes_the_create_action()
    {
        string viewer = Unique("presumptuous-");
        await anchor.SeedAsync(viewer, Long, KgsmTier.Viewer);
        string bearer = await BearerAsync(viewer, Long);

        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/cluster/users", bearer,
            new { username = Unique("uninvited-") });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
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

        // The line outlives its subject, which is the point of a trail, and names who removed it.
        Assert.Equal(user.UserId, data.GetProperty("UserId").GetString());
        Assert.StartsWith("local:", Assert.Single(
            anchor.Journal(AuthEvents.UserDeleted),
            e => e.GetProperty("Data").GetProperty("Username").GetString() == subject).GetProperty("Actor").GetString());
    }

    [Fact]
    public async Task Deleting_an_account_journals_every_assignment_that_went_with_it()
    {
        string admin = Unique("remover-");
        KgsmUser owner = await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        KgsmUser user = await anchor.SeedAsync(Unique("assigned-"), Long, KgsmTier.Operator);
        string role = (await anchor.Store.ApplyAsync(owner.UserId, new Access.CreateRole(Unique("Role-")),
            await anchor.Store.VersionAsync(), DateTimeOffset.UtcNow)).CreatedId!;
        string assignment = (await anchor.Store.ApplyAsync(owner.UserId, new Access.Assign(user.UserId, role, Access.AccessScope.Cluster),
            await anchor.Store.VersionAsync(), DateTimeOffset.UtcNow)).CreatedId!;

        Assert.Equal(HttpStatusCode.NoContent,
            (await SendAsync(HttpMethod.Delete, $"/auth/cluster/users/{user.UserId}", bearer)).StatusCode);

        Assert.Contains(anchor.Journal(AuthEvents.AssignmentRevoked),
            e => e.GetProperty("Data").GetProperty("AssignmentId").GetString() == assignment);
    }

    [Fact]
    public async Task The_last_active_Owner_cannot_be_deleted()
    {
        string admin = Unique("sole-");
        KgsmUser self = await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin, Long);

        // Every other Owner in the shared store is switched off first, so this really is the last one.
        Access.AuthoritySnapshot s = await anchor.Store.LoadAsync();
        var others = (await anchor.Store.ListAsync())
            .Where(u => u.UserId != self.UserId && u.Status == UserStatus.Active && s.IsOwner(u.UserId)).ToList();
        foreach (KgsmUser other in others)
            await anchor.Store.UpdateAsync(other with { Status = UserStatus.Disabled });

        try
        {
            HttpResponseMessage response =
                await SendAsync(HttpMethod.Delete, $"/auth/cluster/users/{self.UserId}", bearer);

            // An account store nobody can administer cannot be repaired through any surface.
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("last_owner",
                (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetProperty("code").GetString());
            Assert.NotNull(await anchor.Store.FindByIdAsync(self.UserId));
        }
        finally
        {
            foreach (KgsmUser other in others)
                await anchor.Store.UpdateAsync(other);
        }
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

}
