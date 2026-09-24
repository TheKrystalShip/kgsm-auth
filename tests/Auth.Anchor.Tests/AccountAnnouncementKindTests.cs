using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// What each door tells the cluster it did. A change and a removal are different messages and a
/// member acts on them differently, so the kind a door announces is part of what that door does.
/// </summary>
/// <remarks>
/// Announcing a removal for something that is not one is invisible here and destructive there: the
/// account still stands on the anchor, and every member deletes it. Nothing on the writing side ever
/// reports a problem, and the person is a stranger everywhere but the machine their account is on.
/// So the kind is asserted per door rather than trusted to the call site.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class AccountAnnouncementKindTests(AnchorFixture anchor)
{
    private const string Long = "a long enough password";
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    /// <summary>
    /// What the anchor owes the cluster about one account. Readable because this fixture has no
    /// members: with nobody to tell, the rows stay owed rather than being sent and cleared.
    /// </summary>
    private async Task<AccountAnnouncementKind> OwedFor(string userId)
    {
        var announcements = new SqliteAccountVersions(
            new UserStoreOptions { Path = Path.Combine(anchor.Root, "users.db") });

        IReadOnlyList<AccountAnnouncement> owed = await announcements.PendingAsync();
        return Assert.Single(owed, a => a.UserId == userId).Kind;
    }

    private async Task<string> BearerAsync(string username) =>
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

    [Fact]
    public async Task An_administrator_setting_a_password_announces_a_change()
    {
        string admin = Unique("kind-resetter-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin);

        KgsmUser user = await anchor.SeedAsync(Unique("kind-reset-"), Long, KgsmTier.Viewer);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(
            HttpMethod.Post, $"/auth/cluster/users/{user.UserId}/password", bearer,
            new { password = "an administrator set this" })).StatusCode);

        // The hash stays here and the handle travels, so what a member has to be told is that the
        // account changed. Told it was removed, the person disappears from every replica because
        // their password was reset.
        Assert.Equal(AccountAnnouncementKind.Changed, await OwedFor(user.UserId));
    }

    [Fact]
    public async Task Somebody_changing_their_own_password_announces_a_change()
    {
        KgsmUser user = await anchor.SeedAsync(Unique("kind-self-"), Long, KgsmTier.Operator);
        AnchorFixture.Session session = await anchor.SignInAsync(user);

        // The account page's door, with the proof the browser's sign-in just gave it.
        Assert.Equal(HttpStatusCode.NoContent, (await anchor.Client.SendAsync(session.AtTheAccountPage(
            HttpMethod.Post, "/account/password", new { password = "one they chose themselves" }))).StatusCode);

        Assert.Equal(AccountAnnouncementKind.Changed, await OwedFor(user.UserId));
    }

    [Fact]
    public async Task An_account_an_administrator_creates_announces_a_change()
    {
        string admin = Unique("kind-creator-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin);

        string subject = Unique("kind-made-");
        HttpResponseMessage response = await SendAsync(
            HttpMethod.Post, "/auth/cluster/users", bearer,
            new { username = subject, password = Long, tier = "viewer" });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        KgsmUser made = (await anchor.Store.FindByUsernameAsync(subject))!;

        // An account announced as removed the moment it is made never reaches a member at all, and
        // the anchor shows it present the whole time.
        Assert.Equal(AccountAnnouncementKind.Changed, await OwedFor(made.UserId));
    }

    [Fact]
    public async Task Deleting_an_account_announces_a_removal()
    {
        string admin = Unique("kind-remover-");
        await anchor.SeedAsync(admin, Long, KgsmTier.Admin);
        string bearer = await BearerAsync(admin);

        KgsmUser user = await anchor.SeedAsync(Unique("kind-gone-"), Long, KgsmTier.Operator);

        Assert.Equal(HttpStatusCode.NoContent,
            (await SendAsync(HttpMethod.Delete, $"/auth/cluster/users/{user.UserId}", bearer)).StatusCode);

        Assert.Equal(AccountAnnouncementKind.Removed, await OwedFor(user.UserId));
    }
}
