using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Minting;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// The anchor's administration of who may do what, over HTTP against a real store: every rule's
/// refusal as a page receives it, a stale version, a sign-in that is not recent, and a caller's own
/// access.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AuthorityEndpointTests : IAsyncLifetime
{
    private const string Start = "kgsm:server.start";
    private const string Console = "kgsm:server.console.read";

    private BusCluster _cluster = null!;
    private HttpClient _http = null!;
    private string _owner = null!;
    private string _manager = null!;
    private string _alice = null!;
    private string _managers = null!;
    private string _seniors = null!;
    private string _seniorPermission = null!;

    public async Task InitializeAsync()
    {
        _cluster = await BusCluster.StartAsync();
        _http = new HttpClient { BaseAddress = new Uri(_cluster.Anchor.Url) };

        await Store.ReplaceCatalogAsync(
        [
            .. AuthActions.Declared,
            new CatalogAction(Start, "Start servers", ActionEffect.Execute, ScopeKind.Instance),
            new CatalogAction(Console, "Read consoles", ActionEffect.Read, ScopeKind.Instance),
        ], DateTimeOffset.UtcNow);

        _owner = Person("owner");
        await Store.GrantOwnerLocallyAsync("owner", "local:test", DateTimeOffset.UtcNow);
        _manager = Person("manager");
        _alice = Person("alice");

        // Managers edit roles and permissions and start servers; Seniors, made after, rank above them.
        string admin = (await AsOwner(new CreatePermission("Administer"))).CreatedId!;
        await AsOwner(new SetPermissionActions(admin, new HashSet<string>
            { AuthActions.RolesEdit, AuthActions.PermissionsEdit, AuthActions.RolesAssign, Start }));
        _managers = (await AsOwner(new CreateRole("Managers"))).CreatedId!;
        await AsOwner(new SetRolePermissions(_managers, new HashSet<string> { admin }));
        await AsOwner(new Assign(_manager, _managers, AccessScope.Cluster));

        _seniorPermission = (await AsOwner(new CreatePermission("Senior"))).CreatedId!;
        await AsOwner(new SetPermissionActions(_seniorPermission, new HashSet<string> { Start }));
        _seniors = (await AsOwner(new CreateRole("Seniors"))).CreatedId!;
        await AsOwner(new SetRolePermissions(_seniors, new HashSet<string> { _seniorPermission }));
    }

    public async Task DisposeAsync()
    {
        _http.Dispose();
        await _cluster.DisposeAsync();
    }

    // ── helpers ───────────────────────────────────────────────────────────────────────────────

    private SqliteAuthorityStore Store => _cluster.Store;

    private string Person(string username)
    {
        string id = UserIds.NewUserId();
        using SqliteConnection connection = new($"Data Source={_cluster.Anchor.Resolve<AnchorOptions>().UserStorePath}");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"""
             INSERT INTO users (user_id, username, username_key, display_name, origin, kind, status, created_utc, updated_utc)
             VALUES ('{id}', '{username}', '{username}', '{username}', 'admitted', 'person', 'active', '2026-09-26T00:00:00Z', '2026-09-26T00:00:00Z');
             INSERT INTO credentials (credential_id, user_id, kind, handle, secret, label, created_utc)
             VALUES ('cred_{id}', '{id}', 'password', 'local:{id}', 'hash', NULL, '2026-09-26T00:00:00Z');
             """;
        command.ExecuteNonQuery();
        return id;
    }

    private async Task<AuthorityWrite> AsOwner(AuthorityEdit edit) =>
        await Store.ApplyAsync(_owner, edit, await Store.VersionAsync(), DateTimeOffset.UtcNow);

    /// <summary>A bearer for <paramref name="account"/>, on a session that proved a credential at <paramref name="provedAt"/>.</summary>
    private async Task<string> SignInAsync(string account, DateTimeOffset? provedAt = null)
    {
        DateTimeOffset at = provedAt ?? DateTimeOffset.UtcNow;
        string sid = "sid_" + Guid.NewGuid().ToString("N");
        SqliteSessionRegistry sessions = _cluster.Anchor.Resolve<SqliteSessionRegistry>();
        await sessions.CreateProviderSessionAsync("p" + sid, $"local:{account}", "{}", "cookie-" + sid, "kgsm-cluster",
            at, at.AddDays(30), null);
        await sessions.CreateAsync(new SessionRegistration(sid, $"local:{account}", "kgsm-cluster", at, at.AddDays(30), null, "jti"), "p" + sid);

        KgsmIdentity identity = new("local", account, account, account, null, []);
        return _cluster.Anchor.Resolve<ISessionTokenService>().MintAccess(identity, tier: null, sid).Token;
    }

    private async Task<HttpResponseMessage> EditAsync(string bearer, object edit, long? version = null)
    {
        Dictionary<string, object?> body = JsonSerializer.Deserialize<Dictionary<string, object?>>(JsonSerializer.Serialize(edit))!;
        body["version"] = version ?? await Store.VersionAsync();

        using HttpRequestMessage request = new(HttpMethod.Post, "/auth/cluster/authority/edits") { Content = JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await _http.SendAsync(request);
    }

    private async Task<HttpResponseMessage> GetAsync(string path, string? bearer)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, path);
        if (bearer is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await _http.SendAsync(request);
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static async Task AssertRefusedAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal(code, (await JsonAsync(response)).GetProperty("error").GetProperty("code").GetString());
    }

    // ── each rule's refusal ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AnActionTheCallerDoesNotHold_IsRefusedAsNotHeld_NamingIt()
    {
        string bearer = await SignInAsync(_manager);
        string permission = (await AsOwner(new CreatePermission("Consoles"))).CreatedId!;

        HttpResponseMessage response = await EditAsync(bearer,
            new { kind = "permission.actions", permissionId = permission, actions = new[] { Console } });

        await AssertRefusedAsync(response, HttpStatusCode.Forbidden, "not_held");
        Assert.Equal([Console], (await JsonAsync(response)).GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
    }

    [Fact]
    public async Task ARoleRankedAboveTheCallers_IsRefusedAsRankNotBelow()
    {
        HttpResponseMessage response = await EditAsync(await SignInAsync(_manager),
            new { kind = "role.rename", roleId = _seniors, name = "Juniors" });

        await AssertRefusedAsync(response, HttpStatusCode.Forbidden, "rank_not_below");
    }

    [Fact]
    public async Task APermissionARoleAboveTheCallerHolds_IsRefusedAsHeldAbove()
    {
        HttpResponseMessage response = await EditAsync(await SignInAsync(_manager),
            new { kind = "permission.actions", permissionId = _seniorPermission, actions = Array.Empty<string>() });

        await AssertRefusedAsync(response, HttpStatusCode.Forbidden, "permission_held_above");
    }

    [Fact]
    public async Task RevokingTheLastOwner_IsRefusedAsLastOwner()
    {
        string ownership = (await Store.LoadAsync()).AssignmentsOf(_owner).Single(a => a.RoleId == BuiltInRoles.OwnerId).AssignmentId;

        HttpResponseMessage response = await EditAsync(await SignInAsync(_owner), new { kind = "revoke", assignmentId = ownership });

        await AssertRefusedAsync(response, HttpStatusCode.Forbidden, "last_owner");
    }

    [Fact]
    public async Task ACallerWithNoAuthAction_IsNotPermitted()
    {
        HttpResponseMessage response = await EditAsync(await SignInAsync(_alice), new { kind = "role.create", name = "Mine" });

        await AssertRefusedAsync(response, HttpStatusCode.Forbidden, "not_permitted");
    }

    // ── versions, sign-in and malformed edits ─────────────────────────────────────────────────

    [Fact]
    public async Task AnEditAgainstAnOlderVersion_Is409WithTheAuthorityAsItStands()
    {
        long before = await Store.VersionAsync();
        await AsOwner(new CreateRole("Meanwhile"));

        HttpResponseMessage response = await EditAsync(await SignInAsync(_owner), new { kind = "role.create", name = "Late" }, before);

        await AssertRefusedAsync(response, HttpStatusCode.Conflict, "stale_authority");
        JsonElement authority = (await JsonAsync(response)).GetProperty("authority");
        Assert.Equal(await Store.VersionAsync(), authority.GetProperty("version").GetInt64());
        Assert.Contains(authority.GetProperty("roles").EnumerateArray(), r => r.GetProperty("name").GetString() == "Meanwhile");
        Assert.DoesNotContain((await Store.LoadAsync()).Roles.Values, r => r.Name == "Late");
    }

    [Fact]
    public async Task AnAllowedEditOnAnOldSignIn_IsReauthRequired_AndChangesNothing()
    {
        long before = await Store.VersionAsync();

        HttpResponseMessage response = await EditAsync(
            await SignInAsync(_owner, DateTimeOffset.UtcNow.AddHours(-1)), new { kind = "role.create", name = "Later" });

        await AssertRefusedAsync(response, HttpStatusCode.Forbidden, "reauth_required");
        Assert.Equal(before, await Store.VersionAsync());
    }

    [Fact]
    public async Task ARefusedEditOnAnOldSignIn_GivesTheRulesReason_NotASignInPrompt()
    {
        HttpResponseMessage response = await EditAsync(
            await SignInAsync(_alice, DateTimeOffset.UtcNow.AddHours(-1)), new { kind = "role.create", name = "Mine" });

        await AssertRefusedAsync(response, HttpStatusCode.Forbidden, "not_permitted");
    }

    [Fact]
    public async Task AnEditNamingNoKnownKind_IsMalformed()
    {
        HttpResponseMessage response = await EditAsync(await SignInAsync(_owner), new { kind = "role.explode", roleId = _managers });

        await AssertRefusedAsync(response, HttpStatusCode.BadRequest, "malformed_request");
    }

    [Fact]
    public async Task AnAllowedEdit_Lands_AndIsOwedToTheCluster()
    {
        HttpResponseMessage response = await EditAsync(await SignInAsync(_manager), new
        {
            kind = "assign", accountId = _alice, roleId = BuiltInRoles.EveryoneId, scope = "cluster",
        });

        // Everyone is never assigned: the rule's own refusal, from a caller allowed to assign.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        string juniors = (await AsOwner(new CreateRole("Juniors"))).CreatedId!;
        await AsOwner(new RankRole(juniors, RoleRanks.FirstCustom + 2));
        long before = await Store.VersionAsync();

        response = await EditAsync(await SignInAsync(_manager), new
        {
            kind = "assign", accountId = _alice, roleId = juniors, scope = "instance:walter/terraria#aaaa1111aaaa1111",
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement result = await JsonAsync(response);
        Assert.Equal(before + 1, result.GetProperty("version").GetInt64());
        string assignment = result.GetProperty("createdId").GetString()!;
        Assert.Contains((await Store.LoadAsync()).AssignmentsOf(_alice), a => a.AssignmentId == assignment);
    }

    // ── reading ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TheAuthority_IsReadByWhoeverAdministersSomeOfIt_AndNobodyElse()
    {
        await AssertRefusedAsync(await GetAsync("/auth/cluster/authority", await SignInAsync(_alice)), HttpStatusCode.Forbidden, "not_permitted");
        await AssertRefusedAsync(await GetAsync("/auth/cluster/authority", null), HttpStatusCode.Unauthorized, "unauthenticated");

        HttpResponseMessage response = await GetAsync("/auth/cluster/authority", await SignInAsync(_manager));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        JsonElement view = await JsonAsync(response);
        Assert.Equal(["Owner", "Seniors", "Managers", "everyone"],
            view.GetProperty("roles").EnumerateArray().Select(r => r.GetProperty("name").GetString()));
        JsonElement console = view.GetProperty("catalog").EnumerateArray().Single(a => a.GetProperty("action").GetString() == Console);
        Assert.True(console.GetProperty("unmapped").GetBoolean());
        JsonElement start = view.GetProperty("catalog").EnumerateArray().Single(a => a.GetProperty("action").GetString() == Start);
        Assert.False(start.GetProperty("unmapped").GetBoolean());
    }

    [Fact]
    public async Task MeAccess_ListsTheCallersOwnAuthActions()
    {
        JsonElement manager = await JsonAsync(await GetAsync("/me/access", await SignInAsync(_manager)));
        string[] cluster = [.. manager.GetProperty("cluster").EnumerateArray().Select(a => a.GetString()!)];
        Assert.Contains(AuthActions.RolesEdit, cluster);
        Assert.Contains(AuthActions.RolesAssign, cluster);
        Assert.DoesNotContain(Start, cluster);
        Assert.True(manager.GetProperty("current").GetBoolean());

        JsonElement alice = await JsonAsync(await GetAsync("/me/access", await SignInAsync(_alice)));
        Assert.Empty(alice.GetProperty("cluster").EnumerateArray());

        await AssertRefusedAsync(await GetAsync("/me/access", null), HttpStatusCode.Unauthorized, "unauthenticated");
    }

    [Fact]
    public async Task MeAccess_NamesAnInstanceWhereAssigningIsHeldThereAlone()
    {
        string granting = (await AsOwner(new CreatePermission("Grant"))).CreatedId!;
        await AsOwner(new SetPermissionActions(granting, new HashSet<string> { AuthActions.RolesAssign }));
        string hosts = (await AsOwner(new CreateRole("Hosts"))).CreatedId!;
        await AsOwner(new SetRolePermissions(hosts, new HashSet<string> { granting }));
        await AsOwner(new Assign(_alice, hosts, AccessScope.ForInstance("walter", "terraria", "aaaa1111aaaa1111")));

        JsonElement report = await JsonAsync(await GetAsync("/me/access", await SignInAsync(_alice)));

        Assert.Empty(report.GetProperty("cluster").EnumerateArray());
        Assert.Equal([AuthActions.RolesAssign],
            report.GetProperty("instances").GetProperty("walter/terraria#aaaa1111aaaa1111").EnumerateArray().Select(a => a.GetString()));
    }
}
