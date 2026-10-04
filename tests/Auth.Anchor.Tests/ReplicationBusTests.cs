using System.Text.Json;

using Microsoft.Data.Sqlite;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Cluster;
using TheKrystalShip.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Identity;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// The authority over a real cluster: an anchor writing, nodes following it over the bus from a
/// snapshot, the heartbeat that keeps them current, members acting for people and services, and the
/// anchor's own recent-sign-in rule.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class ReplicationBusTests : IAsyncLifetime
{
    private const string Start = "kgsm:server.start";
    private const string Console = "kgsm:server.console.read";

    private static readonly AccessScope Terraria = AccessScope.ForInstance("walter", "terraria", "aaaa1111aaaa1111");

    private BusCluster _cluster = null!;
    private BusMember _walter = null!;
    private BusMember _jessie = null!;
    private string _owner = null!;
    private string _alice = null!;

    public async Task InitializeAsync()
    {
        _cluster = await BusCluster.StartAsync("walter", "jessie");
        _walter = _cluster["walter"];
        _jessie = _cluster["jessie"];

        await Store.ReplaceCatalogAsync(
        [
            .. AuthActions.Declared,
            new CatalogAction(Start, "Start servers", ActionEffect.Execute, ScopeKind.Instance),
            new CatalogAction(Console, "Read consoles", ActionEffect.Read, ScopeKind.Instance),
        ], DateTimeOffset.UtcNow);

        _owner = Person("owner");
        await Store.GrantOwnerLocallyAsync("owner", "local:test", DateTimeOffset.UtcNow);
        _alice = Person("alice");
        await DrainAsync();
    }

    public async Task DisposeAsync() => await _cluster.DisposeAsync();

    // ── helpers ───────────────────────────────────────────────────────────────────────────────

    private SqliteAuthorityStore Store => _cluster.Store;

    /// <summary>A person with a password, written the way the version 2 account store writes one.</summary>
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

    private async Task<AuthorityWrite> EditAsync(AuthorityEdit edit)
    {
        AuthorityWrite write = await Store.ApplyAsync(_owner, edit, await Store.VersionAsync(), DateTimeOffset.UtcNow);
        await DrainAsync();
        return write;
    }

    private Task DrainAsync() => _cluster.Anchor.Resolve<AuthorityBroadcast>().DrainAsync(default);

    private async Task<string> RoleStartingServersAsync()
    {
        string permission = (await EditAsync(new CreatePermission("Run servers"))).CreatedId!;
        await EditAsync(new SetPermissionActions(permission, new HashSet<string> { Start, Console }));
        string role = (await EditAsync(new CreateRole("Server manager"))).CreatedId!;
        await EditAsync(new SetRolePermissions(role, new HashSet<string> { permission }));
        return role;
    }

    private static AuthoritySource Source(BusMember node) => new(node.Replica, AuthorityStanding.Replica);

    private static async Task<bool> AllowsAsync(AuthoritySource source, string account, string action, AccessScope target) =>
        (await source.EvaluatorAsync()).Allows(account, action, target).Allowed;

    // ── following the anchor ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ARoleChange_LandsOnTheNodesNextRequest_AndEndsNoSession()
    {
        Assert.True(await _walter.SnapshotWorker.TakeIfOwedAsync(default));
        AuthoritySource walter = Source(_walter);

        SqliteSessionRegistry sessions = _cluster.Anchor.Resolve<SqliteSessionRegistry>();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await sessions.CreateProviderSessionAsync("psid", $"local:{_alice}", "{}", "cookie", "kgsm-cluster", now, now.AddDays(30), null);
        await sessions.CreateAsync(new SessionRegistration("sid", $"local:{_alice}", "kgsm-cluster", now, now.AddDays(30), null, "jti"), "psid");

        string role = await RoleStartingServersAsync();
        await EditAsync(new Assign(_alice, role, Terraria));
        await BusCluster.EventuallyAsync(() => AllowsAsync(walter, _alice, Start, Terraria), "alice's grant on walter");

        int heard = _walter.Resolve<RecordingListener>().Changes;
        await EditAsync(new SetRolePermissions(role, new HashSet<string>()));
        await BusCluster.EventuallyAsync(async () => !await AllowsAsync(walter, _alice, Start, Terraria), "the role emptied on walter");

        Assert.True(await sessions.IsAliveAsync("sid"));
        Assert.True(_walter.Resolve<RecordingListener>().Changes > heard, "walter's listeners were not told of the change");
    }

    [Fact]
    public async Task ANodeJoiningLate_TakesEverythingFromItsSnapshot()
    {
        string role = await RoleStartingServersAsync();
        await EditAsync(new Assign(_alice, role, Terraria));

        Assert.True(await _jessie.SnapshotWorker.TakeIfOwedAsync(default));
        Assert.False(await _jessie.SnapshotWorker.TakeIfOwedAsync(default));

        Assert.True(await AllowsAsync(Source(_jessie), _alice, Start, Terraria));
    }

    [Fact]
    public async Task TheHeartbeat_ConfirmsANodeHoldingTheAnchorsVersion()
    {
        await _walter.SnapshotWorker.TakeIfOwedAsync(default);
        DateTimeOffset taken = (await _walter.Replica.ReplicaStateAsync()).Freshness.ConfirmedAt!.Value;

        await Task.Delay(50);
        await _cluster.Anchor.Resolve<AuthorityBroadcastWorker>().BeatAsync(default);

        await BusCluster.EventuallyAsync(
            async () => (await _walter.Replica.ReplicaStateAsync()).Freshness.ConfirmedAt > taken, "the heartbeat confirm walter");
        Assert.Equal(TimeSpan.FromMinutes(5), (await _walter.Replica.ReplicaStateAsync()).Freshness.Bound);
    }

    // ── acting for somebody ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AMember_ActsForAPerson_AndAsItsOwnServiceAccountsOnly()
    {
        foreach (BusMember node in new[] { _walter, _jessie })
        {
            File.WriteAllText(Path.Combine(node.Manifests, "reactor.json"), JsonSerializer.Serialize(
                new ActionManifest(1, "reactor", "0.5.0", [new ManifestAction("rules.write", "Write rules", "write", "node", null)],
                    [new ManifestRequirement(Start, "instance", "restart a crashed server")]),
                AccessJsonContext.Default.ActionManifest));
            await node.Resolve<AuthorityReporter>().ReportIfDueAsync(default);
        }

        await BusCluster.EventuallyAsync(
            async () => (await Store.LoadAsync()).Accounts.Values.Count(a => a.Service is not null) == 2, "both reactors' service accounts");
        await _walter.SnapshotWorker.TakeIfOwedAsync(default);
        AuthoritySnapshot snapshot = await Source(_walter).CurrentAsync();

        MemberActingAccountResolver resolver = new(
            _walter.Resolve<IClusterTokenService>(), _walter.Resolve<IClusterMemberGate>(), _walter.Resolve<IReplicatedAuthority>());
        string jessieToken = _jessie.Resolve<IClusterTokenService>().Mint().Token;

        MemberActingAccount person = await resolver.ResolveAsync($"local:{_alice}", jessieToken, snapshot);
        Assert.Equal(_alice, person.AccountId);
        Assert.Equal("jessie", person.ActingMember);

        MemberActingAccount own = await resolver.ResolveAsync("svc:reactor@jessie", jessieToken, snapshot);
        Assert.True(own.Succeeded);
        Assert.Equal(new ServiceIdentity("reactor", "jessie"), snapshot.Accounts[own.AccountId!].Service);

        MemberActingAccount borrowed = await resolver.ResolveAsync("svc:reactor@walter", jessieToken, snapshot);
        Assert.Equal(MemberActingRefusal.ServiceNotTheCallers, borrowed.Refusal);

        MemberActingAccount stranger = await resolver.ResolveAsync("local:usr_nobody", jessieToken, snapshot);
        Assert.Equal(MemberActingRefusal.NoSuchAccount, stranger.Refusal);
    }

    // ── recent sign-in ────────────────────────────────────────────────────────────────────────

    private async Task SignInAsync(string account, string sid, DateTimeOffset provedAt)
    {
        SqliteSessionRegistry sessions = _cluster.Anchor.Resolve<SqliteSessionRegistry>();
        await sessions.CreateProviderSessionAsync("p" + sid, $"local:{account}", "{}", "cookie-" + sid, "kgsm-cluster",
            provedAt, provedAt.AddDays(30), null);
        await sessions.CreateAsync(new SessionRegistration(sid, $"local:{account}", "kgsm-cluster", provedAt,
            provedAt.AddDays(30), null, "jti"), "p" + sid);
    }

    [Fact]
    public async Task AnAuthAction_NeedsARecentSignIn_OwnerIncluded()
    {
        AnchorAccess access = _cluster.Anchor.Resolve<AnchorAccess>();
        await SignInAsync(_owner, "fresh", DateTimeOffset.UtcNow);
        await SignInAsync(_owner, "old", DateTimeOffset.UtcNow.AddHours(-1));

        Assert.True((await access.AllowsAsync(_owner, "fresh", AuthActions.RolesEdit, AccessScope.Cluster)).Allowed);

        AnchorAccessResult old = await access.AllowsAsync(_owner, "old", AuthActions.RolesEdit, AccessScope.Cluster);
        Assert.True(old.Decision.Allowed);
        Assert.True(old.ReauthRequired);
        Assert.False(old.Allowed);

        // Anything that is not auth:* needs no recent sign-in.
        Assert.True((await access.AllowsAsync(_owner, "old", Start, Terraria)).Allowed);
    }

    [Fact]
    public async Task ARefusedAuthAction_IsRefused_NotSentToSignInAgain()
    {
        AnchorAccess access = _cluster.Anchor.Resolve<AnchorAccess>();
        await SignInAsync(_alice, "old", DateTimeOffset.UtcNow.AddHours(-1));

        AnchorAccessResult result = await access.AllowsAsync(_alice, "old", AuthActions.RolesEdit, AccessScope.Cluster);
        Assert.False(result.Decision.Allowed);
        Assert.False(result.ReauthRequired);
    }
}
