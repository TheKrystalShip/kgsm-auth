using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Cluster.Tests;

/// <summary>
/// A leaf firing on its own: allowed only where both its service account and the person who switched it
/// on hold the action, at the install, from the node's replica — and blocked, saying why, everywhere else.
/// </summary>
public sealed class AutomationAccessTests : IDisposable
{
    private const string Restart = "kgsm:server.restart";
    private const string Backup = "kgsm:server.backups.create";
    private const string Nonce = "aaaa1111aaaa1111";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "kgsm-automation-" + Guid.NewGuid().ToString("N"));
    private readonly string _path;

    public AutomationAccessTests()
    {
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "users.db");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private AutomationAccess Access(string? node = "walter") =>
        new(new MemberAccess(new AuthorityReplicaFile(_path, NullLogger<AuthorityReplicaFile>.Instance)),
            "scheduler", () => node);

    /// <summary>
    /// A version 2 replica: the scheduler's service account on walter, approved for
    /// <paramref name="serviceHolds"/> at the node, and Alice holding <paramref name="aliceHolds"/> on
    /// the Terraria install.
    /// </summary>
    private async Task SeedAsync(string[] serviceHolds, string[] aliceHolds)
    {
        SqliteAuthorityStore store = new(new UserStoreOptions { Path = _path });
        DateTimeOffset now = DateTimeOffset.UtcNow;

        await store.ApplyAsync(new CatalogRecord(
        [
            new CatalogActionRecord(Restart, "Restart", "execute", "instance", false),
            new CatalogActionRecord(Backup, "Back up", "execute", "instance", false),
        ], 2), now);
        await store.ApplyAsync(new AccountRecord("usr_svc", "scheduler@walter", "svc:scheduler@walter", "admitted",
            "service", "active", now, now, [], new ServiceRecord("scheduler", "walter"),
            [.. serviceHolds.Select(a => new RequirementRecord(a, "instance", "test", RequirementStates.Approved, "node:walter", null, true))],
            3), now);
        await store.ApplyAsync(new PermissionRecord("prm", "P", aliceHolds, 4), now);
        await store.ApplyAsync(new RoleRecord("role", "R", "custom", 1, ["prm"], 5), now);
        await store.ApplyAsync(new AccountRecord("usr_alice", "alice", "Alice", "admitted", "person", "active", now, now,
            [], null, [], 6), now);
        await store.ApplyAsync(new AssignmentRecord("asg", "usr_alice", "role",
            AccessScope.ForInstance("walter", "terraria", Nonce).ToString(), "usr_owner", now, 7), now);
        await store.ConfirmAsync(new AuthorityCurrent(7, 300, AccessContract.Version, now), now);
    }

    [Fact]
    public async Task BothHoldingIt_IsAllowed()
    {
        await SeedAsync([Restart, Backup], [Restart, Backup]);

        AutomationVerdict verdict = await Access().DecideAsync([Backup, Restart], "terraria", Nonce, "usr_alice");

        Assert.True(verdict.Allowed);
    }

    [Fact]
    public async Task AnAuthorWhoDoesNotHoldIt_Blocks_NamingThem()
    {
        await SeedAsync([Restart, Backup], [Backup]);

        AutomationVerdict verdict = await Access().DecideAsync([Backup, Restart], "terraria", Nonce, "usr_alice");

        Assert.False(verdict.Allowed);
        Assert.Contains("alice", verdict.Reason);
        Assert.Contains(Restart, verdict.Reason);
    }

    /// <summary>Writing an automation never lends its author the service's reach — nor the reverse.</summary>
    [Fact]
    public async Task AServiceThatDoesNotHoldIt_Blocks_HoweverMuchTheAuthorHolds()
    {
        await SeedAsync([Backup], [Restart, Backup]);

        AutomationVerdict verdict = await Access().DecideAsync([Restart], "terraria", Nonce, "usr_alice");

        Assert.False(verdict.Allowed);
        Assert.Contains("scheduler's own account", verdict.Reason);
    }

    [Fact]
    public async Task NobodyAsAuthor_Blocks()
    {
        await SeedAsync([Restart], [Restart]);

        AutomationVerdict verdict = await Access().DecideAsync([Restart], "terraria", Nonce, author: " ");

        Assert.False(verdict.Allowed);
        Assert.Contains("nobody is recorded", verdict.Reason);
    }

    /// <summary>A grant on one install does not reach a reinstall under the same name.</summary>
    [Fact]
    public async Task AGrantOnAnotherInstall_DoesNotReach()
    {
        await SeedAsync([Restart], [Restart]);

        Assert.False((await Access().DecideAsync([Restart], "terraria", "bbbb2222bbbb2222", "usr_alice")).Allowed);
        Assert.False((await Access().DecideAsync([Restart], "terraria", installNonce: null, "usr_alice")).Allowed);
    }

    [Fact]
    public async Task ACannotTell_Blocks_AndSaysWhich()
    {
        AutomationVerdict noReplica = await Access().DecideAsync([Restart], "terraria", Nonce, "usr_alice");
        Assert.False(noReplica.Allowed);
        Assert.Contains("could not be read", noReplica.Reason);

        await SeedAsync([Restart], [Restart]);

        AutomationVerdict noNode = await Access(node: null).DecideAsync([Restart], "terraria", Nonce, "usr_alice");
        Assert.False(noNode.Allowed);
        Assert.Contains("has not said which it is", noNode.Reason);

        AutomationVerdict noService = await Access(node: "jessie").DecideAsync([Restart], "terraria", Nonce, "usr_alice");
        Assert.False(noService.Allowed);
        Assert.Contains("no account on jessie", noService.Reason);
    }
}
