using System.Security.Claims;

using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;

using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Cluster.Tests;

/// <summary>
/// A member answering for the person behind a session it verified: from its own replica, and only once
/// that replica is at schema version 2.
/// </summary>
public sealed class MemberAccessTests : IDisposable
{
    private const string Start = "kgsm:server.start";

    private static readonly AccessScope Terraria = AccessScope.ForInstance("walter", "terraria", "aaaa1111aaaa1111");

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "kgsm-member-access-" + Guid.NewGuid().ToString("N"));
    private readonly string _path;

    public MemberAccessTests()
    {
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "users.db");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static ClaimsPrincipal Session(string handle) =>
        new(new ClaimsIdentity([new Claim("sub", handle)], "test"));

    private AuthorityReplicaFile Replica() => new(_path, NullLogger<AuthorityReplicaFile>.Instance);

    /// <summary>A version 2 replica holding one person with a role that starts servers on Terraria.</summary>
    private async Task<string> ReplicaWithAliceAsync(string status = "active")
    {
        SqliteAuthorityStore store = new(new UserStoreOptions { Path = _path });
        DateTimeOffset now = DateTimeOffset.UtcNow;

        await store.ApplyAsync(new CatalogRecord([new CatalogActionRecord(Start, "Start", "execute", "instance", false)], 2), now);
        await store.ApplyAsync(new PermissionRecord("prm_run", "Run", [Start], 3), now);
        await store.ApplyAsync(new RoleRecord("role_run", "Runner", "custom", 1, ["prm_run"], 4), now);
        await store.ApplyAsync(new AccountRecord("usr_alice", "alice", "Alice", "admitted", "person", status, now, now,
            [new ReplicatedIdentity("discord:42", "alice#1")], null, [], 5), now);
        await store.ApplyAsync(new AssignmentRecord("asg_1", "usr_alice", "role_run", Terraria.ToString(), "usr_owner", now, 6), now);
        await store.ConfirmAsync(new AuthorityCurrent(6, 300, AccessContract.Version, now), now);
        return "usr_alice";
    }

    [Fact]
    public async Task NoAccountStore_IsUnavailable_AndNothingIsCreated()
    {
        MemberAccessCaller caller = await new MemberAccess(Replica()).ResolveAsync(Session("discord:42"));

        Assert.Equal(MemberAccessRefusal.Unavailable, caller.Refusal);
        Assert.False(File.Exists(_path));
    }

    [Fact]
    public async Task AVersionOneStore_IsUnavailable_NamingWhy()
    {
        using (SqliteConnection connection = new($"Data Source={_path};Pooling=False"))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1');
                """;
            command.ExecuteNonQuery();
        }

        MemberAccessCaller caller = await new MemberAccess(Replica()).ResolveAsync(Session("discord:42"));

        Assert.Equal(MemberAccessRefusal.Unavailable, caller.Refusal);
        Assert.Contains("version", caller.Reason);
    }

    [Fact]
    public async Task APersonIsResolvedByTheSessionsHandle_AndEvaluatedFromTheReplica()
    {
        string alice = await ReplicaWithAliceAsync();

        (MemberAccessCaller caller, AccessReport? report) = await new MemberAccess(Replica())
            .ReportAsync(Session("discord:42"), [AccessScope.ForNode("walter"), Terraria], a => a.StartsWith("kgsm:", StringComparison.Ordinal));

        Assert.Equal(alice, caller.AccountId);
        Assert.Empty(report!.Cluster);
        Assert.Empty(report.Nodes);
        Assert.Equal([Start], report.Instances["walter/terraria#aaaa1111aaaa1111"]);
        Assert.True(report.Current);
    }

    [Fact]
    public async Task AHandleNoAccountHolds_IsNoAccount()
    {
        await ReplicaWithAliceAsync();

        Assert.Equal(MemberAccessRefusal.NoAccount,
            (await new MemberAccess(Replica()).ResolveAsync(Session("discord:999"))).Refusal);
    }

    [Fact]
    public async Task ADisabledAccount_IsRefused()
    {
        await ReplicaWithAliceAsync(status: "disabled");

        Assert.Equal(MemberAccessRefusal.AccountDisabled,
            (await new MemberAccess(Replica()).ResolveAsync(Session("discord:42"))).Refusal);
    }
}
