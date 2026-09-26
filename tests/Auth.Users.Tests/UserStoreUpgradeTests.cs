using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;

namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// Schema version 1 to 2: accounts survive, tiers go, admins become Owners and nobody else is given
/// anything.
/// </summary>
public class UserStoreUpgradeTests
{
    private static readonly DateTimeOffset At = new(2026, 9, 25, 21, 0, 0, TimeSpan.Zero);

    /// <summary>A version 1 store with one account of every tier, provenance and status that matters.</summary>
    private static (VersionOneFile File, Dictionary<string, string> Ids) VersionOne()
    {
        VersionOneFile file = new();
        Dictionary<string, string> ids = new()
        {
            ["root"] = file.User("root", "admin", "granted"),
            ["derived-admin"] = file.User("derived-admin", "admin", "derived"),
            ["sleeping-admin"] = file.User("sleeping-admin", "admin", "granted", "disabled"),
            ["op"] = file.User("op", "operator", "granted"),
            ["viewer"] = file.User("viewer", "viewer", "derived"),
            ["waiting"] = file.User("waiting", "none", "derived", "pending"),
        };

        file.Identity(ids["op"], "discord:1234", "op#0001");
        return (file, ids);
    }

    private static List<string[]> Rows(string path, string sql)
    {
        using SqliteConnection connection = new($"Data Source={path};Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        using SqliteDataReader reader = command.ExecuteReader();

        List<string[]> rows = [];
        while (reader.Read())
            rows.Add([.. Enumerable.Range(0, reader.FieldCount).Select(i => reader.IsDBNull(i) ? "" : reader.GetValue(i).ToString()!)]);

        return rows;
    }

    [Fact]
    public async Task EveryAdminBecomesAnOwnerAndNobodyElseIsAssignedAnything()
    {
        (VersionOneFile file, Dictionary<string, string> ids) = VersionOne();
        using VersionOneFile _ = file;

        UpgradeReport report = UserStoreUpgrade.ToVersion2(file.Path, At);

        Assert.True(report.Upgraded);
        Assert.Equal(1, report.From);
        Assert.Equal(new[] { "derived-admin", "root", "sleeping-admin" }, report.Owners.Order());

        AuthoritySnapshot snapshot = await new SqliteAuthorityStore(file.Options).LoadAsync();
        Assert.True(snapshot.IsOwner(ids["root"]));
        Assert.True(snapshot.IsOwner(ids["derived-admin"]));
        Assert.True(snapshot.IsOwner(ids["sleeping-admin"]));
        Assert.Equal(3, snapshot.Assignments.Count);
        Assert.All(snapshot.Assignments, a => Assert.Equal(AccessScope.Cluster, a.Scope));
    }

    [Fact]
    public async Task ADisabledAdminIsAnOwnerWhoStillCannotActUntilEnabled()
    {
        (VersionOneFile file, Dictionary<string, string> ids) = VersionOne();
        using VersionOneFile _ = file;
        UserStoreUpgrade.ToVersion2(file.Path, At);

        AccessEvaluator evaluator = new(await new SqliteAuthorityStore(file.Options).LoadAsync());

        Assert.True(evaluator.Allows(ids["root"], "kgsm:server.start", AccessScope.Cluster).Allowed);
        Assert.Equal(DenyReason.AccountDisabled,
            evaluator.Allows(ids["sleeping-admin"], "kgsm:server.start", AccessScope.Cluster).Reason);
        Assert.Equal(DenyReason.UnknownAction,
            evaluator.Allows(ids["op"], "kgsm:server.start", AccessScope.Cluster).Reason);
    }

    [Fact]
    public void OriginIsTakenFromTheTiersProvenance()
    {
        (VersionOneFile file, _) = VersionOne();
        using VersionOneFile _f = file;

        UserStoreUpgrade.ToVersion2(file.Path, At);

        Dictionary<string, string> origin = Rows(file.Path, "SELECT username, origin, kind FROM users;")
            .ToDictionary(r => r[0], r => r[1] + "/" + r[2]);

        Assert.Equal("admitted/person", origin["root"]);
        Assert.Equal("arrived/person", origin["derived-admin"]);
        Assert.Equal("admitted/person", origin["op"]);
        Assert.Equal("arrived/person", origin["viewer"]);
        Assert.Equal("arrived/person", origin["waiting"]);
    }

    [Fact]
    public void TheTiersAreDroppedAndEverythingElseSurvives()
    {
        (VersionOneFile file, Dictionary<string, string> ids) = VersionOne();
        using VersionOneFile _ = file;

        UserStoreUpgrade.ToVersion2(file.Path, At);

        string[] columns = [.. Rows(file.Path, "SELECT name FROM pragma_table_info('users');").Select(r => r[0])];
        Assert.DoesNotContain("tier", columns);
        Assert.DoesNotContain("tier_source", columns);

        Assert.Equal(ids.Count, Rows(file.Path, "SELECT user_id FROM users;").Count);
        Assert.Equal(["discord:1234"], Rows(file.Path, "SELECT handle FROM credentials;").Select(r => r[0]));
        Assert.Equal("2", Rows(file.Path, "SELECT value FROM schema_meta WHERE key = 'schema_version';").Single()[0]);

        Dictionary<string, string> statuses = Rows(file.Path, "SELECT username, status FROM users;").ToDictionary(r => r[0], r => r[1]);
        Assert.Equal("pending", statuses["waiting"]);
        Assert.Equal("disabled", statuses["sleeping-admin"]);
    }

    [Fact]
    public void EveryAccountStartsAtTheFirstAuthorityVersion_AndThePerAccountCountersGo()
    {
        (VersionOneFile file, _) = VersionOne();
        using VersionOneFile _f = file;
        file.WithAccountCounters();

        UserStoreUpgrade.ToVersion2(file.Path, At);

        Assert.All(Rows(file.Path, "SELECT version FROM users;"), r => Assert.Equal("1", r[0]));
        string[] tables = [.. Rows(file.Path, "SELECT name FROM sqlite_master WHERE type = 'table';").Select(r => r[0])];
        Assert.DoesNotContain("account_versions", tables);
        Assert.DoesNotContain("account_announcements", tables);
        Assert.Contains("authority_outbox", tables);
        Assert.Contains("authority_tombstones", tables);
    }

    [Fact]
    public async Task TheBuiltInRolesExistAndEveryoneStartsEmpty()
    {
        (VersionOneFile file, _) = VersionOne();
        using VersionOneFile _f = file;

        UserStoreUpgrade.ToVersion2(file.Path, At);
        AuthoritySnapshot snapshot = await new SqliteAuthorityStore(file.Options).LoadAsync();

        Assert.Equal(RoleKind.Owner, snapshot.Roles[BuiltInRoles.OwnerId].Kind);
        Assert.Empty(snapshot.Roles[BuiltInRoles.EveryoneId].Permissions);
        Assert.Equal(2, snapshot.Roles.Count);
        Assert.Empty(snapshot.Permissions);
        Assert.Equal(1, snapshot.Version);
    }

    [Fact]
    public void AnOwnerOnlyCopyOfTheVersionOneFileIsTakenFirst()
    {
        (VersionOneFile file, Dictionary<string, string> ids) = VersionOne();
        using VersionOneFile _ = file;

        UpgradeReport report = UserStoreUpgrade.ToVersion2(file.Path, At);

        Assert.Equal(file.Path + ".v1-20260925T210000Z", report.Backup);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(report.Backup!));

        Assert.Equal("admin", Rows(report.Backup!, "SELECT tier FROM users WHERE username = 'root';").Single()[0]);
        Assert.Equal(ids.Count, Rows(report.Backup!, "SELECT user_id FROM users;").Count);
        Assert.Equal("1", Rows(report.Backup!, "SELECT value FROM schema_meta WHERE key = 'schema_version';").Single()[0]);
    }

    [Fact]
    public async Task UpgradingTwiceChangesNothingTheSecondTime()
    {
        (VersionOneFile file, _) = VersionOne();
        using VersionOneFile _f = file;

        UserStoreUpgrade.ToVersion2(file.Path, At);
        UpgradeReport again = UserStoreUpgrade.ToVersion2(file.Path, At.AddMinutes(1));

        Assert.False(again.Upgraded);
        Assert.Equal(2, again.From);
        Assert.Equal(3, (await new SqliteAuthorityStore(file.Options).LoadAsync()).Assignments.Count);
    }

    [Fact]
    public void TheAuthorityStoreRefusesAVersionOneFile()
    {
        (VersionOneFile file, _) = VersionOne();
        using VersionOneFile _f = file;

        UserStoreSchemaException e = Assert.Throws<UserStoreSchemaException>(() => new SqliteAuthorityStore(file.Options));
        Assert.Contains(nameof(UserStoreUpgrade), e.Message);
    }

    [Fact]
    public void AFileNewerThanVersionTwoIsRefused()
    {
        using TempStore store = new();
        store.Raw("UPDATE schema_meta SET value = '3' WHERE key = 'schema_version';");

        Assert.Throws<UserStoreSchemaException>(() => UserStoreUpgrade.ToVersion2(store.Path_, At));
    }

    /// <summary>
    /// The upgrade, run against a copy of a real store. Set <c>KGSM_AUTH_UPGRADE_STORE</c> to a copy's
    /// path; the test copies it again and never touches the file named.
    /// </summary>
    [Fact]
    public async Task ARealStoreUpgradesWithEveryAccountAndEveryAdminAccountedFor()
    {
        string? source = Environment.GetEnvironmentVariable("KGSM_AUTH_UPGRADE_STORE");
        if (string.IsNullOrEmpty(source))
            return;

        using VersionOneFile file = new();
        SqliteConnection.ClearAllPools();
        File.Copy(source, file.Path, overwrite: true);

        int users = Rows(file.Path, "SELECT user_id FROM users;").Count;
        int credentials = Rows(file.Path, "SELECT credential_id FROM credentials;").Count;
        string[] admins = [.. Rows(file.Path, "SELECT username FROM users WHERE tier = 'admin';").Select(r => r[0]).Order()];

        UpgradeReport report = UserStoreUpgrade.ToVersion2(file.Path, At);
        AuthoritySnapshot snapshot = await new SqliteAuthorityStore(file.Options).LoadAsync();

        Assert.Equal(admins, report.Owners.Order());
        Assert.Equal(users, snapshot.Accounts.Count);
        Assert.Equal(credentials, Rows(file.Path, "SELECT credential_id FROM credentials;").Count);
        Assert.Equal(admins.Length, snapshot.Assignments.Count);
        Assert.All(snapshot.Accounts.Values, a => Assert.Equal(AccountKind.Person, a.Kind));
    }
}
