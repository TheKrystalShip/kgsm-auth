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
    private static async Task<(TempStore Store, Dictionary<string, KgsmUser> Users)> VersionOneAsync()
    {
        TempStore store = new();
        Dictionary<string, KgsmUser> users = new()
        {
            ["root"] = Make.User("root", KgsmTier.Admin, source: TierSource.Granted),
            ["derived-admin"] = Make.User("derived-admin", KgsmTier.Admin, source: TierSource.Derived),
            ["sleeping-admin"] = Make.User("sleeping-admin", KgsmTier.Admin, UserStatus.Disabled),
            ["op"] = Make.User("op", KgsmTier.Operator, source: TierSource.Granted),
            ["viewer"] = Make.User("viewer", KgsmTier.Viewer, source: TierSource.Derived),
            ["waiting"] = Make.User("waiting", KgsmTier.None, UserStatus.Pending, TierSource.Derived),
        };

        foreach (KgsmUser user in users.Values)
            await store.Store.CreateAsync(user);

        await store.Store.AddCredentialAsync(Make.Identity(users["op"].UserId, "discord:1234", "op#0001"));
        return (store, users);
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
        (TempStore store, Dictionary<string, KgsmUser> users) = await VersionOneAsync();
        using TempStore _ = store;

        UpgradeReport report = UserStoreUpgrade.ToVersion2(store.Path_, At);

        Assert.True(report.Upgraded);
        Assert.Equal(1, report.From);
        Assert.Equal(new[] { "derived-admin", "root", "sleeping-admin" }, report.Owners.Order());

        AuthoritySnapshot snapshot = await new SqliteAuthorityStore(store.Options).LoadAsync();
        Assert.True(snapshot.IsOwner(users["root"].UserId));
        Assert.True(snapshot.IsOwner(users["derived-admin"].UserId));
        Assert.True(snapshot.IsOwner(users["sleeping-admin"].UserId));
        Assert.Equal(3, snapshot.Assignments.Count);
        Assert.All(snapshot.Assignments, a => Assert.Equal(AccessScope.Cluster, a.Scope));
    }

    [Fact]
    public async Task ADisabledAdminIsAnOwnerWhoStillCannotActUntilEnabled()
    {
        (TempStore store, Dictionary<string, KgsmUser> users) = await VersionOneAsync();
        using TempStore _ = store;
        UserStoreUpgrade.ToVersion2(store.Path_, At);

        AccessEvaluator evaluator = new(await new SqliteAuthorityStore(store.Options).LoadAsync());

        Assert.True(evaluator.Allows(users["root"].UserId, "kgsm:server.start", AccessScope.Cluster).Allowed);
        Assert.Equal(DenyReason.AccountDisabled,
            evaluator.Allows(users["sleeping-admin"].UserId, "kgsm:server.start", AccessScope.Cluster).Reason);
        Assert.Equal(DenyReason.UnknownAction,
            evaluator.Allows(users["op"].UserId, "kgsm:server.start", AccessScope.Cluster).Reason);
    }

    [Fact]
    public async Task OriginIsTakenFromTheTiersProvenance()
    {
        (TempStore store, _) = await VersionOneAsync();
        using TempStore _s = store;

        UserStoreUpgrade.ToVersion2(store.Path_, At);

        Dictionary<string, string> origin = Rows(store.Path_, "SELECT username, origin, kind FROM users;")
            .ToDictionary(r => r[0], r => r[1] + "/" + r[2]);

        Assert.Equal("admitted/person", origin["root"]);
        Assert.Equal("arrived/person", origin["derived-admin"]);
        Assert.Equal("admitted/person", origin["op"]);
        Assert.Equal("arrived/person", origin["viewer"]);
        Assert.Equal("arrived/person", origin["waiting"]);
    }

    [Fact]
    public async Task TheTiersAreDroppedAndEverythingElseSurvives()
    {
        (TempStore store, Dictionary<string, KgsmUser> users) = await VersionOneAsync();
        using TempStore _ = store;

        UserStoreUpgrade.ToVersion2(store.Path_, At);

        string[] columns = [.. Rows(store.Path_, "SELECT name FROM pragma_table_info('users');").Select(r => r[0])];
        Assert.DoesNotContain("tier", columns);
        Assert.DoesNotContain("tier_source", columns);

        Assert.Equal(users.Count, Rows(store.Path_, "SELECT user_id FROM users;").Count);
        Assert.Equal(["discord:1234"], Rows(store.Path_, "SELECT handle FROM credentials;").Select(r => r[0]));
        Assert.Equal("2", Rows(store.Path_, "SELECT value FROM schema_meta WHERE key = 'schema_version';").Single()[0]);

        Dictionary<string, string> statuses = Rows(store.Path_, "SELECT username, status FROM users;").ToDictionary(r => r[0], r => r[1]);
        Assert.Equal("pending", statuses["waiting"]);
        Assert.Equal("disabled", statuses["sleeping-admin"]);
    }

    [Fact]
    public async Task EveryAccountStartsAtTheFirstAuthorityVersion_AndThePerAccountCountersGo()
    {
        (TempStore store, Dictionary<string, KgsmUser> _) = await VersionOneAsync();
        using TempStore owned = store;
        _ = new SqliteAccountVersions(new UserStoreOptions { Path = store.Path_ });
        Assert.Single(Rows(store.Path_, "SELECT name FROM sqlite_master WHERE name = 'account_versions';"));

        UserStoreUpgrade.ToVersion2(store.Path_, At);

        Assert.All(Rows(store.Path_, "SELECT version FROM users;"), r => Assert.Equal("1", r[0]));
        string[] tables = [.. Rows(store.Path_, "SELECT name FROM sqlite_master WHERE type = 'table';").Select(r => r[0])];
        Assert.DoesNotContain("account_versions", tables);
        Assert.DoesNotContain("account_announcements", tables);
        Assert.Contains("authority_outbox", tables);
        Assert.Contains("authority_tombstones", tables);
    }

    [Fact]
    public async Task TheBuiltInRolesExistAndEveryoneStartsEmpty()
    {
        (TempStore store, _) = await VersionOneAsync();
        using TempStore _s = store;

        UserStoreUpgrade.ToVersion2(store.Path_, At);
        AuthoritySnapshot snapshot = await new SqliteAuthorityStore(store.Options).LoadAsync();

        Assert.Equal(RoleKind.Owner, snapshot.Roles[BuiltInRoles.OwnerId].Kind);
        Assert.Empty(snapshot.Roles[BuiltInRoles.EveryoneId].Permissions);
        Assert.Equal(2, snapshot.Roles.Count);
        Assert.Empty(snapshot.Permissions);
        Assert.Equal(1, snapshot.Version);
    }

    [Fact]
    public async Task AnOwnerOnlyCopyOfTheVersionOneFileIsTakenFirst()
    {
        (TempStore store, Dictionary<string, KgsmUser> users) = await VersionOneAsync();
        using TempStore _ = store;

        UpgradeReport report = UserStoreUpgrade.ToVersion2(store.Path_, At);

        Assert.Equal(store.Path_ + ".v1-20260925T210000Z", report.Backup);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(report.Backup!));

        KgsmUser? root = await new SqliteUserStore(new UserStoreOptions { Path = report.Backup! }).FindByUsernameAsync("root");
        Assert.Equal(KgsmTier.Admin, root?.Tier);
        Assert.Equal(users.Count, (await new SqliteUserStore(new UserStoreOptions { Path = report.Backup! }).ListAsync()).Count);
    }

    [Fact]
    public async Task UpgradingTwiceChangesNothingTheSecondTime()
    {
        (TempStore store, _) = await VersionOneAsync();
        using TempStore _s = store;

        UserStoreUpgrade.ToVersion2(store.Path_, At);
        UpgradeReport again = UserStoreUpgrade.ToVersion2(store.Path_, At.AddMinutes(1));

        Assert.False(again.Upgraded);
        Assert.Equal(2, again.From);
        Assert.Equal(3, (await new SqliteAuthorityStore(store.Options).LoadAsync()).Assignments.Count);
    }

    [Fact]
    public async Task AVersionOneReaderRefusesTheUpgradedFile()
    {
        (TempStore store, _) = await VersionOneAsync();
        using TempStore _s = store;
        UserStoreUpgrade.ToVersion2(store.Path_, At);
        SqliteConnection.ClearAllPools();

        Assert.Throws<UserStoreSchemaException>(() => store.OpenAgain());
    }

    [Fact]
    public async Task TheAuthorityStoreRefusesAVersionOneFile()
    {
        (TempStore store, _) = await VersionOneAsync();
        using TempStore _s = store;

        UserStoreSchemaException e = Assert.Throws<UserStoreSchemaException>(() => new SqliteAuthorityStore(store.Options));
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

        using TempStore store = new();
        SqliteConnection.ClearAllPools();
        File.Copy(source, store.Path_, overwrite: true);

        int users = Rows(store.Path_, "SELECT user_id FROM users;").Count;
        int credentials = Rows(store.Path_, "SELECT credential_id FROM credentials;").Count;
        string[] admins = [.. Rows(store.Path_, "SELECT username FROM users WHERE tier = 'admin';").Select(r => r[0]).Order()];

        UpgradeReport report = UserStoreUpgrade.ToVersion2(store.Path_, At);
        AuthoritySnapshot snapshot = await new SqliteAuthorityStore(store.Options).LoadAsync();

        Assert.Equal(admins, report.Owners.Order());
        Assert.Equal(users, snapshot.Accounts.Count);
        Assert.Equal(credentials, Rows(store.Path_, "SELECT credential_id FROM credentials;").Count);
        Assert.Equal(admins.Length, snapshot.Assignments.Count);
        Assert.All(snapshot.Accounts.Values, a => Assert.Equal(AccountKind.Person, a.Kind));
    }
}
