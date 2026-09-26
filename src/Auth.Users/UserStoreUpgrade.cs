using System.Data;
using System.Globalization;

using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>What <see cref="UserStoreUpgrade.ToVersion2"/> did.</summary>
/// <param name="From">The schema version the file was at.</param>
/// <param name="Backup">
/// The copy of the file taken before anything changed, or <see langword="null"/> when the file was
/// already at version 2 and nothing was done.
/// </param>
/// <param name="Owners">The usernames assigned Owner because they held <c>admin</c>.</param>
public sealed record UpgradeReport(int From, string? Backup, IReadOnlyList<string> Owners)
{
    /// <summary>Whether the file changed.</summary>
    public bool Upgraded => Backup is not null;
}

/// <summary>
/// Brings an account store from schema version 1 to version 2.
/// </summary>
/// <remarks>
/// <para>
/// Accounts, credentials and identity links survive. What changes, in one transaction:
/// </para>
/// <list type="bullet">
/// <item><c>origin</c> is added and taken from <c>tier_source</c>: <c>granted</c> → <c>admitted</c>, anything else → <c>arrived</c>.</item>
/// <item><c>kind</c> is added; every existing account is a person.</item>
/// <item>The authority tables are created and the two built-in roles seeded.</item>
/// <item>Every account holding <c>admin</c> is assigned Owner, at cluster scope. Nothing else is assigned.</item>
/// <item><c>tier</c> and <c>tier_source</c> are dropped.</item>
/// </list>
/// <para>
/// <b>A copy of the file is taken first</b>, owner-only, beside it. The tiers are the one thing the
/// upgrade erases, and a store's contents are the record itself: the copy is what an operator reads to
/// answer "what did this account hold before".
/// </para>
/// <para>
/// A file already at version 2 is left alone, so running it on every start is safe; a file newer than
/// version 2 is refused, for the same reason <see cref="SqliteUserStore"/> refuses one.
/// </para>
/// </remarks>
public static class UserStoreUpgrade
{
    /// <summary>Who an assignment the upgrade makes is recorded as granted by.</summary>
    public const string Actor = "system:schema-upgrade";

    /// <summary>Upgrade the store at <paramref name="path"/> to schema version 2.</summary>
    /// <param name="path">The account store.</param>
    /// <param name="now">When the upgrade runs; stamps the rows it writes and names the backup.</param>
    /// <exception cref="UserStoreSchemaException">The file is at a version this build cannot upgrade.</exception>
    public static UpgradeReport ToVersion2(string path, DateTimeOffset now)
    {
        if (!File.Exists(path))
            throw new UserStoreSchemaException($"There is no account store at '{path}' to upgrade.");

        string connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWrite,
            ForeignKeys = true,
            Pooling = false,
        }.ToString();

        using SqliteConnection connection = new(connectionString);
        connection.Open();
        Execute(connection, null, "PRAGMA busy_timeout=5000;");

        int from = ReadVersion(connection, path);
        if (from == AuthoritySchema.Version)
            return new UpgradeReport(from, null, []);

        if (from != UserSchema.Version)
        {
            throw new UserStoreSchemaException(
                $"The account store at '{path}' is at schema version {from}; this build upgrades version " +
                $"{UserSchema.Version} to {AuthoritySchema.Version} and nothing else.");
        }

        string backup = Backup(connection, path, now);

        using SqliteTransaction transaction = connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);

        // Read again under the write lock: another process may have upgraded it since.
        if (ReadVersion(connection, path, transaction) == AuthoritySchema.Version)
        {
            transaction.Rollback();
            return new UpgradeReport(AuthoritySchema.Version, null, []);
        }

        string stamp = UserWire.ToWire(now);

        Execute(connection, transaction, "ALTER TABLE users ADD COLUMN origin TEXT NOT NULL DEFAULT 'arrived';");
        Execute(connection, transaction,
            "UPDATE users SET origin = CASE lower(trim(tier_source)) WHEN 'granted' THEN 'admitted' ELSE 'arrived' END;");
        Execute(connection, transaction, "ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'person';");
        Execute(connection, transaction, "ALTER TABLE users ADD COLUMN version INTEGER NOT NULL DEFAULT 1;");

        // Version 1 orders each account on its own counter and owes the cluster from its own table;
        // version 2 orders everything on the authority version, so both go with the tiers.
        Execute(connection, transaction, "DROP TABLE IF EXISTS account_announcements;");
        Execute(connection, transaction, "DROP TABLE IF EXISTS account_versions;");

        Execute(connection, transaction, AuthoritySchema.CreateAuthority);
        SqliteAuthorityStore.SeedBuiltIns(connection, transaction, stamp);

        List<(string Id, string Username)> admins = [];
        using (SqliteCommand read = Command(connection, transaction,
            "SELECT user_id, username FROM users WHERE lower(trim(tier)) = 'admin' ORDER BY created_utc, user_id;"))
        using (SqliteDataReader reader = read.ExecuteReader())
        {
            while (reader.Read())
                admins.Add((reader.GetString(0), reader.GetString(1)));
        }

        foreach ((string id, _) in admins)
        {
            Execute(connection, transaction,
                """
                INSERT INTO assignments (assignment_id, user_id, role_id, scope, granted_by, version, created_utc)
                VALUES ($id, $user, $role, $scope, $by, 1, $now);
                """,
                ("$id", AuthorityIds.NewAssignmentId()), ("$user", id), ("$role", BuiltInRoles.OwnerId),
                ("$scope", AccessScope.Cluster.ToString()), ("$by", Actor), ("$now", stamp));
        }

        Execute(connection, transaction, "ALTER TABLE users DROP COLUMN tier;");
        Execute(connection, transaction, "ALTER TABLE users DROP COLUMN tier_source;");

        Execute(connection, transaction,
            "UPDATE schema_meta SET value = $value WHERE key = $key;",
            ("$key", UserSchema.VersionKey),
            ("$value", AuthoritySchema.Version.ToString(CultureInfo.InvariantCulture)));

        transaction.Commit();
        return new UpgradeReport(from, backup, [.. admins.Select(a => a.Username)]);
    }

    /// <summary>
    /// Copy the whole file, consistently, to <c>&lt;path&gt;.v1-&lt;time&gt;</c> beside it.
    /// </summary>
    /// <remarks>
    /// The target is created empty and owner-only before SQLite writes into it — <c>VACUUM INTO</c>
    /// accepts an empty file — so the password hashes it copies are never readable by anyone else,
    /// not even for the moment between a create and a chmod.
    /// </remarks>
    private static string Backup(SqliteConnection connection, string path, DateTimeOffset now)
    {
        string backup = $"{path}.v1-{now.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture)}";

        FileStreamOptions options = new() { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        using (new FileStream(backup, options))
        {
        }

        Execute(connection, null, "VACUUM INTO $target;", ("$target", backup));
        return backup;
    }

    private static int ReadVersion(SqliteConnection connection, string path, SqliteTransaction? transaction = null)
    {
        using SqliteCommand command = Command(connection, transaction,
            "SELECT value FROM schema_meta WHERE key = $key;", ("$key", UserSchema.VersionKey));

        object? value;
        try
        {
            value = command.ExecuteScalar();
        }
        catch (SqliteException e)
        {
            throw new UserStoreSchemaException($"'{path}' is not an account store: {e.Message}");
        }

        return value is string text && int.TryParse(text, CultureInfo.InvariantCulture, out int version)
            ? version
            : throw new UserStoreSchemaException($"The account store at '{path}' declares no readable schema version.");
    }

    private static SqliteCommand Command(
        SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object Value)[] parameters)
    {
        SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        foreach ((string name, object value) in parameters)
            command.Parameters.AddWithValue(name, value);

        return command;
    }

    private static void Execute(
        SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, transaction, sql, parameters);
        command.ExecuteNonQuery();
    }
}
