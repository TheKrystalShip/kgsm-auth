using System.Globalization;

using Microsoft.Data.Sqlite;

namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// An account store at schema version 1, written the way the builds that held tiers wrote it — the
/// file <see cref="UserStoreUpgrade.ToVersion2"/> reads, which nothing else in this build opens.
/// </summary>
/// <remarks>
/// The layout is the one those builds created, column for column; the upgrade is also run against a
/// copy of a real store (<c>KGSM_AUTH_UPGRADE_STORE</c>), which is what holds this copy to the truth.
/// </remarks>
internal sealed class VersionOneFile : IDisposable
{
    private const string Schema = """
        CREATE TABLE schema_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE users (
            user_id      TEXT PRIMARY KEY,
            username     TEXT NOT NULL,
            username_key TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            tier         TEXT NOT NULL,
            tier_source  TEXT NOT NULL,
            status       TEXT NOT NULL,
            created_utc  TEXT NOT NULL,
            updated_utc  TEXT NOT NULL
        );

        CREATE TABLE credentials (
            credential_id TEXT PRIMARY KEY,
            user_id       TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            kind          TEXT NOT NULL,
            handle        TEXT NOT NULL UNIQUE,
            secret        TEXT NULL,
            label         TEXT NULL,
            created_utc   TEXT NOT NULL,
            last_used_utc TEXT NULL
        );

        CREATE INDEX ix_credentials_user ON credentials(user_id);

        CREATE TABLE login_failures (
            user_id          TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
            failed_count     INTEGER NOT NULL,
            last_failed_utc  TEXT NOT NULL,
            locked_until_utc TEXT NULL
        );

        INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1');
        """;

    private static readonly string Stamp = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero)
        .UtcDateTime.ToString("o", CultureInfo.InvariantCulture);

    private readonly string _directory;

    public VersionOneFile()
    {
        _directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "kgsm-users-v1-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
        Path = System.IO.Path.Combine(_directory, "users.db");
        Options = new UserStoreOptions { Path = Path };
        Run(Schema);
    }

    public string Path { get; }

    public UserStoreOptions Options { get; }

    /// <summary>An account as version 1 held one. Returns its id.</summary>
    /// <param name="tier"><c>none</c>, <c>viewer</c>, <c>operator</c> or <c>admin</c>.</param>
    /// <param name="source"><c>derived</c> or <c>granted</c>.</param>
    /// <param name="status"><c>pending</c>, <c>active</c> or <c>disabled</c>.</param>
    public string User(string username, string tier, string source = "granted", string status = "active")
    {
        string id = UserIds.NewUserId();
        Run("""
            INSERT INTO users (user_id, username, username_key, display_name, tier, tier_source, status, created_utc, updated_utc)
            VALUES ($id, $name, $key, $name, $tier, $source, $status, $at, $at);
            """,
            ("$id", id), ("$name", username), ("$key", Usernames.Key(username)), ("$tier", tier),
            ("$source", source), ("$status", status), ("$at", Stamp));
        return id;
    }

    /// <summary>An external identity attached to an account.</summary>
    public void Identity(string userId, string handle, string? label = null) =>
        Run("""
            INSERT INTO credentials (credential_id, user_id, kind, handle, secret, label, created_utc, last_used_utc)
            VALUES ($id, $user, 'identity', $handle, NULL, $label, $at, NULL);
            """,
            ("$id", UserIds.NewCredentialId()), ("$user", userId), ("$handle", handle),
            ("$label", (object?)label ?? DBNull.Value), ("$at", Stamp));

    /// <summary>The per-account counter tables a clustered version 1 store also held.</summary>
    public void WithAccountCounters() => Run("""
        CREATE TABLE account_versions (user_id TEXT PRIMARY KEY, version INTEGER NOT NULL, updated_utc TEXT NOT NULL);
        CREATE TABLE account_announcements (
            user_id TEXT NOT NULL, version INTEGER NOT NULL, kind TEXT NOT NULL, created_utc TEXT NOT NULL,
            PRIMARY KEY (user_id, version));
        """);

    /// <summary>Run SQL against the file directly.</summary>
    public void Run(string sql, params (string Name, object Value)[] parameters)
    {
        using SqliteConnection connection = new($"Data Source={Path};Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        foreach ((string name, object value) in parameters)
            command.Parameters.AddWithValue(name, value);
        command.ExecuteNonQuery();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a green test over.
        }
    }
}
