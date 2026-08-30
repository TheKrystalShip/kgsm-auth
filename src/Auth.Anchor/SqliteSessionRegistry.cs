using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Sessions;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The anchor's session registry, on its own SQLite file under the unit's state directory.
/// </summary>
/// <remarks>
/// <para>
/// Its own file rather than a table in the account store, because the two have different lifetimes
/// and different readers. Accounts are shared with every surface on the machine and must survive
/// anything; sessions belong to this daemon alone, and a member joining a cluster replicates the
/// accounts and never the sign-ins.
/// </para>
/// <para>
/// A row on disk is what makes a sign-out mean something: a session held only in memory dies with the
/// process, so every restart signs everybody out and no revocation outlives the thing it revoked.
/// </para>
/// <para>
/// SQLite is single-writer, so writes serialise through a process lock; WAL still lets reads run
/// concurrently. Timestamps are ISO-8601 round-trip strings, which sort lexicographically in the
/// order they sort chronologically — so the expiry comparisons are plain string compares and still
/// mean what they say.
/// </para>
/// </remarks>
internal sealed class SqliteSessionRegistry : ISessionRegistry
{
    private readonly string _connectionString;
    private readonly Lock _writeGate = new();

    internal SqliteSessionRegistry(string databasePath)
    {
        string full = Path.GetFullPath(databasePath);
        string? directory = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = full,
            Mode = SqliteOpenMode.ReadWriteCreate,
            DefaultTimeout = 5,
        }.ToString();

        Initialize();
    }

    private void Initialize()
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS sessions (
                session_id  TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                host_id     TEXT NOT NULL,
                created     TEXT NOT NULL,
                expires     TEXT NOT NULL,
                user_agent  TEXT NULL,
                current_jti TEXT NULL,
                revoked     INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions (user_id);
            """;
        cmd.ExecuteNonQuery();
    }

    public Task CreateAsync(SessionRegistration session, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO sessions
                    (session_id, user_id, host_id, created, expires, user_agent, current_jti, revoked)
                VALUES ($sid, $user, $host, $created, $expires, $ua, $jti, 0);
                """;
            cmd.Parameters.AddWithValue("$sid", session.SessionId);
            cmd.Parameters.AddWithValue("$user", session.UserId);
            cmd.Parameters.AddWithValue("$host", session.HostId);
            cmd.Parameters.AddWithValue("$created", session.Created.ToString("O"));
            cmd.Parameters.AddWithValue("$expires", session.Expires.ToString("O"));
            cmd.Parameters.AddWithValue("$ua", (object?)session.UserAgent ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$jti", (object?)session.CurrentJti ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }

        return Task.CompletedTask;
    }

    public Task<bool> IsAliveAsync(string sessionId, CancellationToken ct = default)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            "SELECT 1 FROM sessions WHERE session_id = $sid AND revoked = 0 AND expires > $now;";
        cmd.Parameters.AddWithValue("$sid", sessionId);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));

        return Task.FromResult(cmd.ExecuteScalar() is not null);
    }

    /// <summary>
    /// Rotates the refresh token. The <c>current_jti</c> match is the reuse detection, and it is part
    /// of the UPDATE's own WHERE clause rather than a read followed by a write — two refreshes racing
    /// with the same token would both pass a separate check, and only one may win.
    /// </summary>
    public Task<bool> RotateAsync(
        string sessionId, string presentedJti, string newJti, DateTimeOffset newExpires,
        CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                UPDATE sessions
                   SET current_jti = $new, expires = $expires
                 WHERE session_id = $sid
                   AND current_jti = $presented
                   AND revoked = 0
                   AND expires > $now;
                """;
            cmd.Parameters.AddWithValue("$sid", sessionId);
            cmd.Parameters.AddWithValue("$presented", presentedJti);
            cmd.Parameters.AddWithValue("$new", newJti);
            cmd.Parameters.AddWithValue("$expires", newExpires.ToString("O"));
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));

            return Task.FromResult(cmd.ExecuteNonQuery() == 1);
        }
    }

    /// <summary>
    /// Marks a session revoked rather than deleting the row: the sweep clears it once it is past its
    /// cap anyway, and until then the tombstone is what a replayed refresh lands on.
    /// </summary>
    public Task<bool> RevokeAsync(string sessionId, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                "UPDATE sessions SET revoked = 1, current_jti = NULL WHERE session_id = $sid AND revoked = 0;";
            cmd.Parameters.AddWithValue("$sid", sessionId);

            return Task.FromResult(cmd.ExecuteNonQuery() == 1);
        }
    }

    public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM sessions WHERE expires <= $now;";
            cmd.Parameters.AddWithValue("$now", now.ToString("O"));

            return Task.FromResult(cmd.ExecuteNonQuery());
        }
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }
}
