using System.Globalization;
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

        // Additive, and nullable on purpose. Rows written before this column existed have no answer,
        // and null reads as "not known" — where a default would state a time nothing observed.
        using SqliteCommand add = connection.CreateCommand();
        add.CommandText = "ALTER TABLE sessions ADD COLUMN last_seen TEXT NULL;";
        try
        {
            add.ExecuteNonQuery();
        }
        catch (SqliteException)
        {
            // Already there. SQLite has no ADD COLUMN IF NOT EXISTS, and reading the schema back to
            // decide would be the same round trip with more code.
        }
    }

    /// <summary>One live session, as a person reviewing their own devices sees it.</summary>
    /// <param name="SessionId">The session.</param>
    /// <param name="UserId">Whose it is, as the provider-qualified handle it was keyed by.</param>
    /// <param name="Created">When they signed in.</param>
    /// <param name="Expires">The absolute cap on it.</param>
    /// <param name="UserAgent">The device, or null when it sent none.</param>
    /// <param name="LastSeen">
    /// When this session last rotated its tokens, or null for one that has not since this was
    /// recorded. It is the only contact the anchor has with a live session — every other request goes
    /// to a member and is verified offline — so it is a rotation, named as the nearest true thing
    /// rather than as a request count nothing counts.
    /// </param>
    internal sealed record LiveSession(
        string SessionId,
        string UserId,
        DateTimeOffset Created,
        DateTimeOffset Expires,
        string? UserAgent,
        DateTimeOffset? LastSeen);

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
                   SET current_jti = $new, expires = $expires, last_seen = $now
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

    /// <summary>
    /// Every live session belonging to one account.
    /// </summary>
    /// <remarks>
    /// Live means not revoked and not past its cap. A revoked row is kept as a tombstone until the
    /// sweep takes it, and listing those would show somebody a device they had already signed out.
    /// </remarks>
    /// <param name="handles">
    /// Every credential handle the account can be proved by. Sessions are keyed by the handle
    /// somebody <em>arrived</em> with, so one account signed in with a password and with Discord has
    /// two keys — asking under one of them finds half the devices and reports the other half as
    /// nothing, which reads as an empty card rather than as a wrong question.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The sessions, most recent first.</returns>
    internal Task<IReadOnlyList<LiveSession>> ListAsync(
        IReadOnlyList<string> handles, CancellationToken ct = default)
    {
        if (handles.Count == 0)
            return Task.FromResult<IReadOnlyList<LiveSession>>([]);

        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();

        // Parameterised per handle rather than joined into the text. The values are credential
        // handles read out of the store, but a query built by concatenation is one refactor away from
        // being built from something a caller sent.
        string slots = Bind(cmd, handles);
        cmd.CommandText =
            $"""
            SELECT session_id, user_id, created, expires, user_agent, last_seen
              FROM sessions
             WHERE user_id IN ({slots}) AND revoked = 0 AND expires > $now
             ORDER BY created DESC;
            """;
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));

        var sessions = new List<LiveSession>();
        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            sessions.Add(new LiveSession(
                reader.GetString(0),
                reader.GetString(1),
                DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture),
                DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5)
                    ? null
                    : DateTimeOffset.Parse(reader.GetString(5), CultureInfo.InvariantCulture)));
        }

        return Task.FromResult<IReadOnlyList<LiveSession>>(sessions);
    }

    /// <summary>
    /// Whose session this is, or <see langword="null"/> when there is no live session with that id.
    /// </summary>
    /// <remarks>
    /// Read before revoking one by id, so a caller ending "a session" can be held to it being theirs.
    /// A sid is opaque and unguessable, but an id that leaks must not become a way to sign somebody
    /// else out.
    /// </remarks>
    /// <param name="sessionId">The session.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The account handle, or null.</returns>
    internal Task<string?> OwnerAsync(string sessionId, CancellationToken ct = default)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            "SELECT user_id FROM sessions WHERE session_id = $sid AND revoked = 0 AND expires > $now;";
        cmd.Parameters.AddWithValue("$sid", sessionId);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));

        return Task.FromResult(cmd.ExecuteScalar() as string);
    }

    /// <summary>
    /// End every live session belonging to one account, and say which they were.
    /// </summary>
    /// <remarks>
    /// The ids come back because each has to be announced to the other members: a cluster session is
    /// accepted everywhere and has a row only here, so ending one locally ends it nowhere else.
    /// </remarks>
    /// <param name="handles">Every credential handle the account can be proved by.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The sessions that were live and now are not.</returns>
    internal async Task<IReadOnlyList<string>> RevokeAllAsync(
        IReadOnlyList<string> handles, CancellationToken ct = default)
    {
        IReadOnlyList<LiveSession> live = await ListAsync(handles, ct).ConfigureAwait(false);
        if (live.Count == 0)
            return [];

        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            string slots = Bind(cmd, handles);
            cmd.CommandText =
                $"UPDATE sessions SET revoked = 1, current_jti = NULL "
                + $"WHERE user_id IN ({slots}) AND revoked = 0;";
            cmd.ExecuteNonQuery();
        }

        return [.. live.Select(s => s.SessionId)];
    }

    /// <summary>Bind one parameter per handle and return the placeholder list for an IN clause.</summary>
    private static string Bind(SqliteCommand cmd, IReadOnlyList<string> handles)
    {
        var slots = new string[handles.Count];
        for (int i = 0; i < handles.Count; i++)
        {
            slots[i] = $"$h{i}";
            cmd.Parameters.AddWithValue(slots[i], handles[i]);
        }

        return string.Join(", ", slots);
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
