using Microsoft.Data.Sqlite;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// The applications this provider signs people in to, beside the clients they sign in through.
/// </summary>
/// <remarks>
/// <para>
/// Beside the clients rather than in the account store, because an application is what a client mints
/// for — its audience, its lifetime, the actions its tokens list — and a client is read on every
/// authorization. The account store is replicated to every KGSM member; nothing about an application
/// outside KGSM belongs there.
/// </para>
/// <para>
/// Every write that changes a client or an application advances one generation, in the transaction that
/// makes it. The daemon reads its registry from memory, and the host command writes this file from
/// another process: the generation is how the daemon learns its copy is behind.
/// </para>
/// </remarks>
internal sealed partial class SqliteSessionRegistry
{
    private const string GenerationKey = "generation";

    private static void InitializeApplications(SqliteConnection connection)
    {
        // Additive and nullable, like every column this file has gained: a client registered before an
        // application could be named is KGSM's and public, and a session minted before one was recorded
        // is KGSM's, which null says.
        foreach ((string table, string column) in (ReadOnlySpan<(string, string)>)
        [
            ("clients", "application_id TEXT NULL"),
            ("clients", "secret_hash TEXT NULL"),
            ("sessions", "client_id TEXT NULL"),
        ])
        {
            using SqliteCommand add = connection.CreateCommand();
            add.CommandText = $"ALTER TABLE {table} ADD COLUMN {column};";
            try
            {
                add.ExecuteNonQuery();
            }
            catch (SqliteException)
            {
                // Already there.
            }
        }

        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS applications (
                application_id       TEXT PRIMARY KEY,
                name                 TEXT NOT NULL,
                audience             TEXT NOT NULL UNIQUE,
                manifest_url         TEXT NULL,
                access_lifetime_min  INTEGER NOT NULL,
                discord_applications TEXT NOT NULL,
                act_for_discord      INTEGER NOT NULL,
                created              TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS ix_clients_application ON clients (application_id);

            CREATE TABLE IF NOT EXISTS registry_meta (
                key   TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO registry_meta (key, value) VALUES ('generation', 0);
            """;
        cmd.ExecuteNonQuery();
    }

    /// <summary>The generation the clients and applications are at.</summary>
    internal long RegistryGeneration()
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT value FROM registry_meta WHERE key = $key;";
        cmd.Parameters.AddWithValue("$key", GenerationKey);
        return cmd.ExecuteScalar() is long generation ? generation : 0;
    }

    private static void BumpGeneration(SqliteConnection connection, SqliteTransaction tx)
    {
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "UPDATE registry_meta SET value = value + 1 WHERE key = $key;";
        cmd.Parameters.AddWithValue("$key", GenerationKey);
        cmd.ExecuteNonQuery();
    }

    // ── Applications ──────────────────────────────────────────────────────────

    /// <summary>Every application registered here. KGSM's is built in and never stored.</summary>
    internal Task<IReadOnlyList<Application>> ListApplicationsAsync(CancellationToken ct = default)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            SELECT application_id, name, audience, manifest_url, access_lifetime_min, discord_applications,
                   act_for_discord, created
              FROM applications ORDER BY application_id;
            """;

        var applications = new List<Application>();
        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            applications.Add(new Application(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                NullableString(reader, 3),
                TimeSpan.FromMinutes(reader.GetInt64(4)),
                Lines(reader.GetString(5)),
                reader.GetInt64(6) != 0,
                ApplicationSources.Admin,
                Parse(reader.GetString(7))));
        }

        return Task.FromResult<IReadOnlyList<Application>>(applications);
    }

    /// <summary>What adding an application came to.</summary>
    internal enum AddApplicationOutcome { Added, IdTaken, AudienceTaken, ClientTaken }

    /// <summary>Register an application and its clients, all or none.</summary>
    internal Task<AddApplicationOutcome> AddApplicationAsync(
        Application application, IReadOnlyList<RegisteredClient> clients, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteTransaction tx = connection.BeginTransaction();

            if (Exists(connection, tx, "SELECT 1 FROM applications WHERE application_id = $v;", application.Id))
                return Task.FromResult(AddApplicationOutcome.IdTaken);
            if (Exists(connection, tx, "SELECT 1 FROM applications WHERE audience = $v;", application.Audience))
                return Task.FromResult(AddApplicationOutcome.AudienceTaken);

            using (SqliteCommand insert = connection.CreateCommand())
            {
                insert.Transaction = tx;
                insert.CommandText =
                    """
                    INSERT INTO applications
                        (application_id, name, audience, manifest_url, access_lifetime_min, discord_applications,
                         act_for_discord, created)
                    VALUES ($id, $name, $audience, $manifest, $lifetime, $discord, $act, $created);
                    """;
                BindApplication(insert, application);
                insert.ExecuteNonQuery();
            }

            foreach (RegisteredClient client in clients)
            {
                if (!InsertClient(connection, tx, client))
                    return Task.FromResult(AddApplicationOutcome.ClientTaken);
            }

            BumpGeneration(connection, tx);
            tx.Commit();
            return Task.FromResult(AddApplicationOutcome.Added);
        }
    }

    /// <summary>Change an application's own fields. False when there is none by that id, or the audience is another's.</summary>
    internal Task<bool> UpdateApplicationAsync(Application application, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteTransaction tx = connection.BeginTransaction();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText =
                """
                UPDATE applications
                   SET name = $name, audience = $audience, manifest_url = $manifest,
                       access_lifetime_min = $lifetime, discord_applications = $discord, act_for_discord = $act
                 WHERE application_id = $id;
                """;
            BindApplication(cmd, application);

            bool updated;
            try
            {
                updated = cmd.ExecuteNonQuery() == 1;
            }
            catch (SqliteException e) when (e.SqliteErrorCode == 19)
            {
                // SQLITE_CONSTRAINT: the audience is another application's.
                return Task.FromResult(false);
            }

            if (updated)
                BumpGeneration(connection, tx);
            tx.Commit();
            return Task.FromResult(updated);
        }
    }

    /// <summary>
    /// Remove an application and every client of it, and end every session minted through them.
    /// </summary>
    /// <returns>False when there is none by that id.</returns>
    internal Task<bool> RemoveApplicationAsync(string applicationId, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteTransaction tx = connection.BeginTransaction();

            ExecuteIn(connection, tx,
                """
                UPDATE sessions SET revoked = 1, current_jti = NULL
                 WHERE revoked = 0 AND client_id IN (SELECT client_id FROM clients WHERE application_id = $v);
                """, applicationId);
            ExecuteIn(connection, tx, "DELETE FROM clients WHERE application_id = $v;", applicationId);
            bool removed = ExecuteIn(connection, tx, "DELETE FROM applications WHERE application_id = $v;", applicationId) == 1;

            if (removed)
                BumpGeneration(connection, tx);
            tx.Commit();
            return Task.FromResult(removed);
        }
    }

    /// <summary>Add a client to an application. False when the id is already a client's.</summary>
    internal Task<bool> AddApplicationClientAsync(RegisteredClient client, CancellationToken ct = default) =>
        AddClientAsync(client, ct);

    /// <summary>
    /// Remove one client of an application, and end every session minted through it.
    /// </summary>
    /// <returns>False when the application has no client by that id.</returns>
    internal Task<bool> RemoveApplicationClientAsync(string applicationId, string clientId, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteTransaction tx = connection.BeginTransaction();

            using SqliteCommand delete = connection.CreateCommand();
            delete.Transaction = tx;
            delete.CommandText = "DELETE FROM clients WHERE client_id = $client AND application_id = $app;";
            delete.Parameters.AddWithValue("$client", clientId);
            delete.Parameters.AddWithValue("$app", applicationId);
            if (delete.ExecuteNonQuery() != 1)
                return Task.FromResult(false);

            ExecuteIn(connection, tx,
                "UPDATE sessions SET revoked = 1, current_jti = NULL WHERE revoked = 0 AND client_id = $v;", clientId);

            BumpGeneration(connection, tx);
            tx.Commit();
            return Task.FromResult(true);
        }
    }

    /// <summary>Give a client a new secret, which makes it confidential. False when there is no such client.</summary>
    internal Task<bool> SetClientSecretAsync(string clientId, string secretHash, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteTransaction tx = connection.BeginTransaction();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "UPDATE clients SET secret_hash = $hash WHERE client_id = $id AND source = $source;";
            cmd.Parameters.AddWithValue("$id", clientId);
            cmd.Parameters.AddWithValue("$hash", secretHash);
            cmd.Parameters.AddWithValue("$source", ClientSources.Admin);
            bool set = cmd.ExecuteNonQuery() == 1;
            if (set)
                BumpGeneration(connection, tx);
            tx.Commit();
            return Task.FromResult(set);
        }
    }

    // ── The client a session was minted for ───────────────────────────────────

    /// <summary>The client a session was minted for, or null for one recorded without one.</summary>
    internal string? SessionClient(string sessionId)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT client_id FROM sessions WHERE session_id = $sid;";
        cmd.Parameters.AddWithValue("$sid", sessionId);
        return cmd.ExecuteScalar() as string;
    }

    private static void BindApplication(SqliteCommand cmd, Application application)
    {
        cmd.Parameters.AddWithValue("$id", application.Id);
        cmd.Parameters.AddWithValue("$name", application.Name);
        cmd.Parameters.AddWithValue("$audience", application.Audience);
        cmd.Parameters.AddWithValue("$manifest", (object?)application.ManifestUrl ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$lifetime", (long)application.AccessLifetime.TotalMinutes);
        cmd.Parameters.AddWithValue("$discord", Join(application.DiscordApplications));
        cmd.Parameters.AddWithValue("$act", application.ActForDiscord ? 1 : 0);
        cmd.Parameters.AddWithValue("$created", application.Created.ToString("O"));
    }

    private static bool Exists(SqliteConnection connection, SqliteTransaction tx, string sql, string value)
    {
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("$v", value);
        return cmd.ExecuteScalar() is not null;
    }

    private static int ExecuteIn(SqliteConnection connection, SqliteTransaction tx, string sql, string value)
    {
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("$v", value);
        return cmd.ExecuteNonQuery();
    }
}
