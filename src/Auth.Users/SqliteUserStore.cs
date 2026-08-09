using System.Data;
using System.Globalization;

using Microsoft.Data.Sqlite;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// The shipped <see cref="IUserStore"/>: one SQLite file on the host, read and written by every KGSM
/// surface running beside it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two processes share this file.</b> The Control Panel API and the assistant each open it
/// directly, so every assumption a single-writer store gets away with is wrong here. WAL is on so a
/// reader never blocks behind a writer; a busy timeout is set so two writers wait for each other
/// instead of failing instantly; foreign keys are on so a deleted account really does take its
/// credentials with it; and the schema version is checked at startup so a build never reads a file
/// it half understands.
/// </para>
/// <para>
/// <b>The file is <c>0600</c>.</b> It holds password hashes. The permission is set before WAL is
/// enabled, because SQLite gives the <c>-wal</c> and <c>-shm</c> files the mode the database had
/// when it created them — setting it afterwards leaves two world-readable files carrying the same
/// pages.
/// </para>
/// <para>
/// A connection is opened per operation and returned to the pool. Holding one open across a request
/// would pin a WAL read snapshot and keep the other process's checkpoints from completing.
/// </para>
/// </remarks>
public sealed class SqliteUserStore : IUserStore
{
    private const string UserColumns =
        "user_id, username, display_name, tier, tier_source, status, created_utc, updated_utc";

    private const string JoinedUserColumns =
        "u.user_id, u.username, u.display_name, u.tier, u.tier_source, u.status, u.created_utc, u.updated_utc";

    private const string CredentialColumns =
        "credential_id, user_id, kind, handle, secret, label, created_utc, last_used_utc";

    private readonly string _connectionString;
    private readonly TimeSpan _busyTimeout;

    /// <summary>
    /// Open the store at <paramref name="options"/>, creating and initialising the file if it is not
    /// there and checking its schema version if it is.
    /// </summary>
    /// <exception cref="UserStoreSchemaException">The file is newer than this build understands.</exception>
    public SqliteUserStore(UserStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _busyTimeout = options.BusyTimeout;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = options.Path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            ForeignKeys = true,
            Pooling = true,
            DefaultTimeout = (int)Math.Ceiling(options.BusyTimeout.TotalSeconds),
        }.ToString();

        string? directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(options.Path));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        Initialize(options.Path);
    }

    // ── schema ────────────────────────────────────────────────────────────────────────────────

    private void Initialize(string path)
    {
        using SqliteConnection connection = Connect();

        // Ahead of WAL: SQLite stamps -wal/-shm with the database's mode as it creates them, so a
        // chmod after the fact would leave those two carrying the same pages world-readable.
        Restrict(path);

        Execute(connection, "PRAGMA journal_mode=WAL;");

        using SqliteTransaction transaction =
            connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);

        Execute(connection, UserSchema.CreateV1, transaction);

        string? found = ScalarString(
            connection, "SELECT value FROM schema_meta WHERE key = $key;", transaction,
            ("$key", UserSchema.VersionKey));

        if (found is null)
        {
            Execute(
                connection,
                "INSERT INTO schema_meta (key, value) VALUES ($key, $value);", transaction,
                ("$key", UserSchema.VersionKey),
                ("$value", UserSchema.Version.ToString(CultureInfo.InvariantCulture)));
        }
        else
        {
            if (!int.TryParse(found, CultureInfo.InvariantCulture, out int version))
            {
                throw new UserStoreSchemaException(
                    $"The user store at '{path}' declares an unreadable schema version ('{found}'). " +
                    "Refusing to open it — this build cannot tell what it is looking at.");
            }

            if (version > UserSchema.Version)
            {
                throw new UserStoreSchemaException(
                    $"The user store at '{path}' is at schema version {version}; this build understands " +
                    $"{UserSchema.Version}. It was written by a newer KGSM service sharing this host. " +
                    "Refusing to open it — deploy the newer build here too rather than reading a file " +
                    "this one only half understands.");
            }

            // version < Version lands here, and there is nothing below 1 to bring forward. A future
            // bump adds its forward step at this point: additive DDL, then update the row.
        }

        transaction.Commit();
    }

    /// <summary>
    /// Take the store's file down to owner-only. Password hashes are the one thing on this host that
    /// a local read is worth anything against.
    /// </summary>
    private static void Restrict(string path)
    {
        if (OperatingSystem.IsWindows() || !File.Exists(path))
            return;

        const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if (File.GetUnixFileMode(path) != ownerOnly)
            File.SetUnixFileMode(path, ownerOnly);
    }

    // ── users ─────────────────────────────────────────────────────────────────────────────────

    /// <inheritdoc />
    public async Task<KgsmUser?> FindByIdAsync(string userId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return await ReadUserAsync(
            connection, $"SELECT {UserColumns} FROM users WHERE user_id = $id;", ct,
            ("$id", userId)).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<KgsmUser?> FindByUsernameAsync(string username, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return await ReadUserAsync(
            connection, $"SELECT {UserColumns} FROM users WHERE username_key = $key;", ct,
            ("$key", Usernames.Key(username))).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<KgsmUser?> FindByCredentialAsync(string handle, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return await ReadUserAsync(
            connection,
            $"""
             SELECT {JoinedUserColumns}
             FROM users u
             JOIN credentials c ON c.user_id = u.user_id
             WHERE c.handle = $handle;
             """,
            ct, ("$handle", handle)).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<KgsmUser>> ListAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection, $"SELECT {UserColumns} FROM users ORDER BY created_utc, user_id;");

        List<KgsmUser> users = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
            users.Add(MapUser(reader));

        return users;
    }

    /// <inheritdoc />
    public async Task CreateAsync(KgsmUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection,
            """
            INSERT INTO users
                (user_id, username, username_key, display_name, tier, tier_source, status, created_utc, updated_utc)
            VALUES
                ($id, $username, $key, $display, $tier, $source, $status, $created, $updated);
            """,
            ("$id", user.UserId),
            ("$username", user.Username),
            ("$key", Usernames.Key(user.Username)),
            ("$display", user.DisplayName),
            ("$tier", KgsmTiers.ToWire(user.Tier)),
            ("$source", TierSources.ToWire(user.TierSource)),
            ("$status", UserStatuses.ToWire(user.Status)),
            ("$created", UserWire.ToWire(user.Created)),
            ("$updated", UserWire.ToWire(user.Updated)));

        try
        {
            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        catch (SqliteException e) when (IsUniqueViolation(e, "username_key"))
        {
            throw new DuplicateUsernameException(user.Username);
        }
    }

    /// <inheritdoc />
    public async Task<bool> UpdateAsync(KgsmUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection,
            """
            UPDATE users SET
                username     = $username,
                username_key = $key,
                display_name = $display,
                tier         = $tier,
                tier_source  = $source,
                status       = $status,
                updated_utc  = $updated
            WHERE user_id = $id;
            """,
            ("$id", user.UserId),
            ("$username", user.Username),
            ("$key", Usernames.Key(user.Username)),
            ("$display", user.DisplayName),
            ("$tier", KgsmTiers.ToWire(user.Tier)),
            ("$source", TierSources.ToWire(user.TierSource)),
            ("$status", UserStatuses.ToWire(user.Status)),
            ("$updated", UserWire.ToWire(user.Updated)));

        try
        {
            return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
        }
        catch (SqliteException e) when (IsUniqueViolation(e, "username_key"))
        {
            throw new DuplicateUsernameException(user.Username);
        }
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(string userId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection, "DELETE FROM users WHERE user_id = $id;", ("$id", userId));

        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
    }

    // ── credentials ───────────────────────────────────────────────────────────────────────────

    /// <inheritdoc />
    public async Task<IReadOnlyList<UserCredential>> ListCredentialsAsync(
        string userId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection,
            $"SELECT {CredentialColumns} FROM credentials WHERE user_id = $id ORDER BY created_utc, credential_id;",
            ("$id", userId));

        List<UserCredential> credentials = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
            credentials.Add(MapCredential(reader));

        return credentials;
    }

    /// <inheritdoc />
    public async Task<UserCredential?> FindCredentialAsync(string handle, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection, $"SELECT {CredentialColumns} FROM credentials WHERE handle = $handle;",
            ("$handle", handle));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? MapCredential(reader) : null;
    }

    /// <inheritdoc />
    public async Task AddCredentialAsync(UserCredential credential, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection,
            """
            INSERT INTO credentials
                (credential_id, user_id, kind, handle, secret, label, created_utc, last_used_utc)
            VALUES
                ($id, $user, $kind, $handle, $secret, $label, $created, $used);
            """,
            ("$id", credential.CredentialId),
            ("$user", credential.UserId),
            ("$kind", CredentialKinds.ToWire(credential.Kind)),
            ("$handle", credential.Handle),
            ("$secret", (object?)credential.Secret ?? DBNull.Value),
            ("$label", (object?)credential.Label ?? DBNull.Value),
            ("$created", UserWire.ToWire(credential.Created)),
            ("$used", credential.LastUsed is { } used ? UserWire.ToWire(used) : DBNull.Value));

        try
        {
            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        catch (SqliteException e) when (IsUniqueViolation(e, "handle"))
        {
            throw new DuplicateCredentialException(credential.Handle);
        }
    }

    /// <inheritdoc />
    public async Task<bool> SetCredentialSecretAsync(
        string credentialId, string secret, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection, "UPDATE credentials SET secret = $secret WHERE credential_id = $id;",
            ("$id", credentialId), ("$secret", secret));

        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
    }

    /// <inheritdoc />
    public async Task TouchCredentialAsync(
        string credentialId, DateTimeOffset when, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection, "UPDATE credentials SET last_used_utc = $used WHERE credential_id = $id;",
            ("$id", credentialId), ("$used", UserWire.ToWire(when)));

        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> RemoveCredentialAsync(string credentialId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection, "DELETE FROM credentials WHERE credential_id = $id;", ("$id", credentialId));

        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
    }

    // ── lockout ───────────────────────────────────────────────────────────────────────────────

    /// <inheritdoc />
    public async Task<LoginLockout> GetLockoutAsync(
        string userId, LockoutPolicy policy, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(policy);

        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection,
            "SELECT failed_count, last_failed_utc, locked_until_utc FROM login_failures WHERE user_id = $id;",
            ("$id", userId));

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            return LoginLockout.Clear;

        return Standing(
            reader.GetInt32(0), UserWire.ReadTime(reader.GetString(1)),
            reader.IsDBNull(2) ? null : UserWire.ReadTime(reader.GetString(2)), policy, now);
    }

    /// <inheritdoc />
    public async Task<LoginLockout> RecordFailureAsync(
        string userId, LockoutPolicy policy, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(policy);

        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);

        // Read-then-write, so the transaction takes the write lock up front rather than upgrading a
        // read lock it already holds — an upgrade is what SQLITE_BUSY is for, and the other process
        // trying the same thing at the same time is exactly the case this has to survive.
        await using SqliteTransaction transaction =
            connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);

        int previous = 0;
        DateTimeOffset? lastFailed = null;

        await using (SqliteCommand read = Command(
            connection,
            "SELECT failed_count, last_failed_utc FROM login_failures WHERE user_id = $id;",
            transaction, ("$id", userId)))
        await using (SqliteDataReader reader = await read.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                previous = reader.GetInt32(0);
                lastFailed = UserWire.ReadTime(reader.GetString(1));
            }
        }

        bool stale = lastFailed is null || now - lastFailed.Value >= policy.FailureWindow;
        int count = stale ? 1 : previous + 1;

        TimeSpan delay = policy.DelayAfter(count);
        DateTimeOffset? lockedUntil = delay > TimeSpan.Zero ? now + delay : null;

        await using (SqliteCommand write = Command(
            connection,
            """
            INSERT INTO login_failures (user_id, failed_count, last_failed_utc, locked_until_utc)
            VALUES ($id, $count, $last, $until)
            ON CONFLICT(user_id) DO UPDATE SET
                failed_count     = excluded.failed_count,
                last_failed_utc  = excluded.last_failed_utc,
                locked_until_utc = excluded.locked_until_utc;
            """,
            transaction,
            ("$id", userId),
            ("$count", count),
            ("$last", UserWire.ToWire(now)),
            ("$until", lockedUntil is { } until ? UserWire.ToWire(until) : DBNull.Value)))
        {
            await write.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return new LoginLockout(count, lockedUntil);
    }

    /// <inheritdoc />
    public async Task ClearLockoutAsync(string userId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = Command(
            connection, "DELETE FROM login_failures WHERE user_id = $id;", ("$id", userId));

        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The standing a stored row implies. A run that has gone quiet for the policy's window is
    /// forgotten, but a lockout it already earned is still honoured until it expires on its own —
    /// letting the window reset an active lock would make waiting the cheapest way through it.
    /// </summary>
    private static LoginLockout Standing(
        int storedCount, DateTimeOffset lastFailed, DateTimeOffset? lockedUntil,
        LockoutPolicy policy, DateTimeOffset now)
    {
        bool stale = now - lastFailed >= policy.FailureWindow;
        return new LoginLockout(stale ? 0 : storedCount, lockedUntil);
    }

    // ── plumbing ──────────────────────────────────────────────────────────────────────────────

    private SqliteConnection Connect()
    {
        SqliteConnection connection = new(_connectionString);
        connection.Open();
        ApplyPragmas(connection);
        return connection;
    }

    private async Task<SqliteConnection> ConnectAsync(CancellationToken ct)
    {
        SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        ApplyPragmas(connection);
        return connection;
    }

    /// <summary>
    /// Set per-connection state the connection string cannot carry. <c>busy_timeout</c> is the one
    /// that matters: without it a write that collides with the other process's write fails on the
    /// spot instead of waiting the milliseconds it takes to clear.
    /// </summary>
    private void ApplyPragmas(SqliteConnection connection) =>
        Execute(connection, FormattableString.Invariant(
            $"PRAGMA busy_timeout={(int)_busyTimeout.TotalMilliseconds};"));

    private static SqliteCommand Command(
        SqliteConnection connection, string sql, params (string Name, object Value)[] parameters) =>
        Command(connection, sql, transaction: null, parameters);

    private static SqliteCommand Command(
        SqliteConnection connection, string sql, SqliteTransaction? transaction,
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
        SqliteConnection connection, string sql, SqliteTransaction? transaction = null,
        params (string Name, object Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, sql, transaction, parameters);
        command.ExecuteNonQuery();
    }

    private static string? ScalarString(
        SqliteConnection connection, string sql, SqliteTransaction? transaction,
        params (string Name, object Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, sql, transaction, parameters);
        return command.ExecuteScalar() as string;
    }

    private static async Task<KgsmUser?> ReadUserAsync(
        SqliteConnection connection, string sql, CancellationToken ct,
        params (string Name, object Value)[] parameters)
    {
        await using SqliteCommand command = Command(connection, sql, transaction: null, parameters);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false) ? MapUser(reader) : null;
    }

    private static KgsmUser MapUser(SqliteDataReader reader) => new(
        UserId: reader.GetString(0),
        Username: reader.GetString(1),
        DisplayName: reader.GetString(2),
        Tier: KgsmTiers.Parse(reader.GetString(3)),
        TierSource: TierSources.Parse(reader.GetString(4)),
        Status: UserStatuses.Parse(reader.GetString(5)),
        Created: UserWire.ReadTime(reader.GetString(6)),
        Updated: UserWire.ReadTime(reader.GetString(7)));

    private static UserCredential MapCredential(SqliteDataReader reader) => new(
        CredentialId: reader.GetString(0),
        UserId: reader.GetString(1),
        Kind: CredentialKinds.Parse(reader.GetString(2)),
        Handle: reader.GetString(3),
        Secret: reader.IsDBNull(4) ? null : reader.GetString(4),
        Label: reader.IsDBNull(5) ? null : reader.GetString(5),
        Created: UserWire.ReadTime(reader.GetString(6)),
        LastUsed: reader.IsDBNull(7) ? null : UserWire.ReadTime(reader.GetString(7)));

    /// <summary>
    /// Whether this failure is the unique index on <paramref name="column"/> refusing a duplicate,
    /// as opposed to any other constraint. Matched on the extended result code and the column name
    /// SQLite names in the message, so a foreign-key or not-null failure is never reported to a
    /// caller as "that name is taken".
    /// </summary>
    private static bool IsUniqueViolation(SqliteException e, string column) =>
        e.SqliteExtendedErrorCode == 2067 &&
        e.Message.Contains('.' + column, StringComparison.Ordinal);
}
