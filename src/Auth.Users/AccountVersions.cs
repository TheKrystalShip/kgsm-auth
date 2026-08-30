using System.Data;
using System.Globalization;

using Microsoft.Data.Sqlite;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// The per-account counter that orders account changes between members of a cluster.
/// </summary>
/// <remarks>
/// <para>
/// One writer assigns it — the member holding the cluster's accounts — and every replica compares
/// against it. A change carrying a version no higher than the one a replica already holds is dropped,
/// which is what stops a re-ordered tier arriving after a disable and quietly re-enabling somebody.
/// A counter rather than a timestamp, because one writer makes it trivial and it removes any
/// dependence on clocks agreeing.
/// </para>
/// <para>
/// <b>Its own table, and <see cref="UserSchema.Version"/> deliberately does not move.</b> The account
/// store is opened by every surface on a host, each pinned to its own build of this package, and the
/// schema guard refuses a file declaring a version newer than the build reading it — on purpose,
/// because half-understood accounts is the failure that grants access quietly. Bumping it would
/// therefore refuse the Control Panel, the bot and the assistant simultaneously until all three were
/// redeployed. A table an older build has never heard of is invisible to it instead: it reads
/// accounts exactly as it did, and nothing is half-understood.
/// </para>
/// <para>
/// The version is also not a property of the person. It orders replication; no surface renders it,
/// and an account means the same thing whether or not this table has a row for it.
/// </para>
/// <para>
/// <b>A row outlives the account it belongs to, and that is the tombstone.</b> Deleting an account
/// leaves its version behind, so a stale change for a lower version is still dropped rather than
/// re-creating somebody who was removed.
/// </para>
/// </remarks>
public interface IAccountVersions
{
    /// <summary>
    /// The version an account currently holds here, or <c>0</c> when this member has never seen one.
    /// </summary>
    /// <remarks>
    /// Zero rather than null so a caller compares numbers rather than branching on absence: an
    /// account nobody has ever changed and one whose first change is arriving are the same case.
    /// </remarks>
    Task<long> CurrentAsync(string userId, CancellationToken ct = default);

    /// <summary>
    /// Assign the next version to an account. The writer's call, and the only thing that raises one.
    /// </summary>
    /// <remarks>
    /// Atomic: the read and the increment are one statement, so two concurrent changes to one account
    /// take two versions rather than the same one twice.
    /// </remarks>
    Task<long> NextAsync(string userId, DateTimeOffset now, CancellationToken ct = default);

    /// <summary>
    /// Record that <paramref name="version"/> has been applied, if it is newer than what is held.
    /// Returns whether it was — which is the caller's signal to apply the change itself.
    /// </summary>
    /// <remarks>
    /// The comparison and the write are one statement for the same reason: two deliveries of the same
    /// change racing must not both conclude they are the newer one. A caller that gets
    /// <see langword="false"/> has been handed something it already knows, or something older, and
    /// applying it would move the account backwards.
    /// </remarks>
    Task<bool> TryAdvanceAsync(
        string userId, long version, DateTimeOffset now, CancellationToken ct = default);

    /// <summary>Every version this member holds, for a caller reconciling a full snapshot.</summary>
    Task<IReadOnlyDictionary<string, long>> AllAsync(CancellationToken ct = default);
}

/// <summary>The shipped <see cref="IAccountVersions"/>, in the account store's own file.</summary>
/// <remarks>
/// The same file as the accounts, because a version and the account state it describes have to move
/// together: two files would let a machine hold accounts at one point in time and versions at
/// another, and the disagreement would be invisible until a change was wrongly dropped or wrongly
/// applied.
/// </remarks>
public sealed class SqliteAccountVersions : IAccountVersions
{
    private readonly string _connectionString;

    /// <summary>Opens (and creates) the version table beside the accounts in <paramref name="options"/>.</summary>
    public SqliteAccountVersions(UserStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = options.Path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            DefaultTimeout = (int)Math.Max(1, options.BusyTimeout.TotalSeconds),
        }.ToString();

        using SqliteConnection connection = Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = UserSchema.CreateAccountVersions;
        command.ExecuteNonQuery();
    }

    public async Task<long> CurrentAsync(string userId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        await using SqliteConnection connection = await OpenAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT version FROM account_versions WHERE user_id = $id;";
        command.Parameters.AddWithValue("$id", userId);

        object? found = await command.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return found is long v ? v : 0;
    }

    public async Task<long> NextAsync(string userId, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        await using SqliteConnection connection = await OpenAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO account_versions (user_id, version, updated_utc)
            VALUES ($id, 1, $now)
            ON CONFLICT(user_id) DO UPDATE SET
                version     = account_versions.version + 1,
                updated_utc = excluded.updated_utc
            RETURNING version;
            """;
        command.Parameters.AddWithValue("$id", userId);
        command.Parameters.AddWithValue("$now", UserWire.ToWire(now));

        object? assigned = await command.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return assigned is long v ? v : 0;
    }

    public async Task<bool> TryAdvanceAsync(
        string userId, long version, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        // A version at or below zero names nothing this counter ever assigns, so it cannot be newer
        // than anything and is refused before it reaches the store.
        if (version <= 0)
            return false;

        await using SqliteConnection connection = await OpenAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO account_versions (user_id, version, updated_utc)
            VALUES ($id, $version, $now)
            ON CONFLICT(user_id) DO UPDATE SET
                version     = excluded.version,
                updated_utc = excluded.updated_utc
            WHERE excluded.version > account_versions.version;
            """;
        command.Parameters.AddWithValue("$id", userId);
        command.Parameters.AddWithValue("$version", version);
        command.Parameters.AddWithValue("$now", UserWire.ToWire(now));

        return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
    }

    public async Task<IReadOnlyDictionary<string, long>> AllAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await OpenAsync(ct).ConfigureAwait(false);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT user_id, version FROM account_versions;";

        var versions = new Dictionary<string, long>(StringComparer.Ordinal);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
            versions[reader.GetString(0)] = reader.GetInt64(1);

        return versions;
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        return connection;
    }
}
