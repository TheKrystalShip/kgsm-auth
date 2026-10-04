using System.Globalization;

using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Cluster;

/// <summary>
/// The authority replica of the member that keeps it: the one process on a machine that joins the
/// cluster, takes the snapshot and applies the changes the holder sends.
/// </summary>
/// <remarks>
/// <para>
/// <b>It creates the file, and it discards a file at an older schema version rather than converting
/// it.</b> A replica is whatever the holder of the accounts last said, so there is nothing in an old one
/// worth carrying: the snapshot rebuilds it whole. An older file is moved aside as
/// <c>&lt;path&gt;.discarded-&lt;utc&gt;</c>, owner-only like the file it was, and a fresh store is
/// created in its place.
/// </para>
/// <para>
/// A file newer than this build understands is left alone and reported unavailable, asked again at most
/// once a minute: discarding what a newer build wrote would be this build deciding it knows better.
/// </para>
/// <para>
/// Every other process on the machine reads the same file through <see cref="AuthorityReplicaFile"/>,
/// which never creates it — one writer per machine.
/// </para>
/// </remarks>
public sealed class OwnedReplicaFile(string path, ILogger<OwnedReplicaFile> logger, TimeProvider? clock = null)
    : IReplicatedAuthority
{
    private static readonly TimeSpan Retry = TimeSpan.FromMinutes(1);

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private SqliteAuthorityStore? _replica;
    private string? _unavailable;
    private DateTimeOffset _nextTry = DateTimeOffset.MinValue;

    /// <inheritdoc />
    public SqliteAuthorityStore? Replica
    {
        get
        {
            lock (_gate)
            {
                if (_replica is not null || _clock.GetUtcNow() < _nextTry)
                    return _replica;

                _nextTry = _clock.GetUtcNow() + Retry;
                try
                {
                    if (VersionOf(path) is { } version && version < AuthoritySchema.Version)
                        Discard(version);

                    _replica = new SqliteAuthorityStore(new UserStoreOptions { Path = path });
                    _unavailable = null;
                }
                catch (Exception e) when (e is UserStoreSchemaException or SqliteException or IOException or UnauthorizedAccessException)
                {
                    if (_unavailable != e.Message)
                        logger.LogWarning("the authority replica at {Path} is unavailable: {Reason}", path, e.Message);
                    _unavailable = e.Message;
                }

                return _replica;
            }
        }
    }

    /// <inheritdoc />
    public string? UnavailableReason
    {
        get
        {
            _ = Replica;
            lock (_gate)
                return _unavailable;
        }
    }

    // The schema version a file states, or null for a file that does not exist or states none.
    private static int? VersionOf(string file)
    {
        if (!File.Exists(file))
            return null;

        using SqliteConnection connection = new(new SqliteConnectionStringBuilder
        {
            DataSource = file,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();

        using SqliteCommand exists = connection.CreateCommand();
        exists.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta';";
        if (exists.ExecuteScalar() is null)
            return null;

        using SqliteCommand read = connection.CreateCommand();
        read.CommandText = "SELECT value FROM schema_meta WHERE key = $key;";
        read.Parameters.AddWithValue("$key", UserSchema.VersionKey);
        return int.TryParse(read.ExecuteScalar() as string, NumberStyles.Integer, CultureInfo.InvariantCulture, out int version)
            ? version
            : null;
    }

    private void Discard(int version)
    {
        string aside = path + ".discarded-" + _clock.GetUtcNow().UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        SqliteConnection.ClearAllPools();
        File.Move(path, aside);
        foreach (string suffix in new[] { "-wal", "-shm" })
        {
            if (File.Exists(path + suffix))
                File.Move(path + suffix, aside + suffix);
        }

        logger.LogWarning(
            "the replica at {Path} was at schema version {Version}; moved it to {Aside} and started a fresh one for the holder's snapshot",
            path, version, aside);
    }
}
