using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;

using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Cluster.Tests;

/// <summary>
/// The replica the member that keeps it owns: created when absent, and a version 1 file set aside for
/// the holder's snapshot to replace.
/// </summary>
public sealed class OwnedReplicaFileTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "kgsm-owned-replica-" + Guid.NewGuid().ToString("N"));
    private readonly string _path;

    public OwnedReplicaFileTests()
    {
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "users.db");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private OwnedReplicaFile Owned() => new(_path, NullLogger<OwnedReplicaFile>.Instance);

    private void Raw(string sql)
    {
        using SqliteConnection connection = new($"Data Source={_path};Pooling=False");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    [Fact]
    public async Task AMissingFileIsCreatedAtVersionTwo()
    {
        SqliteAuthorityStore? replica = Owned().Replica;

        Assert.NotNull(replica);
        Assert.True(File.Exists(_path));
        Assert.Equal(1, (await replica.LoadAsync()).Version);
    }

    [Fact]
    public void AVersionOneFileIsSetAsideAndReplaced()
    {
        Raw("""
            CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1');
            CREATE TABLE users (user_id TEXT PRIMARY KEY, tier TEXT NOT NULL);
            INSERT INTO users VALUES ('usr_old', 'admin');
            """);

        OwnedReplicaFile owned = Owned();

        Assert.NotNull(owned.Replica);
        Assert.Null(owned.UnavailableReason);
        string aside = Assert.Single(Directory.GetFiles(_dir, "users.db.v1-discarded-*"));
        using SqliteConnection old = new($"Data Source={aside};Pooling=False;Mode=ReadOnly");
        old.Open();
        using SqliteCommand count = old.CreateCommand();
        count.CommandText = "SELECT count(*) FROM users;";
        Assert.Equal(1L, count.ExecuteScalar());
    }

    [Fact]
    public void AFileNewerThanThisBuildIsLeftAloneAndReportedUnavailable()
    {
        Raw("""
            CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_meta (key, value) VALUES ('schema_version', '9');
            """);

        OwnedReplicaFile owned = Owned();

        Assert.Null(owned.Replica);
        Assert.NotNull(owned.UnavailableReason);
        Assert.Empty(Directory.GetFiles(_dir, "users.db.v1-discarded-*"));
    }

    [Fact]
    public async Task AVersionTwoFileIsOpenedAsItIs()
    {
        SqliteAuthorityStore first = new(new UserStoreOptions { Path = _path });
        await first.CreateAsync(new KgsmUser("usr_kept", "kept", "kept", AccountOrigin.Admitted, UserStatus.Active,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch));

        Assert.NotNull(await Owned().Replica!.FindByIdAsync("usr_kept"));
    }
}
