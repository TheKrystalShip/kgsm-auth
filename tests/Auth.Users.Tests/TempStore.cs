using Microsoft.Data.Sqlite;

namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// A real store on a real file, in a directory of its own, deleted afterwards.
/// </summary>
/// <remarks>
/// <para>
/// The store is not faked out for these tests, because most of what it promises is enforced by
/// SQLite rather than by C#: the uniqueness that stops an identity being linked twice, the cascade
/// that takes credentials with an account, the file mode that keeps password hashes owner-only, and
/// the schema-version gate. A double would assert the code around those and none of them.
/// </para>
/// <para>
/// Each instance gets its own directory so a test can open a second store over the same file — the
/// two-process case that is normal on a host, where the Control Panel API and the assistant both
/// have this open.
/// </para>
/// </remarks>
internal sealed class TempStore : IDisposable
{
    private readonly string _directory;

    public TempStore(TimeSpan? busyTimeout = null)
    {
        _directory = Path.Combine(Path.GetTempPath(), "kgsm-users-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
        Path_ = Path.Combine(_directory, "users.db");

        Options = new UserStoreOptions
        {
            Path = Path_,
            BusyTimeout = busyTimeout ?? TimeSpan.FromSeconds(5),
        };

        Store = new SqliteUserStore(Options);
    }

    public string Path_ { get; }

    public UserStoreOptions Options { get; }

    public SqliteUserStore Store { get; }

    /// <summary>A second store over the same file, as a second service on the host would open it.</summary>
    public SqliteUserStore OpenAgain() => new(new UserStoreOptions
    {
        Path = Path_,
        BusyTimeout = Options.BusyTimeout,
    });

    /// <summary>Run SQL against the file directly, to set up states the API cannot produce.</summary>
    public void Raw(string sql)
    {
        using SqliteConnection connection = new($"Data Source={Path_}");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    public void Dispose()
    {
        // The pool holds the file open, and Windows-style deletion failures aside, leaving a handle
        // open here leaks a connection into the next test in the same process.
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

/// <summary>Builders for the records these tests are about, so a test states only what it is testing.</summary>
internal static class Make
{
    public static readonly DateTimeOffset Now = new(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);

    public static KgsmUser User(
        string username = "haru",
        KgsmTier tier = KgsmTier.Operator,
        UserStatus status = UserStatus.Active,
        TierSource source = TierSource.Granted,
        string? userId = null) =>
        new(
            userId ?? UserIds.NewUserId(),
            username,
            DisplayName: username,
            tier,
            source,
            status,
            Created: Now,
            Updated: Now);

    public static UserCredential Identity(string userId, string handle, string? label = null) =>
        new(
            UserIds.NewCredentialId(), userId, CredentialKind.Identity, handle,
            Secret: null, Label: label, Created: Now, LastUsed: null);
}
