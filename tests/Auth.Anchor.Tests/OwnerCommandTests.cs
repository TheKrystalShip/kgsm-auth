using System.Text.Json;

using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Extensions;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// <c>kgsm-auth-anchor owner grant</c>: Owner assigned from the host's shell, and journaled like any
/// other grant.
/// </summary>
/// <remarks>
/// In the anchor's collection because the journal's state root is a process environment variable,
/// and the fixture's daemon reads the same one.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class OwnerCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "kgsm-owner-" + Guid.NewGuid().ToString("N"));
    private readonly string? _stateRoot = Environment.GetEnvironmentVariable(JournalServiceCollectionExtensions.StateRootVariable);
    private readonly AnchorOptions _options;

    public OwnerCommandTests()
    {
        Directory.CreateDirectory(_root);
        Environment.SetEnvironmentVariable(JournalServiceCollectionExtensions.StateRootVariable, Path.Combine(_root, "state"));
        _options = AnchorOptions.FromSettings(new AnchorSettings { UserStorePath = Path.Combine(_root, "users.db") });
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(JournalServiceCollectionExtensions.StateRootVariable, _stateRoot);
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private SqliteAuthorityStore Store() => new(new UserStoreOptions { Path = _options.UserStorePath });

    private string Person(string username)
    {
        Store();
        string id = UserIds.NewUserId();
        using SqliteConnection connection = new($"Data Source={_options.UserStorePath}");
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"""
             INSERT INTO users (user_id, username, username_key, display_name, origin, kind, status, created_utc, updated_utc)
             VALUES ('{id}', '{username}', '{username}', '{username}', 'admitted', 'person', 'active', '2026-09-25T12:00:00Z', '2026-09-25T12:00:00Z');
             """;
        command.ExecuteNonQuery();
        return id;
    }

    private IReadOnlyList<JsonElement> Journal()
    {
        string directory = Path.Combine(_root, "state", AnchorJournal.ProducerId, "events");
        return Directory.Exists(directory)
            ? [.. Directory.GetFiles(directory, "*.ndjson").SelectMany(File.ReadAllLines)
                .Where(l => l.Length > 0).Select(l => JsonDocument.Parse(l).RootElement.Clone())]
            : [];
    }

    [Fact]
    public async Task OwnerIsGrantedAndTheGrantIsJournaledUnderTheLocalUser()
    {
        string alice = Person("alice");

        int exit = await OwnerCommand.RunAsync(["owner", "grant", "alice"], _options);

        Assert.Equal(0, exit);
        Assert.True((await Store().LoadAsync()).IsOwner(alice));

        JsonElement line = Assert.Single(Journal());
        Assert.Equal(AuthEvents.AssignmentGranted, line.GetProperty("EventType").GetString());
        Assert.Equal($"local:{Environment.UserName}", line.GetProperty("Actor").GetString());
        JsonElement data = line.GetProperty("Data");
        Assert.Equal(alice, data.GetProperty("UserId").GetString());
        Assert.Equal(BuiltInRoles.OwnerId, data.GetProperty("RoleId").GetString());
        Assert.Equal("cluster", data.GetProperty("Scope").GetString());
        Assert.Equal(await Store().VersionAsync(), data.GetProperty("AuthorityVersion").GetInt64());
    }

    [Fact]
    public async Task GrantingAnExistingOwnerChangesAndRecordsNothing()
    {
        Person("alice");
        await OwnerCommand.RunAsync(["owner", "grant", "alice"], _options);
        long version = await Store().VersionAsync();

        Assert.Equal(0, await OwnerCommand.RunAsync(["owner", "grant", "alice"], _options));

        Assert.Equal(version, await Store().VersionAsync());
        Assert.Single(Journal());
    }

    [Fact]
    public async Task AnUnknownAccountIsAFailure()
    {
        Person("alice");

        Assert.Equal(1, await OwnerCommand.RunAsync(["owner", "grant", "nobody"], _options));
        Assert.Empty(Journal());
    }

    [Fact]
    public async Task AStoreAtAnotherSchemaVersionIsRefused()
    {
        using (Microsoft.Data.Sqlite.SqliteConnection connection = new($"Data Source={_options.UserStorePath};Pooling=False"))
        {
            connection.Open();
            using Microsoft.Data.Sqlite.SqliteCommand command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1');
                """;
            command.ExecuteNonQuery();
        }

        Assert.Equal(1, await OwnerCommand.RunAsync(["owner", "grant", "alice"], _options));
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("owner", "grant")]
    [InlineData("owner", "revoke", "alice")]
    public async Task AnythingButGrantAndAUsernameIsUsage(params string[] args) =>
        Assert.Equal(2, await OwnerCommand.RunAsync(args, _options));
}
