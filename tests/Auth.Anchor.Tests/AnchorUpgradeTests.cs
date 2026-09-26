using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Extensions;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// The anchor on its account store at schema version 2: the first administrator it makes is an Owner,
/// and the start that brings a version 1 store forward ends every session there was.
/// </summary>
/// <remarks>
/// In the anchor's collection because the journal's state root is a process environment variable: the
/// bootstrapper built here writes to the fixture's journal, which is where the assertion reads it.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class AnchorUpgradeTests(AnchorFixture anchor) : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "kgsm-anchor-upgrade-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task The_first_administrator_an_empty_store_gets_is_an_Owner()
    {
        KgsmUser admin = (await anchor.Store.FindByUsernameAsync(FirstAdmin.DefaultUsername))!;

        AuthoritySnapshot s = await anchor.Store.LoadAsync();
        Assert.True(s.IsOwner(admin.UserId));
        Assert.True(new AccessEvaluator(s).Allows(admin.UserId, AuthActions.RolesEdit, AccessScope.Cluster).Allowed);
    }

    [Fact]
    public async Task The_start_that_upgrades_the_store_ends_every_session_and_says_why()
    {
        Directory.CreateDirectory(_root);
        string users = Path.Combine(_root, "users.db");
        string sessionsPath = Path.Combine(_root, "sessions.db");
        DateTimeOffset now = DateTimeOffset.UtcNow;

        // A version 1 store with an administrator, and a browser signed in under the tiers.
        string rootId = UserIds.NewUserId();
        using (Microsoft.Data.Sqlite.SqliteConnection connection = new($"Data Source={users};Pooling=False"))
        {
            connection.Open();
            using Microsoft.Data.Sqlite.SqliteCommand command = connection.CreateCommand();
            command.CommandText = """
                CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE users (
                    user_id TEXT PRIMARY KEY, username TEXT NOT NULL, username_key TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL, tier TEXT NOT NULL, tier_source TEXT NOT NULL, status TEXT NOT NULL,
                    created_utc TEXT NOT NULL, updated_utc TEXT NOT NULL);
                CREATE TABLE credentials (
                    credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    kind TEXT NOT NULL, handle TEXT NOT NULL UNIQUE, secret TEXT NULL, label TEXT NULL,
                    created_utc TEXT NOT NULL, last_used_utc TEXT NULL);
                CREATE TABLE login_failures (
                    user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE, failed_count INTEGER NOT NULL,
                    last_failed_utc TEXT NOT NULL, locked_until_utc TEXT NULL);
                INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1');
                INSERT INTO users VALUES ($id, 'root', 'root', 'root', 'admin', 'granted', 'active', $at, $at);
                """;
            command.Parameters.AddWithValue("$id", rootId);
            command.Parameters.AddWithValue("$at", now.UtcDateTime.ToString("o"));
            command.ExecuteNonQuery();
        }

        SqliteSessionRegistry registry = new(sessionsPath);
        await registry.CreateProviderSessionAsync("psid", $"local:{rootId}", "{}", "cookie", "c", now, now.AddDays(1), null);
        await registry.CreateAsync(new SessionRegistration("sid", $"local:{rootId}", "c", now, now.AddDays(1), null, "jti"), "psid");
        Assert.True(await registry.IsAliveAsync("sid"));

        UpgradeReport upgrade = UserStoreUpgrade.ToVersion2(users, now);
        Assert.True(upgrade.Upgraded);

        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton(AnchorOptions.FromSettings(new AnchorSettings { UserStorePath = users, SessionStorePath = sessionsPath }));
        services.AddKgsmJournal(AnchorJournal.ProducerId, typeof(AnchorJournal).Assembly);
        services.AddSingleton<AnchorJournal>();
        services.AddSingleton<AnchorAuthority>();
        services.AddSingleton<IUserStore>(sp => sp.GetRequiredService<AnchorAuthority>().Store!);
        services.AddSingleton<IUserPasswordHasher, IdentityPasswordHasher>();
        services.AddSingleton(sp => new LocalSignInService(sp.GetRequiredService<IUserStore>(),
            sp.GetRequiredService<IUserPasswordHasher>()));
        services.AddSingleton(registry);
        services.AddSingleton(upgrade);
        services.AddSingleton<AnchorBootstrapper>();
        await using ServiceProvider provider = services.BuildServiceProvider();

        await provider.GetRequiredService<AnchorBootstrapper>().StartAsync(default);

        Assert.False(await registry.IsAliveAsync("sid"));
        Assert.Contains(anchor.Journal(AuthEvents.SessionRevoked),
            e => e.GetProperty("Data").GetProperty("Scope").GetString() == SessionRevokeScopes.Upgrade);

        // The administrator is the store's Owner, and the store had accounts, so nobody new was made.
        AuthoritySnapshot s = await provider.GetRequiredService<AnchorAuthority>().Store!.LoadAsync();
        Assert.True(s.IsOwner(rootId));
        Assert.Single(s.Accounts.Values, a => a.Kind == AccountKind.Person);
    }
}
