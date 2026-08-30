using Microsoft.AspNetCore.Mvc.Testing;

using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// One anchor, standing on its own account store in a temporary directory.
/// </summary>
/// <remarks>
/// <para>
/// The daemon is started through its own <c>Program</c> rather than a stand-in, so what the tests
/// exercise is the composition that ships — the same key file, the same session registry, the same
/// live authority read on every request. A test that built its own service graph would prove the
/// graph the test wrote.
/// </para>
/// <para>
/// Configuration arrives through environment variables because that is how the daemon is configured
/// on a host: the settings file is the floor and a variable overrides one key of it. Setting them
/// before the host is built is what makes the paths land in a temporary directory instead of
/// <c>/var/lib</c>.
/// </para>
/// </remarks>
public sealed class AnchorFixture : IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;

    /// <summary>Where this fixture's files live. Removed with the fixture.</summary>
    public string Root { get; }

    /// <summary>The account store, open for a test to seed directly through the library.</summary>
    public SqliteUserStore Store { get; }

    /// <summary>The password hasher the daemon itself uses, so a seeded password is a real one.</summary>
    public IUserPasswordHasher Hasher { get; } = new IdentityPasswordHasher();

    /// <summary>The cluster this anchor mints sessions for.</summary>
    public const string ClusterId = "test-cluster";

    public AnchorFixture()
    {
        Root = Path.Combine(Path.GetTempPath(), "kgsm-auth-anchor-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);

        Environment.SetEnvironmentVariable("Anchor__UserStorePath", Path.Combine(Root, "users.db"));
        Environment.SetEnvironmentVariable("Anchor__SessionStorePath", Path.Combine(Root, "sessions.db"));
        Environment.SetEnvironmentVariable("Anchor__SigningKeyPath", Path.Combine(Root, "signing.pem"));
        // No shared cluster directory in a test, so the anchor publishes no file. Pointed at one
        // inside the fixture rather than left at its default, which would write into the real host's
        // /var/lib/kgsm/cluster.
        Environment.SetEnvironmentVariable("Anchor__PublishedKeyPath", Path.Combine(Root, "cluster", "key.json"));
        Environment.SetEnvironmentVariable("Anchor__ClusterId", ClusterId);
        Environment.SetEnvironmentVariable("Anchor__AllowedOrigins", "https://panel.test");

        Store = new SqliteUserStore(new UserStoreOptions { Path = Path.Combine(Root, "users.db") });

        _factory = new WebApplicationFactory<Program>();
        Client = _factory.CreateClient();
    }

    /// <summary>A client onto the running anchor.</summary>
    public HttpClient Client { get; }

    /// <summary>An account with a password, as an admin would have created it.</summary>
    public async Task<KgsmUser> SeedAsync(
        string username, string password, KgsmTier tier, UserStatus status = UserStatus.Active)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var user = new KgsmUser(
            UserIds.NewUserId(), username, username, tier, TierSource.Granted, status, now, now);

        await Store.CreateAsync(user);
        await Store.AddCredentialAsync(new UserCredential(
            UserIds.NewCredentialId(), user.UserId, CredentialKind.Password,
            UserCredentials.LocalHandle(user.UserId), Hasher.Hash(password),
            Label: null, Created: now, LastUsed: null));

        return user;
    }

    public void Dispose()
    {
        Client.Dispose();
        _factory.Dispose();
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
            // A file the daemon still holds open. The temp tree is disposable either way.
        }
    }
}

/// <summary>
/// One anchor per run.
/// </summary>
/// <remarks>
/// Shared rather than per-test because the daemon is configured through process environment
/// variables, and two fixtures standing at once would each set them for the other.
/// </remarks>
[CollectionDefinition(Name)]
public sealed class AnchorCollection : ICollectionFixture<AnchorFixture>
{
    public const string Name = "anchor";
}
