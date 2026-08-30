using Microsoft.AspNetCore.Mvc.Testing;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Identity;

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

    /// <summary>This anchor's own identity as a member of that cluster.</summary>
    public const string MemberId = "test-anchor";

    /// <summary>Where this anchor says it is reached, as a deployment behind a proxy has to.</summary>
    public const string SignInUrl = "https://auth.test";

    /// <summary>Where a browser is sent back to after a provider sign-in.</summary>
    public const string PanelUrl = "https://panel.test";

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
        Environment.SetEnvironmentVariable("Anchor__MemberId", MemberId);
        Environment.SetEnvironmentVariable("Anchor__PublicBaseUrl", SignInUrl);
        Environment.SetEnvironmentVariable("Anchor__FrontendUrl", PanelUrl);
        Environment.SetEnvironmentVariable("Anchor__AllowSelfRegistration", "true");

        // The host's shared OAuth application, as /etc/kgsm/kgsm-auth.env supplies it on a real
        // machine. Present so the provider door is wired at all — nothing here reaches a provider,
        // because every case under test is decided before an exchange is attempted.
        Environment.SetEnvironmentVariable("KgsmAuth__Providers__discord__ClientId", "test-client-id");
        Environment.SetEnvironmentVariable("KgsmAuth__Providers__discord__ClientSecret", "test-client-secret");

        // A real secret, so this anchor is a real member: it mints service tokens another member
        // would present, and it claims the auth capability on start exactly as a deployed one does.
        // Without it the daemon is standalone — which is also a state worth testing, but not one in
        // which any member-to-member door can be opened at all.
        Environment.SetEnvironmentVariable("Cluster__Secret", "a shared secret for the test cluster");

        Store = new SqliteUserStore(new UserStoreOptions { Path = Path.Combine(Root, "users.db") });

        _factory = new WebApplicationFactory<Program>();
        Client = _factory.CreateClient();

        // A clustered anchor starts standing by and becomes the holder once it has read the
        // assignment — deliberately, so it is never the authority during the window in which it does
        // not know whether it is one. Waited out here rather than raced by every test.
        WaitUntilHolding();
    }

    private void WaitUntilHolding()
    {
        var role = (AnchorRole)_factory.Services.GetService(typeof(AnchorRole))!;
        for (int attempt = 0; attempt < 100 && !role.IsAuthority; attempt++)
            Thread.Sleep(100);

        if (!role.IsAuthority)
            throw new InvalidOperationException("the anchor never took the auth capability");
    }

    /// <summary>A client onto the running anchor.</summary>
    public HttpClient Client { get; }

    /// <summary>Something out of the running daemon's own service graph.</summary>
    public T Service<T>() => (T)_factory.Services.GetService(typeof(T))!;

    /// <summary>
    /// A client that reports a redirect rather than following it — the whole of what an OAuth bounce
    /// and the handoff back to a panel are, so following one would assert against wherever it landed
    /// instead of against what this anchor said.
    /// </summary>
    public HttpClient Following() => _factory.CreateClient(
        new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    /// <summary>
    /// Run <paramref name="body"/> with the anchor standing by, as a second install in a cluster
    /// somebody else holds would be, and put it back afterwards.
    /// </summary>
    /// <remarks>
    /// The running host's own singleton is moved rather than a second anchor stood up beside this
    /// one: the daemon is configured through process environment variables, so two of them in one
    /// test process would each set them for the other. What is under test is the endpoints' reaction
    /// to the standing, and this drives the real pipeline into it.
    /// </remarks>
    public async Task StandingBy(string holder, Func<Task> body)
    {
        var role = (AnchorRole)_factory.Services.GetService(typeof(AnchorRole))!;
        role.Update(AnchorStanding.StandingBy, holder);
        try
        {
            await body();
        }
        finally
        {
            role.Update(AnchorStanding.Holder, MemberId);
        }
    }

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

    /// <summary>
    /// A service token as another member of this cluster would present one.
    /// </summary>
    /// <remarks>
    /// Minted through the running anchor's own token service, so what the test presents is what a
    /// real member presents — signed with the same secret, and validated by the same code.
    /// Members share one secret, so a token bearing another member's id is exactly what a real one
    /// is: attribution, not isolation.
    /// </remarks>
    public string MintMemberToken() =>
        ((IClusterTokenService)_factory.Services.GetService(typeof(IClusterTokenService))!).Mint().Token;

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
