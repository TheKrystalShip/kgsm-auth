using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// The administrator an anchor with no accounts creates for itself.
/// </summary>
/// <remarks>
/// <para>
/// Without one, a fresh anchor is a door nobody can open. Registration is off unless a cluster turns
/// it on, and an account made through it holds <c>none</c> and waits for an approval only an
/// administrator can give — so the first person to arrive is stuck behind an account nobody exists to
/// approve, and the only way in is SQL against the account store.
/// </para>
/// <para>
/// It hides wherever an anchor shares a machine with a Control Panel: they share one account store and
/// the panel bootstrapped it first. An anchor on a machine of its own starts with nothing.
/// </para>
/// <para>
/// These drive <see cref="FirstAdmin"/> directly against a temporary store rather than the running
/// fixture, because the fixture's anchor has already started — and the whole subject is what happens
/// on a start that finds nothing.
/// </para>
/// </remarks>
public sealed class BootstrapAdminTests : IDisposable
{
    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "kgsm-anchor-bootstrap-" + Guid.NewGuid().ToString("N"));

    private (IUserStore Store, LocalSignInService SignIn) Empty()
    {
        Directory.CreateDirectory(_root);
        var store = new SqliteUserStore(new UserStoreOptions { Path = Path.Combine(_root, "users.db") });
        var hasher = new IdentityPasswordHasher();
        return (store, new LocalSignInService(store, hasher, new UserStoreAuthority(store, TimeSpan.Zero)));
    }

    [Fact]
    public async Task An_empty_store_gets_an_administrator_who_can_actually_sign_in()
    {
        (IUserStore store, LocalSignInService signIn) = Empty();

        string? password = await FirstAdmin.CreateAsync(store, signIn, FirstAdmin.DefaultUsername);
        Assert.NotNull(password);

        // Active and admin, not pending: an account awaiting approval is the state this exists to
        // avoid, because there would be nobody to approve it.
        KgsmUser? admin = await store.FindByUsernameAsync(FirstAdmin.DefaultUsername);
        Assert.NotNull(admin);
        Assert.Equal(KgsmTier.Admin, admin.EffectiveTier);
        Assert.Equal(UserStatus.Active, admin.Status);

        LocalSignInResult result = await signIn.SignInAsync(
            FirstAdmin.DefaultUsername, password, DateTimeOffset.UtcNow);

        Assert.Equal(LocalSignInOutcome.Success, result.Outcome);
    }

    [Fact]
    public async Task A_store_that_already_has_accounts_gains_nothing()
    {
        (IUserStore store, LocalSignInService signIn) = Empty();

        DateTimeOffset now = DateTimeOffset.UtcNow;
        await store.CreateAsync(new KgsmUser(
            UserIds.NewUserId(), "somebody", "somebody", KgsmTier.Viewer, TierSource.Granted,
            UserStatus.Active, now, now));

        // Every start but the first, and the case that matters most where an anchor shares a store
        // with a Control Panel: whichever opens it first creates the account and the other must not
        // add a second administrator nobody asked for.
        Assert.Null(await FirstAdmin.CreateAsync(store, signIn, FirstAdmin.DefaultUsername));
        Assert.Null(await store.FindByUsernameAsync(FirstAdmin.DefaultUsername));
    }

    [Fact]
    public void The_password_file_is_owner_readable_and_names_the_account()
    {
        Directory.CreateDirectory(_root);
        string path = Path.Combine(_root, "initial-admin-password");

        Assert.True(FirstAdmin.TryWritePasswordFile(path, "admin", "a-one-time-password", out Exception? error));
        Assert.Null(error);

        string written = File.ReadAllText(path);
        Assert.Contains("admin", written);
        Assert.Contains("a-one-time-password", written);

        // It is a credential sitting on disk. Anything wider than the owner and it is readable by
        // every process on the machine for as long as nobody notices.
        if (OperatingSystem.IsLinux())
        {
            UnixFileMode mode = File.GetUnixFileMode(path);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }
    }

    [Fact]
    public void The_file_is_removed_by_the_account_it_names_and_by_nobody_else()
    {
        Directory.CreateDirectory(_root);
        string path = Path.Combine(_root, "initial-admin-password");
        FirstAdmin.TryWritePasswordFile(path, "admin", "a-one-time-password", out _);

        // Somebody else's first sign-in must not tidy away a credential still nobody has used — a host
        // can grow other accounts from a shell before anyone signs in.
        Assert.False(FirstAdmin.TryConsumePasswordFile(path, "somebody-else", out _));
        Assert.True(File.Exists(path));

        Assert.True(FirstAdmin.TryConsumePasswordFile(path, "admin", out _));
        Assert.False(File.Exists(path));

        // Idempotent: a second sign-in by the same account finds nothing and reports nothing wrong.
        Assert.False(FirstAdmin.TryConsumePasswordFile(path, "admin", out Exception? error));
        Assert.Null(error);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }
}
