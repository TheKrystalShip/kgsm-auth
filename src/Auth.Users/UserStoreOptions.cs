namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// Where the account store lives and how it behaves under contention.
/// </summary>
public sealed class UserStoreOptions
{
    /// <summary>
    /// The path every KGSM surface on a host reads accounts from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A shared host <em>resource</em>, in the same category as <c>/var/lib/kgsm/leaves/</c> and the
    /// provider credentials in <c>/etc/kgsm/</c> — not a service. That distinction is the whole
    /// reason accounts live in a file rather than behind an identity daemon: a file is not something
    /// the assistant can be down for, so the assistant still authenticates people with the Control
    /// Panel API absent, and no leaf ends up depending on a sibling.
    /// </para>
    /// <para>
    /// <b>In a directory of its own, which the service user owns.</b> Not directly under
    /// <c>/var/lib/kgsm/</c>, which is root-owned: SQLite writes <c>-wal</c> and <c>-shm</c>
    /// <em>beside</em> the database, so write permission on the file is not enough — WAL needs the
    /// directory. <c>events/</c> and <c>leaves/</c> already sit under it the same way.
    /// </para>
    /// </remarks>
    public const string DefaultPath = "/var/lib/kgsm/auth/users.db";

    /// <summary>The SQLite file. Created, with its directory, if absent.</summary>
    public string Path { get; set; } = DefaultPath;

    /// <summary>
    /// How long a write waits for another process's write before giving up.
    /// </summary>
    /// <remarks>
    /// Two independently deployed services write this file on their own schedules. WAL lets them
    /// read through each other's writes, but two writers still serialise, and an unconfigured SQLite
    /// fails such a collision instantly rather than waiting the few milliseconds it would take to
    /// clear. Both halves are needed; neither is enough alone.
    /// </remarks>
    public TimeSpan BusyTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>The lockout curve applied to failed passwords.</summary>
    public LockoutPolicy Lockout { get; set; } = LockoutPolicy.Default;
}
