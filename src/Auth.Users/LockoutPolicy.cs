namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// How long a run of failed passwords locks an account out for.
/// </summary>
/// <remarks>
/// <para>
/// A password endpoint needs this and an OAuth one did not: until local logins existed, guessing a
/// credential meant guessing it at Discord, against Discord's rate limits. The cost moves here along
/// with the credential.
/// </para>
/// <para>
/// The curve is exponential from a threshold rather than a fixed cap, because the two failure modes
/// pull opposite ways. A hard "five strikes and the account is locked" hands anyone who knows a
/// username a denial-of-service against its owner; no lockout at all leaves an offline-speed guess
/// running online. Doubling delays cost an attacker orders of magnitude within a handful of attempts
/// while a person who mistyped twice waits seconds.
/// </para>
/// <para>
/// This is a value, not a service: the store applies it inside the same transaction that records the
/// failure, so the count and the lock it implies can never disagree.
/// </para>
/// </remarks>
/// <param name="Threshold">Failures tolerated before any delay is imposed.</param>
/// <param name="BaseDelay">The lockout after the first failure past <paramref name="Threshold"/>.</param>
/// <param name="MaxDelay">The ceiling the doubling stops at.</param>
/// <param name="FailureWindow">
/// How long a failure counts for. A run that goes quiet for this long starts over, so yesterday's
/// typo does not add to today's.
/// </param>
public sealed record LockoutPolicy(
    int Threshold,
    TimeSpan BaseDelay,
    TimeSpan MaxDelay,
    TimeSpan FailureWindow)
{
    /// <summary>
    /// The default curve: three free attempts, then 5s, 10s, 20s… to a 15-minute ceiling, with a run
    /// forgotten after an hour of quiet.
    /// </summary>
    public static readonly LockoutPolicy Default = new(
        Threshold: 3,
        BaseDelay: TimeSpan.FromSeconds(5),
        MaxDelay: TimeSpan.FromMinutes(15),
        FailureWindow: TimeSpan.FromHours(1));

    /// <summary>
    /// How long the account is locked after <paramref name="failedCount"/> consecutive failures, or
    /// <see cref="TimeSpan.Zero"/> while still under the threshold.
    /// </summary>
    public TimeSpan DelayAfter(int failedCount)
    {
        int over = failedCount - Threshold;
        if (over <= 0)
            return TimeSpan.Zero;

        // Doubling in ticks, capped before the shift can overflow rather than after.
        double ticks = BaseDelay.Ticks * Math.Pow(2, Math.Min(over - 1, 32));
        return ticks >= MaxDelay.Ticks ? MaxDelay : TimeSpan.FromTicks((long)ticks);
    }
}

/// <summary>
/// An account's current standing with <see cref="LockoutPolicy"/>.
/// </summary>
/// <param name="FailedCount">Consecutive failures inside the policy's window.</param>
/// <param name="LockedUntil">When the account can be tried again, or <see langword="null"/> if now.</param>
public sealed record LoginLockout(int FailedCount, DateTimeOffset? LockedUntil)
{
    /// <summary>An account with nothing against it.</summary>
    public static readonly LoginLockout Clear = new(0, null);

    /// <summary>Whether a login attempt should be refused outright at <paramref name="now"/>.</summary>
    public bool IsLocked(DateTimeOffset now) => LockedUntil is { } until && until > now;
}
