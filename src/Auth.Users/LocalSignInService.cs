namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>How a username-and-password attempt ended.</summary>
public enum LocalSignInOutcome
{
    /// <summary>
    /// Wrong username, wrong password, or no password set on the account — one outcome on purpose.
    /// </summary>
    /// <remarks>
    /// Not three, because a caller that can tell them apart eventually tells a stranger apart too,
    /// and "no such user" is a username oracle. Collapsing them here means no surface can leak the
    /// difference by forgetting to; the attempt is still logged with the username that was tried, so
    /// nothing an operator needs is lost.
    /// </remarks>
    InvalidCredentials = 0,

    /// <summary>Too many recent failures. <see cref="LocalSignInResult.RetryAfter"/> says when.</summary>
    LockedOut = 1,

    /// <summary>
    /// The password was right and the account is switched off.
    /// </summary>
    /// <remarks>
    /// Reported only <em>after</em> the password verifies, which is the whole reason this outcome can
    /// exist at all. Refusing a disabled account up front would tell anyone who guesses a username
    /// that it names a real account — the same oracle
    /// <see cref="InvalidCredentials"/> exists to close, reopened for exactly the accounts most worth
    /// knowing about. Someone who already knows the password learns nothing new, and telling them
    /// plainly is what stops them retrying a password that will never work.
    /// </remarks>
    Disabled = 2,

    /// <summary>
    /// Authenticated. The tier may still be <see cref="KgsmTier.None"/> — an account awaiting
    /// approval signs in and holds nothing, which is what lets a surface say so instead of denying.
    /// </summary>
    Success = 3,
}

/// <summary>What a sign-in attempt produced.</summary>
/// <param name="Outcome">How it ended.</param>
/// <param name="Principal">The identity and tier, on <see cref="LocalSignInOutcome.Success"/>.</param>
/// <param name="User">The account, on success or on <see cref="LocalSignInOutcome.Disabled"/>.</param>
/// <param name="RetryAfter">When the account can be tried again, on <see cref="LocalSignInOutcome.LockedOut"/>.</param>
public sealed record LocalSignInResult(
    LocalSignInOutcome Outcome,
    ResolvedPrincipal? Principal,
    KgsmUser? User,
    DateTimeOffset? RetryAfter)
{
    internal static readonly LocalSignInResult Invalid =
        new(LocalSignInOutcome.InvalidCredentials, null, null, null);
}

/// <summary>
/// Signing in with a KGSM password — the path that needs no external provider reachable, or
/// configured at all.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not an <see cref="IIdentityProvider"/>. That seam models the authorization-code
/// flow — an authorize URL, a redirect, a code to exchange — and none of those exist here. A local
/// password is verified in one call against a hash on this host. Forcing it through a shape built
/// for a redirect would mean inventing a code and a state that nothing issues.
/// </para>
/// <para>
/// Authority still comes from <see cref="UserStoreAuthority"/> rather than being read off the record
/// here, so a local sign-in and a later session validation cannot answer the same question
/// differently.
/// </para>
/// </remarks>
public sealed class LocalSignInService(
    IUserStore store,
    IUserPasswordHasher hasher,
    UserStoreAuthority authority,
    LockoutPolicy? lockout = null)
{
    /// <summary>
    /// A hash to verify against when the username matches nobody, so an unknown username costs the
    /// same time as a wrong password.
    /// </summary>
    /// <remarks>
    /// Without it the enumeration the outcome enum closes off reopens as a stopwatch: a real account
    /// runs a deliberately slow key derivation, and a missing one returns immediately. Computed once
    /// at construction over a value no password can be.
    /// </remarks>
    private readonly string _decoyHash = hasher.Hash(Guid.NewGuid().ToString("N"));

    private readonly LockoutPolicy _lockout = lockout ?? LockoutPolicy.Default;

    /// <summary>
    /// Verify <paramref name="password"/> against the account named by <paramref name="username"/>.
    /// </summary>
    /// <remarks>
    /// A correct password clears the failure count and stamps the credential; a wrong one adds to it
    /// and may lock the account. A correct password stored under an older hash format is re-hashed
    /// here — the one moment the plaintext is in hand to do it — so accounts migrate as their owners
    /// sign in rather than by a forced reset.
    /// </remarks>
    /// <param name="now">The clock, passed in so lockout behaviour is testable without waiting.</param>
    public async Task<LocalSignInResult> SignInAsync(
        string? username, string? password, DateTimeOffset now, CancellationToken ct = default)
    {
        // A missing field off the wire is a wrong password, not an argument error: it comes from
        // whoever is trying to sign in, and every wrong answer takes the same path and the same time.
        password ??= string.Empty;

        KgsmUser? user = string.IsNullOrWhiteSpace(username)
            ? null
            : await store.FindByUsernameAsync(username, ct).ConfigureAwait(false);

        if (user is null)
        {
            // Spend the same work an account would have cost, then give the same answer.
            hasher.Verify(_decoyHash, password);
            return LocalSignInResult.Invalid;
        }

        LoginLockout standing = await store
            .GetLockoutAsync(user.UserId, _lockout, now, ct).ConfigureAwait(false);

        if (standing.IsLocked(now))
            return new LocalSignInResult(LocalSignInOutcome.LockedOut, null, user, standing.LockedUntil);

        UserCredential? credential = await store
            .FindCredentialAsync(UserCredentials.LocalHandle(user.UserId), ct).ConfigureAwait(false);

        if (credential?.Secret is not { } hash)
        {
            // An account with no password — external identities only. Still costs the same work.
            hasher.Verify(_decoyHash, password);
            return LocalSignInResult.Invalid;
        }

        PasswordVerification verified = hasher.Verify(hash, password);
        if (verified == PasswordVerification.Failed)
        {
            LoginLockout after = await store
                .RecordFailureAsync(user.UserId, _lockout, now, ct).ConfigureAwait(false);

            return after.IsLocked(now)
                ? new LocalSignInResult(LocalSignInOutcome.LockedOut, null, user, after.LockedUntil)
                : LocalSignInResult.Invalid;
        }

        // The password is right, so saying the account is off tells its holder something only its
        // holder could have got this far to hear.
        if (user.Status == UserStatus.Disabled)
            return new LocalSignInResult(LocalSignInOutcome.Disabled, null, user, null);

        if (verified == PasswordVerification.SuccessRehashNeeded)
        {
            await store.SetCredentialSecretAsync(credential.CredentialId, hasher.Hash(password), ct)
                .ConfigureAwait(false);
        }

        await store.ClearLockoutAsync(user.UserId, ct).ConfigureAwait(false);
        await store.TouchCredentialAsync(credential.CredentialId, now, ct).ConfigureAwait(false);

        KgsmIdentity identity = user.AsIdentity();
        KgsmTier tier = await authority.ResolveTierAsync(identity, ct).ConfigureAwait(false);

        return new LocalSignInResult(
            LocalSignInOutcome.Success, new ResolvedPrincipal(identity, tier), user, null);
    }

    /// <summary>
    /// Set or replace an account's password, adding the credential if it has none.
    /// </summary>
    /// <remarks>
    /// Clears the failure count too: an admin resetting a password for someone locked out of their
    /// own account has plainly resolved the situation the lockout existed for, and leaving it in
    /// place would make the reset appear not to have worked.
    /// </remarks>
    public async Task SetPasswordAsync(
        string userId, string password, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        string handle = UserCredentials.LocalHandle(userId);
        UserCredential? existing = await store.FindCredentialAsync(handle, ct).ConfigureAwait(false);
        string hash = hasher.Hash(password);

        if (existing is null)
        {
            await store.AddCredentialAsync(
                new UserCredential(
                    UserIds.NewCredentialId(), userId, CredentialKind.Password, handle, hash,
                    Label: null, Created: now, LastUsed: null),
                ct).ConfigureAwait(false);
        }
        else
        {
            await store.SetCredentialSecretAsync(existing.CredentialId, hash, ct).ConfigureAwait(false);
        }

        await store.ClearLockoutAsync(userId, ct).ConfigureAwait(false);
    }
}
