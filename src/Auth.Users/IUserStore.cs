namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// Where KGSM accounts and their credentials live.
/// </summary>
/// <remarks>
/// <para>
/// A seam for the same reason <c>ISessionRegistry</c> is one: a test stands the whole login and
/// authorization matrix up in memory, and a host that wants its accounts somewhere other than a
/// local file supplies its own. <see cref="SqliteUserStore"/> is the shipped implementation and the
/// one both surfaces use.
/// </para>
/// <para>
/// Implementations must be safe to call concurrently, and must be safe to call concurrently
/// <em>from more than one process</em> — the Control Panel API and the assistant read and write the
/// same accounts, each on its own schedule, with neither aware of the other.
/// </para>
/// <para>
/// Every method takes the values it needs rather than reading a clock: what happens is decided by
/// the caller and is testable without waiting for time to pass.
/// </para>
/// </remarks>
public interface IUserStore
{
    /// <summary>The account with this id, or <see langword="null"/>.</summary>
    Task<KgsmUser?> FindByIdAsync(string userId, CancellationToken ct = default);

    /// <summary>
    /// The account with this username, matched case-insensitively through
    /// <see cref="Usernames.Key"/>, or <see langword="null"/>.
    /// </summary>
    Task<KgsmUser?> FindByUsernameAsync(string username, CancellationToken ct = default);

    /// <summary>
    /// The account a credential handle proves, or <see langword="null"/> when no credential carries
    /// it. This is the whole of "does this external identity belong to anyone here": a subject that
    /// matches no row is a stranger, whatever group or guild they are in.
    /// </summary>
    Task<KgsmUser?> FindByCredentialAsync(string handle, CancellationToken ct = default);

    /// <summary>Every account, oldest first. The admin screen's list; there is no paging.</summary>
    Task<IReadOnlyList<KgsmUser>> ListAsync(CancellationToken ct = default);

    /// <summary>
    /// Add an account. Throws <see cref="DuplicateUsernameException"/> when the username is taken.
    /// </summary>
    Task CreateAsync(KgsmUser user, CancellationToken ct = default);

    /// <summary>
    /// Overwrite an account's mutable fields — username, display name, tier, provenance and status.
    /// Returns <see langword="false"/> when no such account exists; throws
    /// <see cref="DuplicateUsernameException"/> when the new username is taken by another.
    /// </summary>
    Task<bool> UpdateAsync(KgsmUser user, CancellationToken ct = default);

    /// <summary>
    /// Erase an account and everything attached to it. Returns <see langword="false"/> when there
    /// was nothing to erase.
    /// </summary>
    /// <remarks>
    /// Disabling is what an admin normally wants and is what keeps the audit trail legible — this
    /// exists for a pending row that should never have been created, where there is nothing worth
    /// keeping.
    /// </remarks>
    Task<bool> DeleteAsync(string userId, CancellationToken ct = default);

    /// <summary>Everything that can prove this account, oldest first.</summary>
    Task<IReadOnlyList<UserCredential>> ListCredentialsAsync(string userId, CancellationToken ct = default);

    /// <summary>The credential filed under this handle, or <see langword="null"/>.</summary>
    Task<UserCredential?> FindCredentialAsync(string handle, CancellationToken ct = default);

    /// <summary>
    /// Attach a credential. Throws <see cref="DuplicateCredentialException"/> when the handle
    /// already belongs to a credential — which is how an external identity linked to one account is
    /// stopped from being re-pointed at another.
    /// </summary>
    Task AddCredentialAsync(UserCredential credential, CancellationToken ct = default);

    /// <summary>
    /// Replace a credential's stored secret — a password change, or a rehash after
    /// <see cref="PasswordVerification.SuccessRehashNeeded"/>. Returns <see langword="false"/> when
    /// no such credential exists.
    /// </summary>
    Task<bool> SetCredentialSecretAsync(string credentialId, string secret, CancellationToken ct = default);

    /// <summary>Record that a credential just authenticated someone.</summary>
    Task TouchCredentialAsync(string credentialId, DateTimeOffset when, CancellationToken ct = default);

    /// <summary>
    /// Detach a credential. Returns <see langword="false"/> when there was nothing to detach.
    /// </summary>
    /// <remarks>
    /// The store does not refuse the last credential on an account. Whether an account may be left
    /// with no way in is the caller's rule to enforce and its message to write — the store's job is
    /// to say what happened.
    /// </remarks>
    Task<bool> RemoveCredentialAsync(string credentialId, CancellationToken ct = default);

    /// <summary>This account's standing after any failures older than the policy's window expire.</summary>
    Task<LoginLockout> GetLockoutAsync(string userId, LockoutPolicy policy, DateTimeOffset now, CancellationToken ct = default);

    /// <summary>
    /// Record a failed password and return the standing it produces. The count and the lockout it
    /// implies are written together, so a concurrent attempt can never read one without the other.
    /// </summary>
    Task<LoginLockout> RecordFailureAsync(string userId, LockoutPolicy policy, DateTimeOffset now, CancellationToken ct = default);

    /// <summary>Forget an account's failures, on a successful sign-in or an admin's reset.</summary>
    Task ClearLockoutAsync(string userId, CancellationToken ct = default);
}
