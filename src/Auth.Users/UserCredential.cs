namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// What kind of proof a credential is. The column is typed from the first schema version so a second
/// kind costs a row and not a migration.
/// </summary>
public enum CredentialKind
{
    /// <summary>A password this host verifies itself. Its <see cref="UserCredential.Secret"/> is the hash.</summary>
    Password = 0,

    /// <summary>
    /// An external identity linked to the account — a Discord, GitHub or Google subject. Carries no
    /// secret: the provider did the verifying, and no KGSM surface retains a provider token.
    /// </summary>
    Identity = 1,
}

/// <summary>
/// One way a user can prove they are that user. A user has many; the account outlives all of them.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Handle"/> is globally unique across every credential in the store, and that single
/// constraint carries two separate rules. An external identity attaches to exactly one account —
/// linking one that is already linked elsewhere is refused by the database, not by a check someone
/// could forget — and a user has at most one password, because its handle is derived from the
/// account id.
/// </para>
/// <para>
/// A credential is never authority. It answers "this is that account"; what the account may do lives
/// on <see cref="KgsmUser.Tier"/> and nowhere else. An external provider therefore contributes
/// nothing beyond the identification, which is what lets a provider be added without an authority
/// story of its own.
/// </para>
/// </remarks>
/// <param name="CredentialId">The opaque <c>crd_&lt;32 hex&gt;</c> id.</param>
/// <param name="UserId">The account this proves. Deleting the account deletes this with it.</param>
/// <param name="Kind">Password or linked identity.</param>
/// <param name="Handle">
/// <c>provider:subject</c> — <see cref="KgsmIdentity.Handle"/> for a linked identity, and
/// <see cref="UserCredentials.LocalHandle"/> for a password. Unique across the store.
/// </param>
/// <param name="Secret">The password hash, or <see langword="null"/> for a linked identity.</param>
/// <param name="Label">
/// What a human sees in "connected accounts" — the provider-side username at link time. A snapshot,
/// never re-read and never matched on.
/// </param>
/// <param name="Created">When the credential was added.</param>
/// <param name="LastUsed">When it last authenticated someone, or <see langword="null"/> if never.</param>
public sealed record UserCredential(
    string CredentialId,
    string UserId,
    CredentialKind Kind,
    string Handle,
    string? Secret,
    string? Label,
    DateTimeOffset Created,
    DateTimeOffset? LastUsed);

/// <summary>Builds the credential handles the store keys on.</summary>
public static class UserCredentials
{
    /// <summary>
    /// The handle a user's password credential is filed under: <c>local:&lt;user id&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Derived from the opaque account id rather than the username, for the two reasons the account
    /// id exists at all: the row survives a rename, and the uniqueness constraint on the handle
    /// column becomes "one password per account" for free.
    /// </remarks>
    public static string LocalHandle(string userId) => KgsmActor.Format(KgsmActorProvider.Local, userId);

    /// <summary>The handle a linked external identity is filed under.</summary>
    public static string IdentityHandle(KgsmIdentity identity) => identity.Handle;
}

/// <summary>
/// A credential could not be added because its handle already belongs to another credential.
/// </summary>
/// <remarks>
/// Raised as its own type because the caller's answer differs by kind and neither is a server fault:
/// linking an identity that is already attached elsewhere is a real refusal a person has to see
/// ("that Discord account is already connected to another user"), and it must never silently
/// re-point an identity at a new account — that would hand one person another's authority.
/// </remarks>
public sealed class DuplicateCredentialException(string handle)
    : Exception($"The credential '{handle}' is already attached to a user.")
{
    /// <summary>The handle that was already taken.</summary>
    public string Handle { get; } = handle;
}

/// <summary>A username was already taken.</summary>
public sealed class DuplicateUsernameException(string username)
    : Exception($"The username '{username}' is already taken.")
{
    /// <summary>The username that was already taken.</summary>
    public string Username { get; } = username;
}
