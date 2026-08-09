using System.Security.Cryptography;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// Whether an account may be used, and if not, why not.
/// </summary>
/// <remarks>
/// The three states answer three different questions and a caller must not collapse them.
/// <see cref="Pending"/> authenticates and holds no authority — the honest answer for someone who
/// has proved who they are and has not been let in yet, and what lets a surface render "awaiting
/// approval" instead of a bare denial. <see cref="Disabled"/> does not authenticate at all: it is
/// the revocation switch, and it cuts live sessions on every surface through the enabled check.
/// </remarks>
public enum UserStatus
{
    /// <summary>Verified, not yet approved. Signs in; resolves to <see cref="KgsmTier.None"/>.</summary>
    Pending = 0,

    /// <summary>Approved. Signs in and holds the tier on the record.</summary>
    Active = 1,

    /// <summary>Switched off. Cannot sign in, and every live session dies at its next validation.</summary>
    Disabled = 2,
}

/// <summary>
/// Where a user's tier came from, so an access review can answer <em>why</em> someone holds
/// operator.
/// </summary>
/// <remarks>
/// The internal record is the sole authority, which means nothing reconciles it against an external
/// group afterwards. That is a deliberate choice and this column is its compensating control: a tier
/// nobody ever deliberately granted is exactly the deprovisioning drift an access review looks for,
/// and without provenance it is indistinguishable from one an admin chose.
/// </remarks>
public enum TierSource
{
    /// <summary>Seeded from an external mapping. Never re-checked; reported by the drift report.</summary>
    Derived = 0,

    /// <summary>Chosen by an admin on this host.</summary>
    Granted = 1,
}

/// <summary>
/// A KGSM account. The primary object of the identity model: it exists on its own, carries the
/// tier, and is what every credential attaches to.
/// </summary>
/// <remarks>
/// <para>
/// Identified by an opaque <see cref="UserId"/> rather than by a username or an email. Both of those
/// are renameable — keying on one detaches a person from their own sessions, links and audit trail
/// the day they change it — and both are enumerable, which an opaque id is not.
/// </para>
/// <para>
/// One tier per user, never a permission set. The ordered <c>viewer ⊆ operator ⊆ admin</c> ladder is
/// the ecosystem's whole authorization model; a permission the ladder cannot express is how the
/// surfaces diverged before they shared one.
/// </para>
/// </remarks>
/// <param name="UserId">The opaque <c>usr_&lt;32 hex&gt;</c> id. Stable for the account's life.</param>
/// <param name="Username">The login name. Renameable; never used as a key.</param>
/// <param name="DisplayName">What a human is shown. For rendering only, never authority.</param>
/// <param name="Tier">What this account may do here.</param>
/// <param name="TierSource">Why it holds that tier.</param>
/// <param name="Status">Whether it may be used at all.</param>
/// <param name="Created">When the account was made.</param>
/// <param name="Updated">When any field above last changed.</param>
public sealed record KgsmUser(
    string UserId,
    string Username,
    string DisplayName,
    KgsmTier Tier,
    TierSource TierSource,
    UserStatus Status,
    DateTimeOffset Created,
    DateTimeOffset Updated)
{
    /// <summary>
    /// This account as an identity, for the seams that speak <see cref="KgsmIdentity"/>.
    /// </summary>
    /// <remarks>
    /// The subject is the opaque <see cref="UserId"/>, not the username, so the handle a session is
    /// keyed by survives a rename. The actor string still reads <c>local:haru</c>, because an audit
    /// log is read by people.
    /// </remarks>
    public KgsmIdentity AsIdentity() => new(
        KgsmActorProvider.Local, UserId, Username, DisplayName, AvatarUrl: null, Scopes: []);

    /// <summary>
    /// The tier this account actually resolves to right now: the recorded tier while
    /// <see cref="UserStatus.Active"/>, and <see cref="KgsmTier.None"/> otherwise.
    /// </summary>
    /// <remarks>
    /// Kept here rather than at each call site so no caller can read <see cref="Tier"/> off a
    /// pending or disabled record and grant on it.
    /// </remarks>
    public KgsmTier EffectiveTier => Status == UserStatus.Active ? Tier : KgsmTier.None;
}

/// <summary>
/// The opaque ids this store hands out — <c>usr_</c> for an account, <c>crd_</c> for a credential,
/// matching the <c>sid_</c> convention sessions already use.
/// </summary>
/// <remarks>
/// 128 bits from the cryptographic RNG, not a GUID: an id that appears in URLs and audit rows should
/// be unguessable, and a v4 GUID's rendering advertises what it is while carrying the same entropy
/// in more characters.
/// </remarks>
public static class UserIds
{
    /// <summary>The <c>usr_</c> prefix a user id carries.</summary>
    public const string UserPrefix = "usr_";

    /// <summary>The <c>crd_</c> prefix a credential id carries.</summary>
    public const string CredentialPrefix = "crd_";

    /// <summary>A fresh user id.</summary>
    public static string NewUserId() => UserPrefix + RandomHex();

    /// <summary>A fresh credential id.</summary>
    public static string NewCredentialId() => CredentialPrefix + RandomHex();

    private static string RandomHex() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}
