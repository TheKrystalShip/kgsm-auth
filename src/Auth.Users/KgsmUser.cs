using System.Security.Cryptography;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// Whether an account may be used, and if not, why not.
/// </summary>
/// <remarks>
/// The three states answer three different questions and a caller must not collapse them.
/// <see cref="Pending"/> authenticates and holds nothing — the honest answer for someone who has
/// proved who they are and has not been let in yet, and what lets a surface render "awaiting approval"
/// instead of a bare denial. <see cref="Disabled"/> does not authenticate at all: it is the revocation
/// switch, and it cuts live sessions on every surface through the enabled check.
/// </remarks>
public enum UserStatus
{
    /// <summary>Verified, not yet approved. Signs in; holds nothing, not even <c>everyone</c>.</summary>
    Pending = 0,

    /// <summary>Approved. Signs in and holds what its roles and <c>everyone</c> grant.</summary>
    Active = 1,

    /// <summary>Switched off. Cannot sign in, and every live session dies at its next validation.</summary>
    Disabled = 2,
}

/// <summary>
/// A KGSM account. The primary object of the identity model: it exists on its own, and is what every
/// credential attaches to.
/// </summary>
/// <remarks>
/// <para>
/// Identified by an opaque <see cref="UserId"/> rather than by a username or an email. Both of those
/// are renameable — keying on one detaches a person from their own sessions, links and audit trail
/// the day they change it — and both are enumerable, which an opaque id is not.
/// </para>
/// <para>
/// What an account may do is not on it: it is the roles assigned to it, evaluated by
/// <c>TheKrystalShip.KGSM.Auth.Access</c> from the authority the same store holds.
/// </para>
/// </remarks>
/// <param name="UserId">The opaque <c>usr_&lt;32 hex&gt;</c> id. Stable for the account's life.</param>
/// <param name="Username">The login name. Renameable; never used as a key.</param>
/// <param name="DisplayName">What a human is shown. For rendering only, never authority.</param>
/// <param name="Origin">Whether it arrived on its own or somebody admitted it — what pending expiry reads.</param>
/// <param name="Status">Whether it may be used at all.</param>
/// <param name="Created">When the account was made.</param>
/// <param name="Updated">When any field above last changed.</param>
public sealed record KgsmUser(
    string UserId,
    string Username,
    string DisplayName,
    AccountOrigin Origin,
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
