using Microsoft.AspNetCore.Identity;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>What checking a password against a stored hash concluded.</summary>
public enum PasswordVerification
{
    /// <summary>Not this password.</summary>
    Failed = 0,

    /// <summary>Correct, and the stored hash is current.</summary>
    Success = 1,

    /// <summary>
    /// Correct, but the stored hash was produced by an older format or a lower work factor. The
    /// caller re-hashes and stores the result — the one moment the plaintext is in hand to do it.
    /// </summary>
    SuccessRehashNeeded = 2,
}

/// <summary>
/// Turns a password into something storable, and checks one against it.
/// </summary>
/// <remarks>
/// An interface for one reason: the hash format is expected to be replaced. Argon2id is the stronger
/// current recommendation and PBKDF2 is what ships here; moving between them means a second
/// implementation and the <see cref="PasswordVerification.SuccessRehashNeeded"/> path already in
/// place to migrate accounts as their owners sign in, with no flag day and no forced reset.
/// </remarks>
public interface IUserPasswordHasher
{
    /// <summary>The storable form of <paramref name="password"/>. Never reversible.</summary>
    string Hash(string password);

    /// <summary>Whether <paramref name="password"/> produced <paramref name="hash"/>.</summary>
    PasswordVerification Verify(string hash, string password);
}

/// <summary>
/// The shipped hasher: ASP.NET Core Identity's <see cref="PasswordHasher{TUser}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not hand-rolled. This is reviewed, versioned code that already handles the parts a
/// hand-rolled PBKDF2 gets wrong — a per-password salt, a constant-time comparison, a format byte so
/// the parameters can change later, and the rehash signal that makes changing them possible.
/// </para>
/// <para>
/// Only the hasher is taken, not the <c>UserManager</c>/EF Identity stack above it. That stack
/// brings its own schema, its own store abstraction and its own notion of what a user is, all three
/// of which this package already owns.
/// </para>
/// <para>
/// The generic parameter goes unused by every code path in the hasher — it exists for callers who
/// key work off the user object — so <see cref="object"/> stands in and a single instance serves
/// every account.
/// </para>
/// </remarks>
public sealed class IdentityPasswordHasher : IUserPasswordHasher
{
    private static readonly object Anyone = new();
    private readonly PasswordHasher<object> _hasher = new();

    /// <inheritdoc />
    public string Hash(string password) => _hasher.HashPassword(Anyone, password);

    /// <inheritdoc />
    public PasswordVerification Verify(string hash, string password) =>
        _hasher.VerifyHashedPassword(Anyone, hash, password) switch
        {
            PasswordVerificationResult.SuccessRehashNeeded => PasswordVerification.SuccessRehashNeeded,
            PasswordVerificationResult.Success => PasswordVerification.Success,
            _ => PasswordVerification.Failed,
        };
}
