namespace TheKrystalShip.KGSM.Auth.Sessions;

/// <summary>
/// One live login — a (user × device) pair that can be revoked independently.
/// </summary>
/// <remarks>
/// Named a registration rather than a record: a surface's wire DTO for "a session, as shown to its
/// owner" is a different and equally obvious use of that word, and a shared package should not claim
/// the more generic name.
/// </remarks>
/// <param name="SessionId">The <c>sid</c> both the access and the refresh token carry.</param>
/// <param name="UserId">The Discord user id this session belongs to.</param>
/// <param name="HostId">The host the session is scoped to, mirroring the token audience.</param>
/// <param name="Created">When the login happened.</param>
/// <param name="Expires">The absolute cap: past this the session is dead however it is stored.</param>
/// <param name="UserAgent">The device, for a human reading their own session list. Never authority.</param>
/// <param name="CurrentJti">
/// The <c>jti</c> of the refresh token currently valid for this session. A refresh presenting any
/// other value is a replay of a rotated-away token and is refused.
/// </param>
public sealed record SessionRegistration(
    string SessionId,
    string UserId,
    string HostId,
    DateTimeOffset Created,
    DateTimeOffset Expires,
    string? UserAgent,
    string? CurrentJti);

/// <summary>
/// Where sessions live. This is the one fact a stateless JWT cannot answer on its own — "is this
/// session still alive" — so a surface that wants revocation at all needs a registry behind it.
/// </summary>
/// <remarks>
/// <para>
/// The interface is the seam on purpose: what a session IS, how it rotates and when it dies are the
/// ecosystem's, while where the rows go is each surface's own. kgsm-api keeps an EF/SQLite table
/// alongside its audit log; another surface may reasonably use raw SQLite or nothing but memory.
/// Two implementations behind one contract is the contract working, not duplication.
/// </para>
/// <para>
/// Implementations must be safe to call concurrently. Every method takes the value it needs rather
/// than reading a clock or a config, so behaviour is decided by the caller and is testable without
/// waiting for time to pass.
/// </para>
/// </remarks>
public interface ISessionRegistry
{
    /// <summary>Record a new login.</summary>
    Task CreateAsync(SessionRegistration session, CancellationToken ct = default);

    /// <summary>
    /// Is this session alive — the row exists, is not revoked, and has not passed its cap? The
    /// answer every request depends on, so it is expected to be cheap and is cached above this.
    /// </summary>
    Task<bool> IsAliveAsync(string sessionId, CancellationToken ct = default);

    /// <summary>
    /// Rotate a session's refresh token. <paramref name="presentedJti"/> must equal what the session
    /// currently holds; anything else is a replay of a token that has already been rotated away, and
    /// the implementation returns <see langword="false"/> rather than rotating.
    /// <para>
    /// Returning false is the reuse detection. It means either a stale client or a stolen token, and
    /// the caller cannot tell which — so it refuses the refresh and lets the legitimate holder
    /// re-authenticate rather than guessing.
    /// </para>
    /// </summary>
    Task<bool> RotateAsync(
        string sessionId, string presentedJti, string newJti, DateTimeOffset newExpires,
        CancellationToken ct = default);

    /// <summary>
    /// Kill a session. Returns <see langword="false"/> when there was nothing live to kill, so a
    /// double logout is not reported as two revocations.
    /// </summary>
    Task<bool> RevokeAsync(string sessionId, CancellationToken ct = default);

    /// <summary>
    /// Delete every session past <paramref name="now"/>, revoked or not — expired is dead either
    /// way. Returns how many went, so a caller can log a number rather than a guess.
    /// </summary>
    Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken ct = default);
}
