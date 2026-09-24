namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// One live login — a (user × device) pair that can be revoked independently.
/// </summary>
/// <param name="SessionId">The <c>sid</c> both the access and the refresh token carry.</param>
/// <param name="UserId">
/// Who this session belongs to: the <c>provider:subject</c> handle they signed in with. Opaque to the
/// registry, which only ever groups and matches on it.
/// </param>
/// <param name="HostId">The cluster the session is valid on, mirroring the token audience.</param>
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
/// session still alive" — so revoking a session at all needs a registry behind it.
/// </summary>
/// <remarks>
/// Implementations must be safe to call concurrently. Every method takes the value it needs rather
/// than reading a clock or a config, so behaviour is decided by the caller and is testable without
/// waiting for time to pass.
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
