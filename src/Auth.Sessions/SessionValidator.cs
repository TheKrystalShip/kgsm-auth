using Microsoft.Extensions.Caching.Memory;

namespace TheKrystalShip.KGSM.Auth.Sessions;

/// <summary>
/// Answers "is this session still alive" on the request path, cached, so the registry is not queried
/// once per request.
/// </summary>
public interface ISessionValidator
{
    /// <summary>Whether <paramref name="sessionId"/> is still live. Cached.</summary>
    Task<bool> IsValidAsync(string sessionId, CancellationToken ct = default);

    /// <summary>
    /// Drop a cached answer so the next check re-reads the registry. Called by a revoke, so the kill
    /// takes effect at once rather than waiting out the cache.
    /// </summary>
    void Evict(string sessionId);
}

/// <summary>
/// The cached validator over an <see cref="ISessionRegistry"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The cache TTL is the revocation lag, and it is an accepted bound rather than an oversight.</b>
/// A revoke evicts the entry, so in practice the kill is immediate; the TTL is the backstop for the
/// paths that cannot evict — another process, or a revoke that raced a read.
/// </para>
/// <para>
/// <b>Expiration is absolute, never sliding.</b> A sliding window is extended by every hit, so the
/// busiest session — the one most worth being able to revoke — would be the one that never
/// re-checks.
/// </para>
/// <para>
/// <b>A "no" is cached too.</b> Otherwise a revoked session still presenting its token, which is
/// exactly what a stolen one does, queries the registry on every request it makes.
/// </para>
/// </remarks>
public sealed class SessionValidator(
    ISessionRegistry registry,
    IMemoryCache cache,
    TimeSpan cacheTtl) : ISessionValidator
{
    // Namespaced so a session id cannot collide with whatever else the host keeps in a shared cache.
    private static string Key(string sessionId) => "kgsm.session." + sessionId;

    private readonly TimeSpan _cacheTtl = cacheTtl > TimeSpan.Zero ? cacheTtl : TimeSpan.FromSeconds(5);

    public async Task<bool> IsValidAsync(string sessionId, CancellationToken ct = default)
    {
        if (cache.TryGetValue(Key(sessionId), out bool cached))
            return cached;

        bool alive = await registry.IsAliveAsync(sessionId, ct).ConfigureAwait(false);

        cache.Set(Key(sessionId), alive, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = _cacheTtl,
        });
        return alive;
    }

    public void Evict(string sessionId) => cache.Remove(Key(sessionId));
}
