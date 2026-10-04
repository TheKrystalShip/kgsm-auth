using Microsoft.Extensions.Caching.Memory;

namespace TheKrystalShip.Auth.Cluster;

/// <summary>
/// The sessions somebody has ended, as a member records them.
/// </summary>
/// <remarks>
/// A session the anchor minted is verified against a published key and needs nothing stored anywhere
/// to be accepted, so it is held to a <b>deny-list</b>: the only thing worth storing is that somebody
/// ended it. A member implements this over whatever file it already keeps.
/// </remarks>
public interface IClusterSessionDenyList
{
    /// <summary>Whether anybody has said this session is over.</summary>
    Task<bool> IsRevokedAsync(string sessionId, CancellationToken ct = default);

    /// <summary>
    /// Record that a session is over. A no-op when it is already recorded.
    /// </summary>
    /// <param name="until">
    /// When the record may be swept, not when the session dies — the session is already dead. It
    /// bounds the marker by the longest a bearer for it could still be presented.
    /// </param>
    Task RecordRevocationAsync(string sessionId, DateTimeOffset until, CancellationToken ct = default);
}

/// <summary>
/// Whether a session minted by the cluster's auth anchor has been ended, cached on the request path.
/// </summary>
/// <remarks>
/// <para>
/// <b>The cache TTL is the lag, and an end evicts.</b> A revoke arriving over the bus drops the entry
/// so the kill is immediate, and the TTL is the backstop for a read that raced it. Absolute rather
/// than sliding, so the busiest session — the one most worth being able to end — is not the one that
/// never re-checks.
/// </para>
/// <para>
/// <b>Both answers are cached.</b> Not caching "this is over" would send exactly the session most
/// worth refusing to the database on every request it makes, which is what a stolen bearer does.
/// </para>
/// </remarks>
public sealed class ClusterSessionRevocations(
    IClusterSessionDenyList denyList,
    IMemoryCache cache,
    TimeSpan cacheTtl)
{
    // Namespaced so a session id cannot collide with whatever else the member keeps in a shared cache.
    private static string Key(string sessionId) => "kgsm.cluster-session.revoked." + sessionId;

    private readonly TimeSpan _cacheTtl = cacheTtl > TimeSpan.Zero ? cacheTtl : TimeSpan.FromSeconds(5);

    /// <summary>Whether this session has been ended.</summary>
    public async Task<bool> IsRevokedAsync(string sessionId, CancellationToken ct = default)
    {
        if (cache.TryGetValue(Key(sessionId), out bool cached))
            return cached;

        bool revoked = await denyList.IsRevokedAsync(sessionId, ct).ConfigureAwait(false);

        cache.Set(Key(sessionId), revoked, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = _cacheTtl,
        });
        return revoked;
    }

    /// <summary>Drop a cached answer, so an end that has just arrived takes effect now.</summary>
    public void Evict(string sessionId) => cache.Remove(Key(sessionId));
}
