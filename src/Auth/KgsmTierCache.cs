using System.Collections.Concurrent;

namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// Short-TTL per-user cache of the tier a caller holds, for surfaces that re-derive authority on
/// every request rather than baking it into a token. Resolving a tier costs a round-trip to whatever
/// answers for authority, and without this a chatty caller would spend that budget asking the same
/// question about the same person.
/// </summary>
/// <remarks>
/// <para>
/// Keyed by the caller's identity handle (<see cref="KgsmIdentity.Handle"/>) rather than a bare
/// subject: a subject is unique only within its provider, so two providers handing out the same
/// string would otherwise share one cache entry and one person's authority would answer for another.
/// </para>
/// <para>
/// One entry per user, because authority is one ordered tier: a single resolution answers every
/// question a surface asks of them.
/// </para>
/// <para>
/// <b>A denial is cached like any other answer.</b> Not caching <see cref="KgsmTier.None"/> would
/// mean the one caller most likely to retry — someone with no access, or a bot hammering an
/// endpoint — is also the one who reaches the authority on every single request.
/// </para>
/// <para>
/// The TTL is the staleness bound on a revoked role: authority deliberately is not stored on a
/// session, so this is the only place a stale answer survives. A brief per-user stampede on expiry is
/// accepted rather than locked against.
/// </para>
/// <para>
/// <b>Only established answers belong here.</b> A failure to reach the authority must never be
/// written as a tier — that would turn a brief outage into a full-TTL lockout for someone who really
/// does hold the role. The caller reports the outage instead and caches nothing.
/// </para>
/// </remarks>
public sealed class KgsmTierCache(TimeSpan ttl)
{
    private sealed record Entry(KgsmTier Tier, DateTimeOffset FetchedUtc);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeSpan _ttl = ttl > TimeSpan.Zero ? ttl : TimeSpan.FromSeconds(60);

    /// <summary>This user's cached tier, if it is still within the TTL.</summary>
    public bool TryGet(string handle, out KgsmTier tier)
    {
        tier = KgsmTier.None;
        if (!_entries.TryGetValue(handle, out Entry? entry))
            return false;

        if (DateTimeOffset.UtcNow - entry.FetchedUtc > _ttl)
        {
            _entries.TryRemove(handle, out _);
            return false;
        }

        tier = entry.Tier;
        return true;
    }

    public void Set(string handle, KgsmTier tier) =>
        _entries[handle] = new Entry(tier, DateTimeOffset.UtcNow);

    /// <summary>Drops a user's cached tier — on logout, or when a session is revoked.</summary>
    public void Remove(string handle) => _entries.TryRemove(handle, out _);
}
