using System.Collections.Concurrent;

namespace TheKrystalShip.KGSM.Auth.Discord;

/// <summary>
/// Short-TTL per-user cache of the tier a caller holds, for surfaces that re-derive authority on
/// every request rather than baking it into a token. Discord's member endpoint is rate-limited, and
/// without this a chatty caller would spend its budget asking the same question about the same
/// person.
/// </summary>
/// <remarks>
/// <para>
/// One entry per user, because authority is one ordered tier: a single lookup of a member's roles
/// answers every question a surface asks of them.
/// </para>
/// <para>
/// <b>A denial is cached like any other answer.</b> Not caching <see cref="KgsmTier.None"/> would
/// mean the one caller most likely to retry — someone with no access, or a bot hammering an
/// endpoint — is also the one who reaches Discord on every single request.
/// </para>
/// <para>
/// The TTL is the staleness bound on a revoked role: authority deliberately is not stored on a
/// session, so this is the only place a stale answer survives. A brief per-user stampede on expiry is
/// accepted rather than locked against.
/// </para>
/// </remarks>
public sealed class DiscordTierCache(TimeSpan ttl)
{
    private sealed record Entry(KgsmTier Tier, DateTimeOffset FetchedUtc);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeSpan _ttl = ttl > TimeSpan.Zero ? ttl : TimeSpan.FromSeconds(60);

    /// <summary>This user's cached tier, if it is still within the TTL.</summary>
    public bool TryGet(string userId, out KgsmTier tier)
    {
        tier = KgsmTier.None;
        if (!_entries.TryGetValue(userId, out Entry? entry))
            return false;

        if (DateTimeOffset.UtcNow - entry.FetchedUtc > _ttl)
        {
            _entries.TryRemove(userId, out _);
            return false;
        }

        tier = entry.Tier;
        return true;
    }

    public void Set(string userId, KgsmTier tier) =>
        _entries[userId] = new Entry(tier, DateTimeOffset.UtcNow);

    /// <summary>Drops a user's cached tier — on logout, or when a session is revoked.</summary>
    public void Remove(string userId) => _entries.TryRemove(userId, out _);
}
