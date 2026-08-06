using Microsoft.Extensions.Caching.Memory;

using TheKrystalShip.KGSM.Auth.Sessions;

namespace TheKrystalShip.KGSM.Auth.Sessions.Tests;

/// <summary>
/// The cache in front of the registry is the revocation-lag bound, so its behaviour is the security
/// property — not a performance detail.
/// </summary>
public class SessionValidatorTests
{
    private sealed class CountingRegistry(bool alive) : ISessionRegistry
    {
        public int Queries { get; private set; }
        public bool Alive { get; set; } = alive;

        public Task<bool> IsAliveAsync(string sessionId, CancellationToken ct = default)
        {
            Queries++;
            return Task.FromResult(Alive);
        }

        public Task CreateAsync(SessionRegistration session, CancellationToken ct = default) => Task.CompletedTask;
        public Task<bool> RotateAsync(string a, string b, string c, DateTimeOffset d, CancellationToken ct = default) => Task.FromResult(true);
        public Task<bool> RevokeAsync(string sessionId, CancellationToken ct = default) => Task.FromResult(true);
        public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken ct = default) => Task.FromResult(0);
    }

    private static SessionValidator Validator(ISessionRegistry registry, TimeSpan? ttl = null) =>
        new(registry, new MemoryCache(new MemoryCacheOptions()), ttl ?? TimeSpan.FromSeconds(5));

    [Fact]
    public async Task RepeatedChecksHitTheRegistryOnce()
    {
        var registry = new CountingRegistry(alive: true);
        SessionValidator validator = Validator(registry);

        for (int i = 0; i < 10; i++)
            Assert.True(await validator.IsValidAsync("sid_1"));

        Assert.Equal(1, registry.Queries);
    }

    [Fact]
    public async Task ADenialIsCachedToo()
    {
        // A revoked session still presenting its token is exactly what a stolen one does. Without
        // caching the "no", it queries the registry on every request it makes.
        var registry = new CountingRegistry(alive: false);
        SessionValidator validator = Validator(registry);

        for (int i = 0; i < 10; i++)
            Assert.False(await validator.IsValidAsync("sid_1"));

        Assert.Equal(1, registry.Queries);
    }

    [Fact]
    public async Task EvictMakesTheNextCheckReRead()
    {
        var registry = new CountingRegistry(alive: true);
        SessionValidator validator = Validator(registry);

        Assert.True(await validator.IsValidAsync("sid_1"));

        // What a revoke does: flip the stored answer, then evict. Without the evict the caller would
        // stay authorized for the rest of the TTL.
        registry.Alive = false;
        validator.Evict("sid_1");

        Assert.False(await validator.IsValidAsync("sid_1"));
        Assert.Equal(2, registry.Queries);
    }

    [Fact]
    public async Task WithoutAnEvictTheAnswerSurvivesUntilTheTtl()
    {
        // The accepted bound, stated as a test so it is a decision rather than a surprise: a revoke
        // that cannot evict — another process, or a race — takes effect within the TTL, not sooner.
        var registry = new CountingRegistry(alive: true);
        SessionValidator validator = Validator(registry, TimeSpan.FromMilliseconds(250));

        Assert.True(await validator.IsValidAsync("sid_1"));
        registry.Alive = false;
        Assert.True(await validator.IsValidAsync("sid_1"));   // still cached

        await Task.Delay(400);

        Assert.False(await validator.IsValidAsync("sid_1"));  // TTL elapsed, re-read
    }

    [Fact]
    public async Task OneSessionsAnswerIsNeverServedForAnother()
    {
        var registry = new CountingRegistry(alive: true);
        SessionValidator validator = Validator(registry);

        Assert.True(await validator.IsValidAsync("sid_1"));
        registry.Alive = false;

        Assert.False(await validator.IsValidAsync("sid_2"));
        Assert.True(await validator.IsValidAsync("sid_1"));   // still its own cached answer
    }

    [Fact]
    public async Task SessionKeysAreNamespacedInASharedCache()
    {
        // The host's cache is shared with everything else it caches. An unnamespaced session id could
        // collide with an unrelated key and read someone else's value as an authorization decision.
        var cache = new MemoryCache(new MemoryCacheOptions());
        cache.Set("sid_1", true);

        var registry = new CountingRegistry(alive: false);
        var validator = new SessionValidator(registry, cache, TimeSpan.FromSeconds(5));

        Assert.False(await validator.IsValidAsync("sid_1"));
        Assert.Equal(1, registry.Queries);
    }
}
