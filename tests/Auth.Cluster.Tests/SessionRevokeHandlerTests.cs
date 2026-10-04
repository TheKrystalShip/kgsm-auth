using System.Text.Json;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.Auth.Cluster.Tests;

/// <summary>
/// Ending a session because the anchor said so. The handler runs on every member, so what it does
/// with a payload is the one place a sign-out either reaches a machine or silently does not.
/// </summary>
public class SessionRevokeHandlerTests
{
    private sealed class Ended : IClusterSessionDenyList
    {
        public List<string> Recorded { get; } = [];

        public Task<bool> IsRevokedAsync(string sessionId, CancellationToken ct = default) =>
            Task.FromResult(Recorded.Contains(sessionId));

        public Task RecordRevocationAsync(string sessionId, DateTimeOffset until, CancellationToken ct = default)
        {
            Recorded.Add(sessionId);
            return Task.CompletedTask;
        }
    }

    private static (SessionRevokeHandler Handler, Ended Ended, ClusterSessionRevocations Revocations) Build()
    {
        var ended = new Ended();
        var revocations = new ClusterSessionRevocations(
            ended, new MemoryCache(new MemoryCacheOptions()), TimeSpan.FromMinutes(5));

        return (
            new SessionRevokeHandler(
                ended, revocations, TimeSpan.FromDays(30), NullLogger<SessionRevokeHandler>.Instance),
            ended,
            revocations);
    }

    private static ClusterEnvelope Envelope(string payload) =>
        new("msg_1", "session.revoke", "other-member", DateTimeOffset.UtcNow, JsonDocument.Parse(payload).RootElement);

    [Fact]
    public async Task Ending_a_session_records_that_it_is_over()
    {
        (SessionRevokeHandler handler, Ended ended, _) = Build();

        await handler.HandleAsync(Envelope("""{"scope":"sid","sid":"sid_abc"}"""), default);

        Assert.Equal(["sid_abc"], ended.Recorded);
    }

    [Fact]
    public async Task The_end_takes_effect_at_once_however_long_the_cache_holds()
    {
        // The request path caches "not ended" for minutes. A sign-out that waited out the cache would
        // leave the session accepted here for exactly that long.
        (SessionRevokeHandler handler, _, ClusterSessionRevocations revocations) = Build();
        Assert.False(await revocations.IsRevokedAsync("sid_abc"));

        await handler.HandleAsync(Envelope("""{"scope":"sid","sid":"sid_abc"}"""), default);

        Assert.True(await revocations.IsRevokedAsync("sid_abc"));
    }

    [Theory]
    [InlineData("""{"scope":"sid"}""")]
    [InlineData("""{"scope":"user","handle":"local:usr_abc"}""")]
    [InlineData("""{"scope":"nonsense"}""")]
    [InlineData("""{}""")]
    [InlineData("""[]""")]
    public async Task A_payload_it_cannot_act_on_is_a_no_op_rather_than_a_throw(string payload)
    {
        // A throw surfaces as a transient 500, which keeps the message in the sender's outbox — so a
        // payload that can never become valid would wedge the queue behind it, taking every later
        // message with it, including a disable.
        (SessionRevokeHandler handler, Ended ended, _) = Build();

        await handler.HandleAsync(Envelope(payload), default);

        Assert.Empty(ended.Recorded);
    }
}
