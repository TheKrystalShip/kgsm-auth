using System.Text.Json;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Cluster.Tests;

/// <summary>
/// Ending a session because another member said so. The handler runs on every member, so what it does
/// with a payload is the one place a sign-out either reaches a machine or silently does not.
/// </summary>
public class SessionRevokeHandlerTests
{
    private sealed class Sessions : IClusterSessionAuthority
    {
        public List<string> Revoked { get; } = [];
        public List<string> Recorded { get; } = [];
        public List<string> RevokedHandles { get; } = [];
        public IReadOnlyList<string> ReturnsForHandle { get; set; } = [];

        public Task RevokeAsync(string sessionId, CancellationToken ct = default)
        {
            Revoked.Add(sessionId);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<string>> RevokeAllForHandleAsync(string handle, CancellationToken ct = default)
        {
            RevokedHandles.Add(handle);
            return Task.FromResult(ReturnsForHandle);
        }

        public Task<bool> IsRevokedAsync(string sessionId, CancellationToken ct = default) =>
            Task.FromResult(Recorded.Contains(sessionId));

        public Task RecordRevocationAsync(string sessionId, DateTimeOffset until, CancellationToken ct = default)
        {
            Recorded.Add(sessionId);
            return Task.CompletedTask;
        }
    }

    private sealed class Validator : ISessionValidator
    {
        public List<string> Evicted { get; } = [];
        public Task<bool> IsValidAsync(string sessionId, CancellationToken ct = default) => Task.FromResult(true);
        public void Evict(string sessionId) => Evicted.Add(sessionId);
    }

    private static (SessionRevokeHandler Handler, Sessions Sessions, Validator Validator) Build()
    {
        var sessions = new Sessions();
        var validator = new Validator();
        var revocations = new ClusterSessionRevocations(
            sessions, new MemoryCache(new MemoryCacheOptions()), TimeSpan.FromSeconds(5));

        return (
            new SessionRevokeHandler(
                sessions, validator, revocations, TimeSpan.FromDays(30), NullLogger<SessionRevokeHandler>.Instance),
            sessions,
            validator);
    }

    private static ClusterEnvelope Envelope(string payload) =>
        new("msg_1", "session.revoke", "other-member", DateTimeOffset.UtcNow, JsonDocument.Parse(payload).RootElement);

    [Fact]
    public async Task Ending_one_session_both_revokes_a_row_and_records_that_it_is_over()
    {
        // The two writes are not alternatives. A session this member minted has a row to revoke; one
        // the anchor minted has none, and the record is the only thing that ends it here. The handler
        // does both because it cannot tell which it was handed.
        (SessionRevokeHandler handler, Sessions sessions, Validator validator) = Build();

        await handler.HandleAsync(Envelope("""{"scope":"sid","sid":"sid_abc"}"""), default);

        Assert.Equal(["sid_abc"], sessions.Revoked);
        Assert.Equal(["sid_abc"], sessions.Recorded);
        Assert.Equal(["sid_abc"], validator.Evicted);
    }

    [Fact]
    public async Task A_person_is_named_by_handle()
    {
        (SessionRevokeHandler handler, Sessions sessions, _) = Build();
        sessions.ReturnsForHandle = ["sid_1", "sid_2"];

        await handler.HandleAsync(Envelope("""{"scope":"user","handle":"local:usr_abc"}"""), default);

        Assert.Equal(["local:usr_abc"], sessions.RevokedHandles);
    }

    [Fact]
    public async Task A_bare_discord_id_names_a_discord_identity()
    {
        // A sender stating a bare id is naming a Discord identity, which is one of the two spellings
        // the credential store keys on. Read as a handle it would match nobody, and the sign-out
        // would report success having ended nothing.
        (SessionRevokeHandler handler, Sessions sessions, _) = Build();

        await handler.HandleAsync(Envelope("""{"scope":"user","discordId":"245717107596197888"}"""), default);

        Assert.Equal(["discord:245717107596197888"], sessions.RevokedHandles);
    }

    [Theory]
    [InlineData("""{"scope":"sid"}""")]
    [InlineData("""{"scope":"user"}""")]
    [InlineData("""{"scope":"nonsense"}""")]
    [InlineData("""{}""")]
    [InlineData("""[]""")]
    public async Task A_payload_it_cannot_act_on_is_a_no_op_rather_than_a_throw(string payload)
    {
        // A throw surfaces as a transient 500, which keeps the message in the sender's outbox — so a
        // payload that can never become valid would wedge the queue behind it, taking every later
        // message with it, including a disable.
        (SessionRevokeHandler handler, Sessions sessions, Validator validator) = Build();

        await handler.HandleAsync(Envelope(payload), default);

        Assert.Empty(sessions.Revoked);
        Assert.Empty(sessions.Recorded);
        Assert.Empty(sessions.RevokedHandles);
        Assert.Empty(validator.Evicted);
    }
}
