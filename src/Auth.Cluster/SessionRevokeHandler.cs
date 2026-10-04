using System.Text.Json;

using Microsoft.Extensions.Logging;

using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.Auth.Cluster;

/// <summary>
/// Ends a session because the auth anchor said it is over.
/// </summary>
/// <remarks>
/// A session the anchor minted has no row on this member — the sign-in happened on another machine and
/// the bearer is verified against a published key — so ending it here means recording that it is over
/// and dropping the cached answer, which makes the refusal immediate.
/// <para>
/// <b>Idempotent by construction.</b> Recording an end that is already recorded is a no-op, so
/// replaying this handler for the same envelope — or receiving two envelopes that target the same
/// session — is always harmless, which is what <see cref="IClusterMessageHandler"/> requires. A
/// malformed-but-known-type payload is logged and swallowed, never thrown: throwing surfaces as a
/// transient <c>500</c> and the sender retries forever against a payload that can never become valid.
/// </para>
/// </remarks>
public sealed class SessionRevokeHandler(
    IClusterSessionDenyList denyList,
    ClusterSessionRevocations clusterSessions,
    TimeSpan revocationRetention,
    ILogger<SessionRevokeHandler> logger) : IClusterMessageHandler
{
    /// <summary>The type every member registers this against.</summary>
    public string Type => "session.revoke";

    public async Task HandleAsync(ClusterEnvelope envelope, CancellationToken ct)
    {
        string? scope = GetString(envelope.Payload, "scope");
        if (!string.Equals(scope, "sid", StringComparison.Ordinal))
        {
            logger.LogWarning(
                "cluster session.revoke (id={Id} from={From}): unrecognized/missing scope {Scope} — no-op",
                envelope.Id, envelope.From, scope);
            return;
        }

        string? sid = GetString(envelope.Payload, "sid");
        if (string.IsNullOrWhiteSpace(sid))
        {
            logger.LogWarning(
                "cluster session.revoke (id={Id} from={From}): scope=sid but no sid in payload — no-op",
                envelope.Id, envelope.From);
            return;
        }

        await denyList.RecordRevocationAsync(
            sid, DateTimeOffset.UtcNow + revocationRetention, ct).ConfigureAwait(false);

        clusterSessions.Evict(sid);
    }

    private static string? GetString(JsonElement payload, string propertyName) =>
        payload.ValueKind == JsonValueKind.Object
        && payload.TryGetProperty(propertyName, out JsonElement value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
