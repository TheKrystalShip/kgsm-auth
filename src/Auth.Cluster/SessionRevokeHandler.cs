using System.Text.Json;

using Microsoft.Extensions.Logging;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// The sessions this member holds rows for, as the bus needs to reach them.
/// </summary>
/// <remarks>
/// Narrower than a session registry on purpose: this is what ending somebody's session from another
/// machine requires, and nothing else. A member implements it over whatever it already keeps its own
/// sessions in.
/// </remarks>
public interface IClusterSessionAuthority : IClusterSessionDenyList
{
    /// <summary>
    /// End one session this member minted. A no-op on an already-revoked or absent row, which is what
    /// makes the handler idempotent without checking first.
    /// </summary>
    Task RevokeAsync(string sessionId, CancellationToken ct = default);

    /// <summary>
    /// End every session this member holds for one person, returning the ids ended so their cached
    /// answers can be dropped.
    /// </summary>
    Task<IReadOnlyList<string>> RevokeAllForHandleAsync(string handle, CancellationToken ct = default);
}

/// <summary>
/// Ends a session because another member said it is over.
/// </summary>
/// <remarks>
/// <b>It ends two kinds of session.</b> One this member minted has a row, and revoking it is a write
/// to that row. One the cluster's auth anchor minted has none — the sign-in happened on a different
/// machine — so ending it here means recording that it is over, because the bearer is verified
/// against a published key and needs no row to be accepted. The handler does both and does not have
/// to know which it was handed.
/// <para>
/// <b>Idempotent by construction.</b> Both writes are no-ops on an already-revoked or absent row, so
/// replaying this handler for the same envelope — or receiving two envelopes that target the same
/// session — is always harmless, which is what <see cref="IClusterMessageHandler"/> requires. A
/// malformed-but-known-type payload is logged and swallowed, never thrown: throwing surfaces as a
/// transient <c>500</c> and the sender retries forever against a payload that can never become valid.
/// </para>
/// </remarks>
public sealed class SessionRevokeHandler(
    IClusterSessionAuthority sessions,
    ISessionValidator sessionValidator,
    ClusterSessionRevocations clusterSessions,
    TimeSpan revocationRetention,
    ILogger<SessionRevokeHandler> logger) : IClusterMessageHandler
{
    /// <summary>The type every member registers this against.</summary>
    public string Type => "session.revoke";

    public async Task HandleAsync(ClusterEnvelope envelope, CancellationToken ct)
    {
        string? scope = GetString(envelope.Payload, "scope");
        switch (scope)
        {
            case "sid":
            {
                string? sid = GetString(envelope.Payload, "sid");
                if (string.IsNullOrWhiteSpace(sid))
                {
                    logger.LogWarning(
                        "cluster session.revoke (id={Id} from={From}): scope=sid but no sid in payload — no-op",
                        envelope.Id, envelope.From);
                    return;
                }

                await sessions.RevokeAsync(sid, ct).ConfigureAwait(false);

                // A session the anchor minted has no row here — it was never a sign-in on this member
                // — so there is nothing for the revoke above to act on, and this member would go on
                // accepting its bearer. The record is what ends it. Also a no-op when a row is already
                // present, so the two calls together handle both kinds without the handler having to
                // know which it was given.
                await sessions.RecordRevocationAsync(
                    sid, DateTimeOffset.UtcNow + revocationRetention, ct).ConfigureAwait(false);

                sessionValidator.Evict(sid);
                clusterSessions.Evict(sid);
                break;
            }

            case "user":
            {
                // The handle names the person. A sender that states a bare Discord id is naming a
                // Discord identity, which is one of the two spellings the credential store keys on.
                string? handle = GetString(envelope.Payload, "handle");
                if (string.IsNullOrWhiteSpace(handle)
                    && GetString(envelope.Payload, "discordId") is { Length: > 0 } discordId)
                {
                    handle = KgsmActor.Format(KgsmActorProvider.Discord, discordId);
                }

                if (string.IsNullOrWhiteSpace(handle))
                {
                    logger.LogWarning(
                        "cluster session.revoke (id={Id} from={From}): scope=user but nobody named in "
                        + "payload — no-op", envelope.Id, envelope.From);
                    return;
                }

                IReadOnlyList<string> revoked =
                    await sessions.RevokeAllForHandleAsync(handle, ct).ConfigureAwait(false);

                foreach (string sid in revoked)
                {
                    sessionValidator.Evict(sid);
                    clusterSessions.Evict(sid);
                }
                break;
            }

            case "all":
                // Reserved. A member-wide revoke-everything is not implemented, so log loudly and
                // no-op rather than guess at a destructive interpretation of it.
                logger.LogWarning(
                    "cluster session.revoke (id={Id} from={From}): scope=all is reserved and not "
                    + "implemented — no-op",
                    envelope.Id, envelope.From);
                break;

            default:
                logger.LogWarning(
                    "cluster session.revoke (id={Id} from={From}): unrecognized/missing scope {Scope} — no-op",
                    envelope.Id, envelope.From, scope);
                break;
        }
    }

    private static string? GetString(JsonElement payload, string propertyName) =>
        payload.ValueKind == JsonValueKind.Object
        && payload.TryGetProperty(propertyName, out JsonElement value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
