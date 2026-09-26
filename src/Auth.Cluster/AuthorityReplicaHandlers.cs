using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// This member's read-only copy of the cluster's authority, and whether it can be reached at all.
/// </summary>
/// <remarks>
/// A seam for the same reason <see cref="IReplicatedAccounts"/> is one: where the file lives and what
/// to do when it will not open are the member's business. Unavailable is a real answer and is
/// reported, never worked around.
/// </remarks>
public interface IReplicatedAuthority
{
    /// <summary>The replica, or <see langword="null"/> when it could not be opened.</summary>
    SqliteAuthorityStore? Replica { get; }

    /// <summary>Why it is unavailable, when it is.</summary>
    string? UnavailableReason { get; }
}

/// <summary>A replicated record another record still blocks here. The bus delivers it again.</summary>
public sealed class AuthorityDeferredException(string message) : Exception(message);

/// <summary>
/// Applies one kind of authority message from the member holding the accounts.
/// </summary>
/// <remarks>
/// <para>
/// <b>Only the holder is listened to.</b> A message from any other member is acknowledged and dropped:
/// the anchor is the one writer, and a replica that took a record from anyone else would hold a state
/// the anchor never published.
/// </para>
/// <para>
/// <b>Throws only for a deferral</b>, which is transient by construction — a name or handle another
/// record holds here until a message already in flight moves it — so the sender's retry is exactly what
/// resolves it. Every other outcome is permanent and acknowledged: a stale record never becomes newer,
/// and a payload this build cannot read will not become readable.
/// </para>
/// </remarks>
public sealed class AuthorityRecordHandler<T>(
    string type,
    JsonTypeInfo<T> payload,
    Func<SqliteAuthorityStore, T, DateTimeOffset, CancellationToken, Task<AuthorityApplyOutcome>> apply,
    Func<T, string> describe,
    IReplicatedAuthority authority,
    ClusterStateStore clusterState,
    ILogger<AuthorityRecordHandler<T>> logger) : IClusterMessageHandler
    where T : class
{
    public string Type => type;

    public async Task HandleAsync(ClusterEnvelope envelope, CancellationToken ct)
    {
        if (!await FromHolderAsync(clusterState, envelope, ct).ConfigureAwait(false))
        {
            logger.LogWarning("cluster {Type} (id={Id}) from '{From}', which does not hold the accounts — dropped",
                type, envelope.Id, envelope.From);
            return;
        }

        if (authority.Replica is not { } replica)
        {
            logger.LogError("cluster {Type} (id={Id} from={From}) dropped — the authority replica is unavailable: {Reason}",
                type, envelope.Id, envelope.From, authority.UnavailableReason);
            return;
        }

        T? record;
        try
        {
            record = envelope.Payload.Deserialize(payload);
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "cluster {Type} (id={Id} from={From}): unreadable payload — dropped", type, envelope.Id, envelope.From);
            return;
        }

        if (record is null)
        {
            logger.LogWarning("cluster {Type} (id={Id} from={From}): empty payload — dropped", type, envelope.Id, envelope.From);
            return;
        }

        AuthorityApplyOutcome outcome = await apply(replica, record, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        switch (outcome)
        {
            case AuthorityApplyOutcome.Applied:
                logger.LogInformation("{Type} {Record} applied from {From}", type, describe(record), envelope.From);
                break;

            case AuthorityApplyOutcome.Stale:
                logger.LogDebug("{Type} {Record} is not newer than what this member holds — dropped", type, describe(record));
                break;

            case AuthorityApplyOutcome.Deferred:
                throw new AuthorityDeferredException(
                    $"{type} {describe(record)} is blocked by a name or handle another record still holds here");
        }
    }

    internal static async Task<bool> FromHolderAsync(ClusterStateStore clusterState, ClusterEnvelope envelope, CancellationToken ct) =>
        string.Equals(await clusterState.HolderAsync(ClusterCapability.Auth, ct).ConfigureAwait(false), envelope.From, StringComparison.Ordinal);
}

/// <summary>
/// Applies the anchor's heartbeat: the bound this member holds itself to, the contract it must meet,
/// and a confirmation that it is current when it already holds the anchor's version.
/// </summary>
public sealed class AuthorityCurrentHandler(
    IReplicatedAuthority authority,
    ClusterStateStore clusterState,
    ILogger<AuthorityCurrentHandler> logger) : IClusterMessageHandler
{
    public string Type => AuthorityMessageTypes.Current;

    public async Task HandleAsync(ClusterEnvelope envelope, CancellationToken ct)
    {
        if (!await AuthorityRecordHandler<AuthorityCurrent>.FromHolderAsync(clusterState, envelope, ct).ConfigureAwait(false))
        {
            logger.LogWarning("authority.current from '{From}', which does not hold the accounts — dropped", envelope.From);
            return;
        }

        if (authority.Replica is not { } replica)
            return;

        AuthorityCurrent? current;
        try
        {
            current = envelope.Payload.Deserialize(AuthorityReplicationJson.Default.AuthorityCurrent);
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "authority.current (id={Id}): unreadable payload — dropped", envelope.Id);
            return;
        }

        if (current is null)
            return;

        if (!await replica.ConfirmAsync(current, DateTimeOffset.UtcNow, ct).ConfigureAwait(false))
        {
            // Behind: the changes that bring it level are in flight, or were missed. Staying unconfirmed
            // is what sends the snapshot worker to take the whole state again once the bound runs out.
            logger.LogDebug("authority.current at version {Version} is ahead of this replica; not confirmed", current.Version);
        }
    }
}

/// <summary>Registers what a member needs to follow the cluster's authority.</summary>
public static class AuthorityReplicaServiceCollectionExtensions
{
    /// <summary>
    /// The handler for every authority message and the worker that takes a snapshot. The member supplies
    /// <see cref="IReplicatedAuthority"/>.
    /// </summary>
    public static IServiceCollection AddAuthorityReplica(this IServiceCollection services)
    {
        Record(services, AuthorityMessageTypes.AccountChanged, AuthorityReplicationJson.Default.AccountRecord,
            (s, r, now, ct) => s.ApplyAsync(r, now, ct), r => $"{r.UserId}@{r.Version}");
        Record(services, AuthorityMessageTypes.RoleChanged, AuthorityReplicationJson.Default.RoleRecord,
            (s, r, now, ct) => s.ApplyAsync(r, now, ct), r => $"{r.RoleId}@{r.Version}");
        Record(services, AuthorityMessageTypes.PermissionChanged, AuthorityReplicationJson.Default.PermissionRecord,
            (s, r, now, ct) => s.ApplyAsync(r, now, ct), r => $"{r.PermissionId}@{r.Version}");
        Record(services, AuthorityMessageTypes.AssignmentChanged, AuthorityReplicationJson.Default.AssignmentRecord,
            (s, r, now, ct) => s.ApplyAsync(r, now, ct), r => $"{r.AssignmentId}@{r.Version}");
        Record(services, AuthorityMessageTypes.CatalogChanged, AuthorityReplicationJson.Default.CatalogRecord,
            (s, r, now, ct) => s.ApplyAsync(r, now, ct), r => $"catalog@{r.Version}");

        Removal(services, AuthorityMessageTypes.AccountRemoved, AuthorityRecordKey.Account);
        Removal(services, AuthorityMessageTypes.RoleRemoved, AuthorityRecordKey.Role);
        Removal(services, AuthorityMessageTypes.PermissionRemoved, AuthorityRecordKey.Permission);
        Removal(services, AuthorityMessageTypes.AssignmentRemoved, AuthorityRecordKey.Assignment);

        services.AddSingleton<IClusterMessageHandler, AuthorityCurrentHandler>();
        services.AddHostedService<AuthoritySnapshotWorker>();
        return services;
    }

    private static void Record<T>(
        IServiceCollection services, string type, JsonTypeInfo<T> payload,
        Func<SqliteAuthorityStore, T, DateTimeOffset, CancellationToken, Task<AuthorityApplyOutcome>> apply,
        Func<T, string> describe)
        where T : class =>
        services.AddSingleton<IClusterMessageHandler>(sp => new AuthorityRecordHandler<T>(
            type, payload, apply, describe,
            sp.GetRequiredService<IReplicatedAuthority>(),
            sp.GetRequiredService<ClusterStateStore>(),
            sp.GetRequiredService<ILogger<AuthorityRecordHandler<T>>>()));

    private static void Removal(IServiceCollection services, string type, Func<string, AuthorityRecordKey> key) =>
        Record(services, type, AuthorityReplicationJson.Default.RecordRemoval,
            (s, r, now, ct) => s.RemoveAsync(key(r.Id), r.Version, now, ct), r => $"{r.Id}@{r.Version}");
}
