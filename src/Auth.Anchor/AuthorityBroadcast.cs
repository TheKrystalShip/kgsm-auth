using TheKrystalShip.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// Tells every other member what changed about who may do what.
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing here decides what is owed.</b> Every authority write files each record it changed in the
/// store's outbox in the same transaction, so this only drains: each owed record is sent as it stands
/// now, at its own version, or as its removal. A crash anywhere costs a redelivery, which every replica
/// drops as not newer.
/// </para>
/// <para>
/// The row is cleared only after the bus holds the message durably, and only up to the version sent, so
/// a write landing while this drains is owed again at its own version rather than lost.
/// </para>
/// </remarks>
internal sealed class AuthorityBroadcast(
    IClusterBus bus,
    MemberTargets members,
    AnchorAuthority authority,
    ILogger<AuthorityBroadcast> logger) : IAuthorityAnnouncer
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Send everything owed. Safe from anywhere, at any time; one drain runs at once.</summary>
    public async Task DrainAsync(CancellationToken ct)
    {
        if (authority.Store is not { } store)
            return;

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            IReadOnlyList<AuthorityAnnouncement> owed = await store.PendingAnnouncementsAsync(ct).ConfigureAwait(false);
            if (owed.Count == 0)
                return;

            IReadOnlyList<ClusterTarget> targets = await members.ResolveAsync(ct).ConfigureAwait(false);
            if (targets.Count == 0)
            {
                // Nobody to tell yet. A member joining later takes a snapshot, which holds all of it, so
                // what is owed to nobody is cleared rather than kept for a member that will not need it.
                foreach (AuthorityAnnouncement announcement in owed)
                    await store.ClearAnnouncementAsync(announcement.Key, announcement.Version, ct).ConfigureAwait(false);
                return;
            }

            foreach (AuthorityAnnouncement announcement in owed)
            {
                if (ct.IsCancellationRequested)
                    return;

                await SendAsync(store, announcement, targets, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "could not read what this anchor owes the cluster about its authority");
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task SendAsync(
        SqliteAuthorityStore store, AuthorityAnnouncement owed, IReadOnlyList<ClusterTarget> targets, CancellationToken ct)
    {
        try
        {
            AuthorityRecordKey key = owed.Key;
            if (owed.Removed)
            {
                await bus.EnqueueAsync(key.RemovedType, new RecordRemoval(key.Id, owed.Version),
                    AuthorityReplicationJson.Default.RecordRemoval, targets, ct).ConfigureAwait(false);
            }
            else
            {
                await SendCurrentAsync(store, key, targets, ct).ConfigureAwait(false);
            }

            await store.ClearAnnouncementAsync(key, owed.Version, ct).ConfigureAwait(false);
            logger.LogDebug("queued {Record} at version {Version} to {Targets} member(s)", key, owed.Version, targets.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "could not queue {Record} at version {Version} — it is owed and will be retried",
                owed.Key, owed.Version);
        }
    }

    /// <summary>
    /// Send a record as it stands now. A record no longer there was removed after this row was owed; its
    /// removal is owed at its own, higher version and replaces this row, so nothing is sent for it here.
    /// </summary>
    private async Task SendCurrentAsync(
        SqliteAuthorityStore store, AuthorityRecordKey key, IReadOnlyList<ClusterTarget> targets, CancellationToken ct)
    {
        switch (key.Kind)
        {
            case AuthorityRecordKind.Account:
                if (await store.ReadAccountRecordAsync(key.Id, ct).ConfigureAwait(false) is { } account)
                    await bus.EnqueueAsync(key.ChangedType, account, AuthorityReplicationJson.Default.AccountRecord, targets, ct).ConfigureAwait(false);
                break;

            case AuthorityRecordKind.Role:
                if (await store.ReadRoleRecordAsync(key.Id, ct).ConfigureAwait(false) is { } role)
                    await bus.EnqueueAsync(key.ChangedType, role, AuthorityReplicationJson.Default.RoleRecord, targets, ct).ConfigureAwait(false);
                break;

            case AuthorityRecordKind.Permission:
                if (await store.ReadPermissionRecordAsync(key.Id, ct).ConfigureAwait(false) is { } permission)
                    await bus.EnqueueAsync(key.ChangedType, permission, AuthorityReplicationJson.Default.PermissionRecord, targets, ct).ConfigureAwait(false);
                break;

            case AuthorityRecordKind.Assignment:
                if (await store.ReadAssignmentRecordAsync(key.Id, ct).ConfigureAwait(false) is { } assignment)
                    await bus.EnqueueAsync(key.ChangedType, assignment, AuthorityReplicationJson.Default.AssignmentRecord, targets, ct).ConfigureAwait(false);
                break;

            default:
                await bus.EnqueueAsync(key.ChangedType, await store.ReadCatalogRecordAsync(ct).ConfigureAwait(false),
                    AuthorityReplicationJson.Default.CatalogRecord, targets, ct).ConfigureAwait(false);
                break;
        }
    }
}

/// <summary>
/// Drains the authority outbox on a timer, and sends every live member the heartbeat that keeps it
/// current.
/// </summary>
/// <remarks>
/// <para>
/// The write paths drain at once, so a change reaches the cluster within the moment; the timer catches
/// everything they missed — a crash, a bus that was down.
/// </para>
/// <para>
/// <b>The heartbeat goes only to members the roster shows alive.</b> It is worth something only fresh,
/// and it carries the moment it was sent, so one held for a member that is down would confirm nothing
/// when it arrived. A member that is down goes stale, which is what it should be, and takes a snapshot
/// when it is back.
/// </para>
/// </remarks>
internal sealed class AuthorityBroadcastWorker(
    AuthorityBroadcast broadcast,
    AnchorAuthority authority,
    AnchorOptions options,
    IClusterBus bus,
    MembersStore members,
    ClusterOptions cluster,
    TimeProvider clock,
    ILogger<AuthorityBroadcastWorker> logger) : BackgroundService
{
    private static readonly TimeSpan DrainInterval = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        DateTimeOffset nextBeat = DateTimeOffset.MinValue;
        TimeSpan tick = options.AuthorityHeartbeat < DrainInterval ? options.AuthorityHeartbeat : DrainInterval;

        using var timer = new PeriodicTimer(tick);
        try
        {
            do
            {
                await broadcast.DrainAsync(stoppingToken).ConfigureAwait(false);

                if (clock.GetUtcNow() >= nextBeat)
                {
                    await BeatAsync(stoppingToken).ConfigureAwait(false);
                    nextBeat = clock.GetUtcNow() + options.AuthorityHeartbeat;
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // The host is stopping.
        }
    }

    /// <summary>Send <c>authority.current</c> to every live member.</summary>
    internal async Task BeatAsync(CancellationToken ct)
    {
        if (authority.Store is not { } store)
            return;

        try
        {
            IReadOnlyList<MemberRow> rows = await members.ListEnabledAsync(ct).ConfigureAwait(false);
            ClusterTarget[] targets =
            [
                .. rows
                    .Where(r => !string.Equals(r.MemberId, cluster.MemberId, StringComparison.Ordinal))
                    .Where(r => r.MembershipState == GossipState.Alive && !string.IsNullOrWhiteSpace(r.Url))
                    .Select(r => new ClusterTarget(r.MemberId, r.Url)),
            ];

            if (targets.Length == 0)
                return;

            AuthorityCurrent current = new(
                await store.VersionAsync(ct).ConfigureAwait(false),
                (int)options.StalenessBound.TotalSeconds,
                Access.AccessContract.Version,
                clock.GetUtcNow());

            await bus.EnqueueAsync(AuthorityMessageTypes.Current, current,
                AuthorityReplicationJson.Default.AuthorityCurrent, targets, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "could not send the authority heartbeat");
        }
    }
}
