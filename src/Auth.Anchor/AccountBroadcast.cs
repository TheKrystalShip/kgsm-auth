using Microsoft.Extensions.Hosting;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Tells every other member what changed about an account.
/// </summary>
/// <remarks>
/// <para>
/// Withdrawal has to travel as reliably as granting, which is why this rides the durable bus rather
/// than a best-effort notification: a member that is down when somebody is disabled gets the change
/// when it returns, not never. Promoting somebody and being unable to demote them is worse than the
/// state either mechanism replaces.
/// </para>
/// <para>
/// <b>Nothing here decides what is owed.</b> That is written in the accounts' own database, in the
/// same transaction as the version that orders the change, so a change cannot exist at a version with
/// no announcement outstanding for it. This drains what is already recorded — which is why a crash
/// anywhere in it costs a redelivery rather than a change nobody is ever told about.
/// </para>
/// <para>
/// <b>Draining is idempotent by construction.</b> An announcement carries an account's whole state at
/// a version and every replica drops anything not newer, so the row is deleted only after the bus has
/// accepted the message: a crash in that gap re-sends something harmless rather than dropping
/// something that mattered.
/// </para>
/// </remarks>
internal sealed class AccountBroadcast(
    IClusterBus bus,
    MemberTargets members,
    IUserStore store,
    IAccountAnnouncements announcements,
    ILogger<AccountBroadcast> logger)
{
    /// <summary>An account's whole state, as this member now holds it.</summary>
    internal const string ChangedType = "account.changed";

    /// <summary>An account that is gone.</summary>
    internal const string RemovedType = "account.removed";

    /// <summary>
    /// Send everything this member owes the cluster about its accounts.
    /// </summary>
    /// <remarks>
    /// Safe to call at any time and from anywhere: an empty outbox is the ordinary state, and a
    /// second caller finding the same row simply sends it again. A write path calls it so the cluster
    /// hears within the moment; the worker calls it so nothing depends on that call having happened.
    /// </remarks>
    internal async Task DrainAsync(CancellationToken ct)
    {
        IReadOnlyList<AccountAnnouncement> owed;
        try
        {
            owed = await announcements.PendingAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "could not read what this member owes the cluster about its accounts");
            return;
        }

        if (owed.Count == 0)
            return;

        IReadOnlyList<ClusterTarget> targets = await members.ResolveAsync(ct).ConfigureAwait(false);
        if (targets.Count == 0)
        {
            // Nobody to tell. The rows stay: a member joining later is told by its own snapshot, and a
            // cluster that gains its first member after a change still owes that change to it.
            return;
        }

        foreach (AccountAnnouncement announcement in owed)
        {
            if (ct.IsCancellationRequested)
                return;

            await SendAsync(announcement, targets, ct).ConfigureAwait(false);
        }
    }

    private async Task SendAsync(
        AccountAnnouncement owed, IReadOnlyList<ClusterTarget> targets, CancellationToken ct)
    {
        try
        {
            if (owed.Kind == AccountAnnouncementKind.Removed)
            {
                await bus.EnqueueAsync(
                    RemovedType, new AccountRemoval(owed.UserId, owed.Version),
                    AccountReplicationJson.Default.AccountRemoval, targets, ct).ConfigureAwait(false);
            }
            else
            {
                KgsmUser? user = await store.FindByIdAsync(owed.UserId, ct).ConfigureAwait(false);
                if (user is null)
                {
                    // Changed, and then deleted before this drained. The removal is owed at a higher
                    // version and will be sent on its own; announcing the state of an account that is
                    // gone would be telling members something that stopped being true.
                    await announcements.ClearAsync(owed.UserId, owed.Version, ct).ConfigureAwait(false);
                    return;
                }

                IReadOnlyList<UserCredential> credentials =
                    await store.ListCredentialsAsync(owed.UserId, ct).ConfigureAwait(false);

                await bus.EnqueueAsync(
                    ChangedType,
                    new AccountChange(ReplicatedAccount.From(user, credentials), owed.Version),
                    AccountReplicationJson.Default.AccountChange, targets, ct).ConfigureAwait(false);
            }

            // Only now. The bus has the message durably, so forgetting it here is safe; forgetting it
            // first would lose the change on any failure below.
            await announcements.ClearAsync(owed.UserId, owed.Version, ct).ConfigureAwait(false);

            logger.LogInformation(
                "queued {Type} for {Account} at version {Version} to {Targets} member(s)",
                owed.Kind == AccountAnnouncementKind.Removed ? RemovedType : ChangedType,
                owed.UserId, owed.Version, targets.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The row stays, so the next pass tries again. Nothing here fails the admin's request:
            // their change has committed, and the announcement is owed rather than lost.
            logger.LogError(ex,
                "could not queue the change to {Account} at version {Version} — it is owed and will be "
                + "retried", owed.UserId, owed.Version);
        }
    }
}

/// <summary>
/// Drains what this member owes the cluster about its accounts, whether or not anything asked it to.
/// </summary>
/// <remarks>
/// The write paths drain immediately so a change reaches the cluster within the moment. This exists
/// for every case where that did not happen: a crash between the change and its announcement, a bus
/// that was unreachable, a cluster with no members at the time. It runs once at startup for the first
/// of those, and on a timer for the rest.
/// </remarks>
internal sealed class AccountBroadcastWorker(
    AccountBroadcast broadcast,
    ILogger<AccountBroadcastWorker> logger) : BackgroundService
{
    /// <summary>
    /// Slow, because it is the backstop rather than the path. What it is catching up on is measured in
    /// how long a member was down, and the write paths already drain in the ordinary case.
    /// </summary>
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            do
            {
                await broadcast.DrainAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // The host is stopping. Not a failure.
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "the account announcement drainer stopped");
        }
    }
}
