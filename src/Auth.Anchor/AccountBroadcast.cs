using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Tells every other member what just changed about an account.
/// </summary>
/// <remarks>
/// <para>
/// Withdrawal has to travel as reliably as granting, which is why this rides the durable bus rather
/// than a best-effort notification: a member that is down when somebody is disabled gets the change
/// when it returns, not never. Promoting somebody and being unable to demote them is worse than the
/// state either mechanism replaces.
/// </para>
/// <para>
/// <b>The announcement is not in the same transaction as the change it announces.</b> The bus's
/// standalone enqueue commits after the local write, so a crash in the gap leaves the change applied
/// here and never announced — the change is never lost, only the telling of it. A member catches up
/// by taking a snapshot, which is also what it does when it joins, so the repair path is the one
/// that already has to exist rather than a second mechanism for a narrow window.
/// </para>
/// </remarks>
internal sealed class AccountBroadcast(
    IClusterBus bus,
    MembersStore members,
    ClusterOptions cluster,
    IUserStore store,
    ILogger<AccountBroadcast> logger)
{
    /// <summary>An account's whole state, as this member now holds it.</summary>
    internal const string ChangedType = "account.changed";

    /// <summary>An account that is gone.</summary>
    internal const string RemovedType = "account.removed";

    /// <summary>Announce an account's new state at the version just assigned to it.</summary>
    internal async Task PublishAsync(KgsmUser user, long version, CancellationToken ct)
    {
        IReadOnlyList<ClusterTarget> targets = await TargetsAsync(ct).ConfigureAwait(false);
        if (targets.Count == 0)
            return;

        IReadOnlyList<UserCredential> credentials =
            await store.ListCredentialsAsync(user.UserId, ct).ConfigureAwait(false);

        var change = new AccountChange(ReplicatedAccount.From(user, credentials), version);

        await Send(
            () => bus.EnqueueAsync(
                ChangedType, change, AccountReplicationJson.Default.AccountChange, targets, ct),
            ChangedType, user.UserId, targets.Count).ConfigureAwait(false);
    }

    /// <summary>Announce that an account is gone, at the version that says so.</summary>
    internal async Task PublishRemovalAsync(string userId, long version, CancellationToken ct)
    {
        IReadOnlyList<ClusterTarget> targets = await TargetsAsync(ct).ConfigureAwait(false);
        if (targets.Count == 0)
            return;

        var removal = new AccountRemoval(userId, version);

        await Send(
            () => bus.EnqueueAsync(
                RemovedType, removal, AccountReplicationJson.Default.AccountRemoval, targets, ct),
            RemovedType, userId, targets.Count).ConfigureAwait(false);
    }

    /// <summary>
    /// Every member that should hear about it: enabled, and not this one.
    /// </summary>
    /// <remarks>
    /// State is deliberately not filtered on. A member that is unreachable right now is exactly what
    /// the outbox exists for — dropping it here would turn "deliver when it returns" into "never",
    /// which is the failure withdrawal travelling durably is meant to prevent. A member an admin has
    /// <em>disabled</em> is a different thing and is left out: it is not part of this cluster's
    /// answer to anything until somebody turns it back on.
    /// </remarks>
    private async Task<IReadOnlyList<ClusterTarget>> TargetsAsync(CancellationToken ct)
    {
        IReadOnlyList<MemberRow> rows = await members.ListEnabledAsync(ct).ConfigureAwait(false);

        return
        [
            .. rows
                .Where(r => !string.Equals(r.MemberId, cluster.MemberId, StringComparison.Ordinal))
                .Where(r => !string.IsNullOrWhiteSpace(r.Url))
                .Select(r => new ClusterTarget(r.MemberId, r.Url)),
        ];
    }

    /// <summary>
    /// Enqueue, and never let a failure to announce undo the change that was already made.
    /// </summary>
    /// <remarks>
    /// The account write has committed by the time this runs. Throwing here would fail the admin's
    /// request after their change had landed, which reads as "it did not work" about something that
    /// did — and would invite them to repeat it. The honest outcome is a change that is applied and
    /// not yet told, which a snapshot repairs.
    /// </remarks>
    private async Task Send(Func<Task> enqueue, string type, string userId, int targets)
    {
        try
        {
            await enqueue().ConfigureAwait(false);
            logger.LogInformation(
                "queued {Type} for {Account} to {Targets} member(s)", type, userId, targets);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex,
                "could not queue {Type} for {Account} — the change is applied here and other members "
                + "will not learn of it until they take a snapshot", type, userId);
        }
    }
}
