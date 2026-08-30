using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Who a durable announcement goes to: every member of the cluster except this one.
/// </summary>
/// <remarks>
/// <para>
/// State is deliberately not filtered on. A member that is unreachable right now is exactly what the
/// outbox exists for — dropping it here would turn "deliver when it returns" into "never", which is
/// the failure durable withdrawal is meant to prevent. A member an admin has <em>disabled</em> is a
/// different thing and is left out: it is not part of this cluster's answer to anything until
/// somebody turns it back on.
/// </para>
/// <para>
/// A member with no address is left out too, and not because it does not matter. An identity-bearing,
/// secret-carrying message addressed at nobody is retried at nobody for the full retry window.
/// </para>
/// </remarks>
internal sealed class MemberTargets(MembersStore members, ClusterOptions cluster)
{
    internal async Task<IReadOnlyList<ClusterTarget>> ResolveAsync(CancellationToken ct)
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
}
