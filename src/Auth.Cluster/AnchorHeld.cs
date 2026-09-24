using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// Which member holds this cluster's accounts, when it is not this one.
/// </summary>
/// <remarks>
/// Read from cluster state — a capability somebody holds — so the answer changes on its own when an
/// anchor joins or is reassigned, without this member being reconfigured or restarted.
/// </remarks>
public sealed class AnchorHeldGate(
    ClusterStateStore clusterState,
    ClusterOptions cluster)
{
    /// <summary>
    /// Who holds the cluster's accounts, when it is not this member.
    /// </summary>
    /// <remarks>
    /// A name and deliberately no address: a person reaches the anchor at the issuer a member names at
    /// its protected-resource document, which is the one place that answer is given.
    /// </remarks>
    /// <param name="MemberId">The member holding the cluster's accounts.</param>
    public sealed record Elsewhere(string MemberId);

    /// <summary>
    /// The member holding the cluster's accounts, or <see langword="null"/> when there is no cluster,
    /// nobody holds them, or this member does.
    /// </summary>
    public async Task<Elsewhere?> HolderAsync(CancellationToken ct)
    {
        if (!cluster.Enabled)
            return null;

        string? holder = await clusterState.HolderAsync(ClusterCapability.Auth, ct).ConfigureAwait(false);
        if (holder is null || string.Equals(holder, cluster.MemberId, StringComparison.Ordinal))
            return null;

        // The roster is deliberately not consulted. A holder this member has an assignment for but no
        // roster row for is still the holder.
        return new Elsewhere(holder);
    }
}
