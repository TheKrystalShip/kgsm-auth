using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// Where this cluster's accounts are held, and therefore whether this member still answers for them.
/// </summary>
/// <remarks>
/// <para>
/// A standalone host holds its own accounts and is the only place anybody can sign in, which is what
/// most installs are. A host whose cluster has an <b>auth anchor</b> holds a read-only replica
/// instead: the accounts are the anchor's, one member writes them, and a person signs in once against
/// that member rather than once per machine.
/// </para>
/// <para>
/// So the answer is not a setting. It is read from cluster state — a capability somebody holds — and
/// it changes on its own when an anchor joins or is reassigned, without this member being
/// reconfigured or restarted.
/// </para>
/// </remarks>
public sealed class AnchorHeldGate(
    ClusterStateStore clusterState,
    ClusterOptions cluster)
{
    /// <summary>
    /// Who holds the cluster's accounts, when it is not this member.
    /// </summary>
    /// <remarks>
    /// A name and deliberately no address. A member of a cluster does not tell a caller where that
    /// cluster's accounts are — a browser reaches the anchor because somebody gave it the anchor's
    /// address, not because a member it happened to find offered one. Carrying the address here at
    /// all would make putting it back on a response a one-line change nobody would question.
    /// </remarks>
    /// <param name="MemberId">The member holding the cluster's accounts.</param>
    public sealed record Elsewhere(string MemberId);

    /// <summary>
    /// The member holding the cluster's accounts, or <see langword="null"/> when this member holds its
    /// own.
    /// </summary>
    /// <remarks>
    /// Null means "nobody else answers for these accounts", which covers a standalone host and a
    /// clustered one whose cluster has no anchor. Both are the same fact from here: there is nowhere
    /// else to send anybody, so this member is the only door there is and closing it would lock
    /// everybody out of their own machine.
    /// </remarks>
    public async Task<Elsewhere?> HolderAsync(CancellationToken ct)
    {
        if (!cluster.Enabled)
            return null;

        string? holder = await clusterState.HolderAsync(ClusterCapability.Auth, ct).ConfigureAwait(false);
        if (holder is null || string.Equals(holder, cluster.MemberId, StringComparison.Ordinal))
            return null;

        // The roster is deliberately not consulted. A holder this member has an assignment for but no
        // roster row for is still the holder — the accounts are not this member's to answer for merely
        // because it cannot currently see who does.
        return new Elsewhere(holder);
    }
}

/// <summary>
/// How a member says that a door belongs to whichever member holds the cluster's accounts.
/// </summary>
/// <remarks>
/// The status, the code and the header are named once so every surface refuses in the same words. The
/// response body is not here: a client routes on the code and the header, and each surface already
/// has its own error envelope — one shape imposed on all of them would be a second wire contract to
/// keep in step for no reader's benefit.
/// </remarks>
public static class AnchorHeld
{
    /// <summary>
    /// The refusal's code. A client routes on this rather than reading English.
    /// </summary>
    public const string Code = "auth_held_by_anchor";

    /// <summary>
    /// The header naming the member that holds the accounts. A name is not an address: it says this
    /// door is not the one, without being a way to discover the one.
    /// </summary>
    public const string HolderHeader = "X-Kgsm-Auth-Holder";

    /// <summary>
    /// What to tell a person. <c>503</c> rather than <c>404</c> or <c>403</c>: the door exists and
    /// this is not a refusal of the caller — it is this member saying it is not the one that answers,
    /// which is a different fact from either.
    /// </summary>
    public static string Message(string holder) =>
        $"This cluster's accounts are held by '{holder}'.";
}
