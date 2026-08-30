using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>Whether this anchor is the authority on accounts, and if not, why not.</summary>
internal enum AnchorStanding
{
    /// <summary>
    /// Not part of a cluster. This machine's accounts are its own and this anchor is the only thing
    /// that holds them, so it serves everything.
    /// </summary>
    Standalone = 0,

    /// <summary>In a cluster, and the assignment names this member. It serves everything.</summary>
    Holder = 1,

    /// <summary>
    /// In a cluster, and the assignment names somebody else — or nobody yet, or nobody this member
    /// has heard of. A promotion candidate, and not an authority.
    /// </summary>
    StandingBy = 2,
}

/// <summary>
/// Whether this anchor may act as the cluster's account authority right now.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three states, not two, and the first is what keeps a standalone install untouched.</b> A
/// machine with no cluster secret is not a member of anything: its accounts are its own, this anchor
/// is the only thing holding them, and there is no assignment to read. Collapsing that into "not the
/// holder" would make every standalone install refuse its own sign-ins.
/// </para>
/// <para>
/// <b>Standing by is a refusal to act, not a failure.</b> A second anchor installed on another
/// machine reads the assignment, sees it is not the holder, and serves nothing that mints or extends
/// a cluster credential. That is what makes it a promotion candidate rather than a second authority:
/// the sessions it could issue would be signed with a key no member verifies against.
/// </para>
/// <para>
/// The answer is cached and refreshed by <see cref="ClusterMembershipWorker"/> rather than read per
/// request, so a request costs no query. The staleness bound is one refresh interval, which is
/// within the same eventual-consistency trade every other cluster-wide change rides.
/// </para>
/// </remarks>
internal sealed class AnchorRole
{
    private volatile Snapshot _current;

    private sealed record Snapshot(AnchorStanding Standing, string? Holder);

    internal AnchorRole(ClusterOptions cluster)
    {
        // Before the first evaluation, a clustered anchor stands by. An anchor that assumed it held
        // the capability until told otherwise would serve as the authority for exactly the window in
        // which it does not know whether it is one.
        _current = new Snapshot(
            cluster.Enabled ? AnchorStanding.StandingBy : AnchorStanding.Standalone, null);
    }

    /// <summary>Where this anchor stands as of the last evaluation.</summary>
    internal AnchorStanding Standing => _current.Standing;

    /// <summary>
    /// The member that holds the capability, or <see langword="null"/> when nobody does or this
    /// member has not heard yet. Named in a refusal so an operator is told where to go.
    /// </summary>
    internal string? Holder => _current.Holder;

    /// <summary>Whether this anchor may mint or extend a session, or answer as the account authority.</summary>
    internal bool IsAuthority => _current.Standing != AnchorStanding.StandingBy;

    /// <summary>Record what the cluster currently says. Returns true when the standing changed.</summary>
    internal bool Update(AnchorStanding standing, string? holder)
    {
        Snapshot next = new(standing, holder);
        Snapshot previous = _current;
        _current = next;
        return previous.Standing != next.Standing
            || !string.Equals(previous.Holder, next.Holder, StringComparison.Ordinal);
    }
}
