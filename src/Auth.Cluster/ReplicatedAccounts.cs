using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// This member's read-only copy of the cluster's accounts, and whether it can be reached at all.
/// </summary>
/// <remarks>
/// A seam rather than the store itself, because opening the account store is a surface's own
/// business: each one knows where its file is, when it opened it and what it does about a failure to.
/// What every member shares is what happens next — applying what the holder publishes, and saying so
/// when it cannot.
/// <para>
/// <b>Unavailable is a real answer.</b> A store that will not open is reported, never worked around:
/// a member that quietly resolved everybody as a stranger would look healthy while refusing everyone.
/// </para>
/// </remarks>
public interface IReplicatedAccounts
{
    /// <summary>
    /// The replica to apply changes to, or <see langword="null"/> when the account store could not be
    /// opened.
    /// </summary>
    AccountReplica? Replica { get; }

    /// <summary>Why the store is unavailable, when it is. <see langword="null"/> when it is not.</summary>
    string? UnavailableReason { get; }
}
