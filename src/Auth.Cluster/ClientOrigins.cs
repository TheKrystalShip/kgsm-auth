namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// The origins a browser holding one of this cluster's sessions may call a member from.
/// </summary>
/// <remarks>
/// <para>
/// They are the provider's registered clients, read through the holder of <c>auth</c> — or, on a leaf,
/// from the host file the member on its machine writes. So no member is configured with a list of
/// origins: registering a client at the provider is what admits it everywhere, and removing one there
/// is what stops it.
/// </para>
/// <para>
/// A member answers such an origin <b>without credentials</b>. A session travels as a bearer, and
/// nothing a member serves reads a cookie, so an allowance with credentials would buy a caller nothing
/// but the risk.
/// </para>
/// </remarks>
public interface IClientOrigins
{
    /// <summary>Whether <paramref name="origin"/>, exactly as a browser sent it, is a registered client's.</summary>
    bool Admits(string? origin);
}
