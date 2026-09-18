using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Where a browser reaches this anchor, and the provider callbacks built from it.
/// </summary>
/// <remarks>
/// <para>
/// The configured public address when there is one; otherwise the name this anchor serves in a cluster
/// with a DNS anchor — the accounts capability's own name, which is the same for whichever member holds
/// the capability. Read on every use: the name is only this anchor's while it holds the capability and
/// serves it.
/// </para>
/// <para>
/// A provider accepts only redirect URIs registered on its application, so the callback has to be one of
/// them or the bounce is refused at the provider, where no log here sees it. Building both callbacks from
/// one base means the two a provider needs registered can never name different origins.
/// </para>
/// </remarks>
internal sealed class AnchorAddress(AnchorOptions options, IEnumerable<ISelfAddressSource> assigned)
{
    private readonly ISelfAddressSource[] _assigned = [.. assigned];

    /// <summary>The origin a browser reaches this anchor at, or null when it has none to state.</summary>
    public string? Base =>
        options.PublicBaseUrl is { Length: > 0 } configured
            ? configured.TrimEnd('/')
            : _assigned.SelectMany(s => s.Addresses).FirstOrDefault()?.TrimEnd('/');

    /// <summary>Where a provider sends the browser back after a sign-in, or null with no address.</summary>
    public string? RedirectUri(string provider) =>
        Base is { } origin ? $"{origin}/auth/{provider}/callback" : null;

    /// <summary>
    /// Where a provider sends the browser back when somebody is <em>attaching</em> an account rather
    /// than signing in with one, or null with no address.
    /// </summary>
    /// <remarks>
    /// A separate address because the two arrivals mean different things and must not be confused: one
    /// mints a session for whoever comes back, the other attaches whoever comes back to an account
    /// that is already signed in.
    /// </remarks>
    public string? LinkRedirectUri(string provider) =>
        Base is { } origin ? $"{origin}/auth/identities/{provider}/callback" : null;
}
