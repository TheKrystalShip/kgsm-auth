namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// The authorization tier a caller holds on a KGSM host. Ordered: a higher tier subsumes the lower
/// ones (admin ⊇ operator ⊇ viewer), so a viewer requirement is satisfied by an operator and an
/// admin too.
/// <para>
/// <see cref="None"/> is "identity verified, but this host grants them nothing" — a subject attached
/// to no account here, or one awaiting approval. Re-authenticating cannot change it, so it is a
/// terminal denial rather than a prompt to sign in again.
/// </para>
/// The ordinal drives the hierarchy; the lower-case name is the wire and claim form
/// (<see cref="KgsmTiers"/>).
/// </summary>
public enum KgsmTier
{
    None = 0,
    Viewer = 1,
    Operator = 2,
    Admin = 3,
}

/// <summary>Wire/claim strings for <see cref="KgsmTier"/>, and the parse back. Lower-case, stable.</summary>
public static class KgsmTiers
{
    public const string None = "none";
    public const string Viewer = "viewer";
    public const string Operator = "operator";
    public const string Admin = "admin";

    /// <summary>The wire form of a tier — the value carried in a claim or a relay header.</summary>
    public static string ToWire(KgsmTier tier) => tier switch
    {
        KgsmTier.Admin => Admin,
        KgsmTier.Operator => Operator,
        KgsmTier.Viewer => Viewer,
        _ => None,
    };

    /// <summary>
    /// The tier a wire string names. Anything unrecognised — absent, misspelled, from a newer peer
    /// that speaks a tier this build does not know — parses to <see cref="KgsmTier.None"/>, so an
    /// unreadable value denies rather than grants.
    /// </summary>
    public static KgsmTier Parse(string? wire) => wire?.Trim().ToLowerInvariant() switch
    {
        Admin => KgsmTier.Admin,
        Operator => KgsmTier.Operator,
        Viewer => KgsmTier.Viewer,
        _ => KgsmTier.None,
    };
}
