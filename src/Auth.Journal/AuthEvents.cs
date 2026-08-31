namespace TheKrystalShip.KGSM.Auth.Journal;

/// <summary>
/// The account events a KGSM host records, by name.
/// </summary>
/// <remarks>
/// <para>
/// <b>The names are the contract, and they say nothing about who wrote them.</b> Whichever component
/// holds a host's accounts records what happened to them: a standalone host's own API, or the auth
/// anchor when a cluster's accounts are held by one. A reader establishes which from the journal the
/// line was read out of — a fact it can check — so neither producer names itself in a payload and
/// neither needs a family of names of its own.
/// </para>
/// <para>
/// That is what lets the two coexist without a reader learning either. A cluster whose anchor takes
/// over from a member's own door produces one unbroken series of <c>auth.signed_in</c> rows, worded
/// by one mapper, filterable as one type.
/// </para>
/// </remarks>
public static class AuthEvents
{
    /// <summary>A session began.</summary>
    public const string SignedIn = "auth.signed_in";

    /// <summary>A session ended because its holder ended it.</summary>
    public const string SignedOut = "auth.signed_out";

    /// <summary>
    /// A peer node asserted an already-authenticated identity, which this host minted its own session
    /// for. Same shape as a sign-in, with <c>PeerNode</c> saying the proof was somebody else's.
    /// </summary>
    public const string ClusterVouched = "auth.cluster.vouched";

    /// <summary>Sessions were torn down before they expired.</summary>
    public const string SessionRevoked = "auth.session.revoked";

    /// <summary>
    /// A run of wrong passwords locked an account.
    /// </summary>
    /// <remarks>
    /// Recorded when the lock <em>begins</em>, never on the attempts it then refuses. An account under
    /// attack is retried immediately, so a row per refused attempt would be the flood that buries the
    /// record it is made of.
    /// </remarks>
    public const string LockedOut = "auth.locked_out";

    /// <summary>An account came into existence.</summary>
    public const string UserProvisioned = "user.provisioned";

    /// <summary>An account waiting on somebody was let in.</summary>
    public const string UserApproved = "user.approved";

    /// <summary>An account was switched off.</summary>
    public const string UserDisabled = "user.disabled";

    /// <summary>An account's authority moved.</summary>
    public const string UserTierChanged = "user.tier_changed";

    /// <summary>An account is gone.</summary>
    public const string UserDeleted = "user.deleted";

    /// <summary>An account's password was set. Never what it was set to.</summary>
    public const string UserPasswordChanged = "user.password_changed";

    /// <summary>An external identity was attached to an account.</summary>
    public const string IdentityLinked = "identity.linked";

    /// <summary>An external identity was detached from an account.</summary>
    public const string IdentityUnlinked = "identity.unlinked";
}

/// <summary>
/// How far a revocation reached, as <c>auth.session.revoked</c> carries it.
/// </summary>
/// <remarks>
/// The width rides on the line where a reader can filter on it, rather than becoming four names for
/// the one fact that sessions stopped being valid. Who was affected and who did it are already there.
/// </remarks>
public static class SessionRevokeScopes
{
    /// <summary>One of the caller's own sessions.</summary>
    public const string Self = "self";

    /// <summary>Every session the caller holds.</summary>
    public const string All = "all";

    /// <summary>Somebody else's, ended by an administrator.</summary>
    public const string Admin = "admin";

    /// <summary>
    /// Ended because the account behind it was switched off.
    /// </summary>
    /// <remarks>
    /// Its own scope because nobody acted at the moment it happened. The disable is already recorded
    /// and can be hours earlier; this is when the access actually stopped, which is the question an
    /// incident review asks and the other three scopes would answer by naming a person who was not
    /// there.
    /// </remarks>
    public const string Withdrawn = "withdrawn";
}
