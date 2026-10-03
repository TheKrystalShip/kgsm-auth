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

    /// <summary>An account is gone.</summary>
    public const string UserDeleted = "user.deleted";

    /// <summary>An account's password was set. Never what it was set to.</summary>
    public const string UserPasswordChanged = "user.password_changed";

    /// <summary>An external identity was attached to an account.</summary>
    public const string IdentityLinked = "identity.linked";

    /// <summary>An external identity was detached from an account.</summary>
    public const string IdentityUnlinked = "identity.unlinked";

    /// <summary>A role was created, renamed, ranked or given different permissions.</summary>
    public const string RoleChanged = "auth.role.changed";

    /// <summary>A role was deleted.</summary>
    public const string RoleRemoved = "auth.role.removed";

    /// <summary>A permission was created, renamed or given different actions.</summary>
    public const string PermissionChanged = "auth.permission.changed";

    /// <summary>A permission was deleted.</summary>
    public const string PermissionRemoved = "auth.permission.removed";

    /// <summary>An account was given a role within a scope.</summary>
    public const string AssignmentGranted = "auth.assignment.granted";

    /// <summary>An account lost a role within a scope.</summary>
    public const string AssignmentRevoked = "auth.assignment.revoked";

    /// <summary>A service's requirement was approved, automatically or by a person, or narrowed.</summary>
    public const string ServiceRequirementApproved = "auth.service.requirement.approved";

    /// <summary>A service's requirement was revoked.</summary>
    public const string ServiceRequirementRevoked = "auth.service.requirement.revoked";

    /// <summary>A service was refused an action.</summary>
    public const string ServiceRefused = "auth.service.refused";

    /// <summary>The catalog of declared actions changed.</summary>
    public const string CatalogChanged = "auth.catalog.changed";
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

    /// <summary>Somebody else's, ended on <c>auth:accounts.disable</c>.</summary>
    public const string Other = "other";

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
