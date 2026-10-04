namespace TheKrystalShip.Auth.Access;

/// <summary>Whether an account is a person or a component acting on its own.</summary>
public enum AccountKind
{
    /// <summary>A person, who signs in.</summary>
    Person = 0,

    /// <summary>
    /// A component on one member, which holds no credential that signs in, no <c>everyone</c> and no
    /// self actions.
    /// </summary>
    Service = 1,
}

/// <summary>Whether an account may be used at all.</summary>
/// <remarks>
/// Evaluated before anything else: a pending account authenticates and holds nothing, and a disabled
/// one does not authenticate.
/// </remarks>
public enum AccountStatus
{
    /// <summary>Verified, not yet approved. Holds nothing.</summary>
    Pending = 0,

    /// <summary>Approved.</summary>
    Active = 1,

    /// <summary>Switched off.</summary>
    Disabled = 2,
}

/// <summary>
/// The component and member a service account belongs to.
/// </summary>
/// <param name="Component">The component's id, as its manifest names it.</param>
/// <param name="Member">The member id of the member running it.</param>
public sealed record ServiceIdentity(string Component, string Member)
{
    /// <summary>The actor provider a service account is named under.</summary>
    public const string ActorProvider = "svc";

    /// <summary>The name half of the actor string: <c>&lt;component&gt;@&lt;member&gt;</c>.</summary>
    public string Name => $"{Component}@{Member}";

    /// <summary>The actor string audit names it by: <c>svc:&lt;component&gt;@&lt;member&gt;</c>.</summary>
    public string Actor => $"{ActorProvider}:{Name}";

    /// <summary>
    /// The scope a requirement is approved at automatically: the node itself for a component on a
    /// node, the whole cluster for an anchor.
    /// </summary>
    public AccessScope MemberScope(bool anchor) => anchor ? AccessScope.Cluster : AccessScope.ForNode(Member);
}

/// <summary>An account, as the evaluator needs to know it.</summary>
/// <param name="AccountId">The opaque account id.</param>
/// <param name="Name">The username, for messages; never a key.</param>
/// <param name="Kind">A person or a service.</param>
/// <param name="Status">Whether it may be used.</param>
/// <param name="Service">The component and member a service account belongs to.</param>
public sealed record AccessAccount(
    string AccountId, string Name, AccountKind Kind, AccountStatus Status, ServiceIdentity? Service = null);

/// <summary>A named bundle of actions: the unit a role is built from.</summary>
/// <param name="PermissionId">The opaque permission id.</param>
/// <param name="Name">Unique, compared case-insensitively.</param>
/// <param name="Actions">The action ids it holds.</param>
public sealed record Permission(string PermissionId, string Name, IReadOnlySet<string> Actions);

/// <summary>What sort of role a role is.</summary>
public enum RoleKind
{
    /// <summary>A role a person made.</summary>
    Custom = 0,

    /// <summary>
    /// The built-in role that holds every action, including unmapped ones. Ranked first, always at
    /// cluster scope, neither editable nor deletable.
    /// </summary>
    Owner = 1,

    /// <summary>
    /// The built-in role every active person holds implicitly at cluster scope. Empty at creation;
    /// its permissions are editable, and it is never assigned.
    /// </summary>
    Everyone = 2,
}

/// <summary>Wire strings for <see cref="RoleKind"/>, and the parse back.</summary>
public static class RoleKinds
{
    public const string Custom = "custom";
    public const string Owner = "owner";
    public const string Everyone = "everyone";

    /// <summary>The wire form of a role kind.</summary>
    public static string ToWire(RoleKind kind) => kind switch
    {
        RoleKind.Owner => Owner,
        RoleKind.Everyone => Everyone,
        _ => Custom,
    };

    /// <summary>
    /// The role kind a string names, with anything unrecognised read as <see cref="RoleKind.Custom"/>:
    /// a custom role grants exactly its permissions and no more.
    /// </summary>
    public static RoleKind Parse(string? wire) => wire?.Trim().ToLowerInvariant() switch
    {
        Owner => RoleKind.Owner,
        Everyone => RoleKind.Everyone,
        _ => RoleKind.Custom,
    };
}

/// <summary>A named, ranked set of permissions.</summary>
/// <param name="RoleId">The opaque role id.</param>
/// <param name="Name">Unique, compared case-insensitively.</param>
/// <param name="Kind">Custom, or one of the built-ins.</param>
/// <param name="Rank">Its place in the total order: lower ranks higher. See <see cref="RoleRanks"/>.</param>
/// <param name="Permissions">The permission ids it holds.</param>
public sealed record Role(string RoleId, string Name, RoleKind Kind, int Rank, IReadOnlySet<string> Permissions);

/// <summary>
/// The fixed ends of the role order. Custom roles take the dense ranks between them.
/// </summary>
/// <remarks>
/// A lower rank is a higher role. Owner is first, then every role a person made in the order they
/// ranked them, then <c>everyone</c>, then every service account's own role.
/// </remarks>
public static class RoleRanks
{
    /// <summary>Owner's rank. Nothing ranks at or above it.</summary>
    public const int Owner = 0;

    /// <summary>The highest rank a custom role can hold.</summary>
    public const int FirstCustom = 1;

    /// <summary><c>everyone</c>'s rank: below every custom role.</summary>
    public const int Everyone = int.MaxValue - 1;

    /// <summary>A service account's own role: last.</summary>
    public const int Service = int.MaxValue;
}

/// <summary>The ids the two built-in roles are stored under.</summary>
public static class BuiltInRoles
{
    /// <summary>Owner's role id.</summary>
    public const string OwnerId = "role_owner";

    /// <summary><c>everyone</c>'s role id.</summary>
    public const string EveryoneId = "role_everyone";

    /// <summary>Owner's name.</summary>
    public const string OwnerName = "Owner";

    /// <summary><c>everyone</c>'s name.</summary>
    public const string EveryoneName = "everyone";
}

/// <summary>An account holding a role within a scope.</summary>
/// <param name="AssignmentId">The opaque assignment id.</param>
/// <param name="AccountId">Who holds it.</param>
/// <param name="RoleId">What they hold.</param>
/// <param name="Scope">Where they hold it.</param>
public sealed record Assignment(string AssignmentId, string AccountId, string RoleId, AccessScope Scope);

/// <summary>Where a service's requirement stands.</summary>
public enum RequirementState
{
    /// <summary>Granted at <see cref="ServiceRequirement.Grant"/>.</summary>
    Approved = 0,

    /// <summary>An <c>auth:*</c> requirement, waiting for an Owner.</summary>
    Waiting = 1,

    /// <summary>Taken away by a person. Stays taken away for the account's life.</summary>
    Revoked = 2,
}

/// <summary>Wire strings for <see cref="RequirementState"/>, and the parse back.</summary>
public static class RequirementStates
{
    public const string Approved = "approved";
    public const string Waiting = "waiting";
    public const string Revoked = "revoked";

    /// <summary>The wire form of a requirement's state.</summary>
    public static string ToWire(RequirementState state) => state switch
    {
        RequirementState.Approved => Approved,
        RequirementState.Waiting => Waiting,
        _ => Revoked,
    };

    /// <summary>
    /// The state a string names, with anything unrecognised read as <see cref="RequirementState.Revoked"/>,
    /// the one state that grants nothing.
    /// </summary>
    public static RequirementState Parse(string? wire) => wire?.Trim().ToLowerInvariant() switch
    {
        Approved => RequirementState.Approved,
        Waiting => RequirementState.Waiting,
        _ => RequirementState.Revoked,
    };
}

/// <summary>
/// An action a service account needs, from its component's manifest, and what has been decided
/// about it.
/// </summary>
/// <param name="AccountId">The service account.</param>
/// <param name="Action">The other component's action id it performs.</param>
/// <param name="ScopeKind">The scope kind the manifest says it needs the action at.</param>
/// <param name="Why">The manifest's reason, for the person reviewing it.</param>
/// <param name="State">Approved, waiting or revoked.</param>
/// <param name="Grant">Where it is approved; set while <see cref="State"/> is approved.</param>
/// <param name="DecidedBy">
/// The actor who last decided it, or <see langword="null"/> when it was approved automatically. A
/// requirement a person decided stays as they left it.
/// </param>
/// <param name="Declared">
/// Whether the component's latest manifest still declares it. Only a declared requirement grants:
/// nothing is performed without being required.
/// </param>
public sealed record ServiceRequirement(
    string AccountId,
    string Action,
    ScopeKind ScopeKind,
    string? Why,
    RequirementState State,
    AccessScope? Grant,
    string? DecidedBy,
    bool Declared)
{
    /// <summary>Whether this requirement grants <see cref="Action"/> anywhere right now.</summary>
    public bool Grants => Declared && State == RequirementState.Approved && Grant is not null;
}

/// <summary>
/// How recently a member heard that its replica is current.
/// </summary>
/// <remarks>
/// A member past the bound serves <c>read</c> actions and refuses everything else, Owners included.
/// The anchor holds the authority itself and is always current.
/// </remarks>
public readonly record struct AuthorityFreshness
{
    private AuthorityFreshness(bool authoritative, DateTimeOffset? confirmedAt, TimeSpan bound)
    {
        IsAuthoritative = authoritative;
        ConfirmedAt = confirmedAt;
        Bound = bound;
    }

    /// <summary>Whether this is the authority itself rather than a replica of it.</summary>
    public bool IsAuthoritative { get; }

    /// <summary>When the last <c>authority.current</c> was applied, if ever.</summary>
    public DateTimeOffset? ConfirmedAt { get; }

    /// <summary>How long a replica stays current without another.</summary>
    public TimeSpan Bound { get; }

    /// <summary>The anchor's own store: always current.</summary>
    public static AuthorityFreshness Authoritative { get; } = new(true, null, TimeSpan.Zero);

    /// <summary>A replica last confirmed at <paramref name="confirmedAt"/>, current for <paramref name="bound"/>.</summary>
    public static AuthorityFreshness Replica(DateTimeOffset? confirmedAt, TimeSpan bound) =>
        new(false, confirmedAt, bound);

    /// <summary>Whether a replica with this freshness is current at <paramref name="now"/>.</summary>
    public bool IsCurrent(DateTimeOffset now) =>
        IsAuthoritative || (ConfirmedAt is { } at && now - at <= Bound);
}

/// <summary>
/// The evaluation contract: the version of the rules this build evaluates by.
/// </summary>
/// <remarks>
/// The anchor names the minimum every member must run inside <c>authority.current</c>. A member below
/// it refuses to evaluate and says so, rather than answering by rules the cluster has moved past.
/// </remarks>
public static class AccessContract
{
    /// <summary>The contract this build evaluates by.</summary>
    public const int Version = 1;
}
