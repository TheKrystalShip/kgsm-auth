namespace TheKrystalShip.Auth.Access;

/// <summary>
/// One change a person asks to make to who may do what.
/// </summary>
/// <remarks>
/// Every change to permissions, roles, assignments, service requirements and the standing of an
/// account is one of these. <see cref="AuthorityRules.Check"/> decides whether the asker may make it,
/// and the store applies it only once that has said yes, in the same transaction.
/// </remarks>
public abstract record AuthorityEdit
{
    /// <summary>What kind of edit this is: its name on the wire and the action it needs.</summary>
    public abstract EditKind Kind { get; }
}

/// <summary>
/// A kind of edit: the name a request spells it with, the <c>auth:*</c> action it needs, and whether that
/// action is checked at a scope the request names rather than cluster-wide.
/// </summary>
/// <remarks>
/// <para>
/// <b>The one place an edit's action is written.</b> <see cref="AuthorityRules.Check"/> enforces
/// <see cref="Action"/>, the anchor parses requests by <see cref="Name"/>, and the anchor publishes
/// <see cref="Wire"/> as its operations — so what a client is told an edit needs is what the rules check.
/// </para>
/// <para>
/// An edit with no <see cref="Name"/> is not made through the edits endpoint: switching an account off
/// and deleting one are the account routes' own, and checked there with the same rules.
/// </para>
/// </remarks>
/// <param name="Name">The request's <c>kind</c>, or null for an edit made only by an account route.</param>
/// <param name="Action">The action the asker must hold.</param>
/// <param name="ScopedByRequest">
/// Whether the action is checked at the scope the edit is about — an assignment's — rather than
/// cluster-wide.
/// </param>
public sealed record EditKind(string? Name, string Action, bool ScopedByRequest = false)
{
    /// <summary>Create a role.</summary>
    public static readonly EditKind RoleCreate = new("role.create", AuthActions.RolesEdit);

    /// <summary>Rename a role.</summary>
    public static readonly EditKind RoleRename = new("role.rename", AuthActions.RolesEdit);

    /// <summary>Delete a role.</summary>
    public static readonly EditKind RoleDelete = new("role.delete", AuthActions.RolesEdit);

    /// <summary>Rank a role.</summary>
    public static readonly EditKind RoleRank = new("role.rank", AuthActions.RolesEdit);

    /// <summary>Set a role's permissions.</summary>
    public static readonly EditKind RolePermissions = new("role.permissions", AuthActions.RolesEdit);

    /// <summary>Create a permission.</summary>
    public static readonly EditKind PermissionCreate = new("permission.create", AuthActions.PermissionsEdit);

    /// <summary>Rename a permission.</summary>
    public static readonly EditKind PermissionRename = new("permission.rename", AuthActions.PermissionsEdit);

    /// <summary>Delete a permission.</summary>
    public static readonly EditKind PermissionDelete = new("permission.delete", AuthActions.PermissionsEdit);

    /// <summary>Set a permission's actions.</summary>
    public static readonly EditKind PermissionActions = new("permission.actions", AuthActions.PermissionsEdit);

    /// <summary>Assign a role at a scope.</summary>
    public static readonly EditKind AssignRole = new("assign", AuthActions.RolesAssign, ScopedByRequest: true);

    /// <summary>Take an assignment away, at the scope it was made.</summary>
    public static readonly EditKind RevokeAssignment = new("revoke", AuthActions.RolesAssign, ScopedByRequest: true);

    /// <summary>Approve a service's requirement.</summary>
    public static readonly EditKind RequirementApprove = new("requirement.approve", AuthActions.ServicesManage);

    /// <summary>Narrow a service's requirement.</summary>
    public static readonly EditKind RequirementNarrow = new("requirement.narrow", AuthActions.ServicesManage);

    /// <summary>Revoke a service's requirement.</summary>
    public static readonly EditKind RequirementRevoke = new("requirement.revoke", AuthActions.ServicesManage);

    /// <summary>Switch an account off, or back on.</summary>
    public static readonly EditKind AccountDisable = new(null, AuthActions.AccountsDisable);

    /// <summary>Delete an account.</summary>
    public static readonly EditKind AccountDelete = new(null, AuthActions.AccountsDelete);

    /// <summary>Every kind a request to the edits endpoint may name.</summary>
    public static readonly IReadOnlyList<EditKind> Wire =
    [
        RoleCreate, RoleRename, RoleDelete, RoleRank, RolePermissions,
        PermissionCreate, PermissionRename, PermissionDelete, PermissionActions,
        AssignRole, RevokeAssignment,
        RequirementApprove, RequirementNarrow, RequirementRevoke,
    ];
}

/// <summary>Create a role, directly below the creator's highest role.</summary>
public sealed record CreateRole(string Name) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RoleCreate;
}

/// <summary>Rename a role.</summary>
public sealed record RenameRole(string RoleId, string Name) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RoleRename;
}

/// <summary>Delete a role, and every assignment of it.</summary>
public sealed record DeleteRole(string RoleId) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RoleDelete;
}

/// <summary>
/// Move a role to <paramref name="Rank"/> among the custom roles, counting from
/// <see cref="RoleRanks.FirstCustom"/>.
/// </summary>
public sealed record RankRole(string RoleId, int Rank) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RoleRank;
}

/// <summary>Replace the permissions a role holds.</summary>
public sealed record SetRolePermissions(string RoleId, IReadOnlySet<string> PermissionIds) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RolePermissions;
}

/// <summary>Create an empty permission.</summary>
public sealed record CreatePermission(string Name) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.PermissionCreate;
}

/// <summary>Rename a permission.</summary>
public sealed record RenamePermission(string PermissionId, string Name) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.PermissionRename;
}

/// <summary>Delete a permission, removing it from every role holding it.</summary>
public sealed record DeletePermission(string PermissionId) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.PermissionDelete;
}

/// <summary>Replace the actions filed into a permission.</summary>
public sealed record SetPermissionActions(string PermissionId, IReadOnlySet<string> Actions) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.PermissionActions;
}

/// <summary>Give an account a role within a scope.</summary>
public sealed record Assign(string AccountId, string RoleId, AccessScope Scope) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.AssignRole;
}

/// <summary>Take an assignment away.</summary>
public sealed record Revoke(string AssignmentId) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RevokeAssignment;
}

/// <summary>Approve a service's requirement at a scope: one waiting, or one revoked earlier.</summary>
public sealed record ApproveRequirement(string AccountId, string Action, AccessScope Scope) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RequirementApprove;
}

/// <summary>Narrow an approved requirement to a scope inside the one it holds.</summary>
public sealed record NarrowRequirement(string AccountId, string Action, AccessScope Scope) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RequirementNarrow;
}

/// <summary>Revoke a service's requirement. It stays revoked for the account's life.</summary>
public sealed record RevokeRequirement(string AccountId, string Action) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.RequirementRevoke;
}

/// <summary>Switch an account off.</summary>
public sealed record DisableAccount(string AccountId) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.AccountDisable;
}

/// <summary>Delete an account and every assignment it holds.</summary>
public sealed record DeleteAccount(string AccountId) : AuthorityEdit
{
    /// <inheritdoc />
    public override EditKind Kind => EditKind.AccountDelete;
}

/// <summary>Why a change was refused.</summary>
public enum RefusalCode
{
    /// <summary>The asker lacks the <c>auth:*</c> action the change needs, at its scope.</summary>
    NotPermitted,

    /// <summary>Only an Owner grants, revokes or acts on Owner.</summary>
    OwnerOnly,

    /// <summary>The built-in roles are not renamed, deleted, ranked or assigned; Owner is not edited.</summary>
    BuiltInRole,

    /// <summary>The role is not ranked below the asker's highest role at that scope or wider.</summary>
    RankNotBelow,

    /// <summary>The change would grant actions the asker does not hold at that scope or wider.</summary>
    NotHeld,

    /// <summary>A role holding the permission ranks at or above the asker's highest role.</summary>
    PermissionHeldAbove,

    /// <summary>The change would leave the cluster with no active Owner.</summary>
    LastOwner,

    /// <summary>The name is taken, compared case-insensitively.</summary>
    DuplicateName,

    /// <summary>The name is empty or too long.</summary>
    InvalidName,

    /// <summary>The rank is outside the custom roles.</summary>
    InvalidRank,

    /// <summary>The account already holds that role at that scope.</summary>
    DuplicateAssignment,

    /// <summary>The scope does not suit the change: Owner outside the cluster, a narrowing that widens.</summary>
    InvalidScope,

    /// <summary>A self action or an undeclared one cannot be filed into a permission.</summary>
    NotFileable,

    /// <summary>The account is of the wrong kind for the change.</summary>
    WrongAccountKind,

    /// <summary>The requirement is not in a state the change applies to.</summary>
    WrongRequirementState,

    /// <summary>Something the change names does not exist.</summary>
    NotFound,
}

/// <summary>A refused change, and why.</summary>
/// <param name="Code">The reason.</param>
/// <param name="Message">A sentence for the person who asked.</param>
/// <param name="Actions">For <see cref="RefusalCode.NotHeld"/>, the actions the asker does not hold.</param>
public sealed record AuthorityRefusal(RefusalCode Code, string Message, IReadOnlyList<string>? Actions = null);
