namespace TheKrystalShip.KGSM.Auth.Access;

/// <summary>
/// One change a person asks to make to who may do what.
/// </summary>
/// <remarks>
/// Every change to permissions, roles, assignments, service requirements and the standing of an
/// account is one of these. <see cref="AuthorityRules.Check"/> decides whether the asker may make it,
/// and the store applies it only once that has said yes, in the same transaction.
/// </remarks>
public abstract record AuthorityEdit;

/// <summary>Create a role, directly below the creator's highest role.</summary>
public sealed record CreateRole(string Name) : AuthorityEdit;

/// <summary>Rename a role.</summary>
public sealed record RenameRole(string RoleId, string Name) : AuthorityEdit;

/// <summary>Delete a role, and every assignment of it.</summary>
public sealed record DeleteRole(string RoleId) : AuthorityEdit;

/// <summary>
/// Move a role to <paramref name="Rank"/> among the custom roles, counting from
/// <see cref="RoleRanks.FirstCustom"/>.
/// </summary>
public sealed record RankRole(string RoleId, int Rank) : AuthorityEdit;

/// <summary>Replace the permissions a role holds.</summary>
public sealed record SetRolePermissions(string RoleId, IReadOnlySet<string> PermissionIds) : AuthorityEdit;

/// <summary>Create an empty permission.</summary>
public sealed record CreatePermission(string Name) : AuthorityEdit;

/// <summary>Rename a permission.</summary>
public sealed record RenamePermission(string PermissionId, string Name) : AuthorityEdit;

/// <summary>Delete a permission, removing it from every role holding it.</summary>
public sealed record DeletePermission(string PermissionId) : AuthorityEdit;

/// <summary>Replace the actions filed into a permission.</summary>
public sealed record SetPermissionActions(string PermissionId, IReadOnlySet<string> Actions) : AuthorityEdit;

/// <summary>Give an account a role within a scope.</summary>
public sealed record Assign(string AccountId, string RoleId, AccessScope Scope) : AuthorityEdit;

/// <summary>Take an assignment away.</summary>
public sealed record Revoke(string AssignmentId) : AuthorityEdit;

/// <summary>Approve a service's requirement at a scope: one waiting, or one revoked earlier.</summary>
public sealed record ApproveRequirement(string AccountId, string Action, AccessScope Scope) : AuthorityEdit;

/// <summary>Narrow an approved requirement to a scope inside the one it holds.</summary>
public sealed record NarrowRequirement(string AccountId, string Action, AccessScope Scope) : AuthorityEdit;

/// <summary>Revoke a service's requirement. It stays revoked for the account's life.</summary>
public sealed record RevokeRequirement(string AccountId, string Action) : AuthorityEdit;

/// <summary>Switch an account off.</summary>
public sealed record DisableAccount(string AccountId) : AuthorityEdit;

/// <summary>Delete an account and every assignment it holds.</summary>
public sealed record DeleteAccount(string AccountId) : AuthorityEdit;

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
