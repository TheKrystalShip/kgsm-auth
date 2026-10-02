namespace TheKrystalShip.KGSM.Auth.Access;

/// <summary>
/// Which changes to access a caller may make.
/// </summary>
/// <remarks>
/// <para>
/// Every change needs the <c>auth:*</c> action it is, held at its scope. Beyond that, two rules hold
/// per scope:
/// </para>
/// <list type="bullet">
/// <item>
///   <b>Subset.</b> A caller puts into a role, a permission, an assignment or a service's grant only
///   actions they hold at that scope or wider.
/// </item>
/// <item>
///   <b>Ranking.</b> A caller edits, ranks, assigns or removes only roles ranked below their own highest
///   role at that scope or wider, and never raises a role to or above their own.
/// </item>
/// </list>
/// <para>
/// A permission is edited only when every role holding it ranks below the caller, since editing it
/// changes all of them at once: two people who can edit permissions cannot empty each other's roles
/// through one they share.
/// </para>
/// <para>
/// An Owner is outside both rules. Only an Owner grants or revokes Owner, and the cluster never loses
/// its last active Owner. The checks are pure: they read a snapshot and change nothing.
/// </para>
/// </remarks>
public static class AuthorityRules
{
    /// <summary>The longest name a role or permission may have.</summary>
    public const int MaxNameLength = 64;

    /// <summary>
    /// Whether <paramref name="actorId"/> may make <paramref name="edit"/>. <see langword="null"/> means
    /// it may; otherwise the refusal says why.
    /// </summary>
    public static AuthorityRefusal? Check(AuthoritySnapshot snapshot, string actorId, AuthorityEdit edit, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(edit);

        Context c = new(snapshot, new AccessEvaluator(snapshot, clock), actorId);

        // The action first, from the edit's kind — the same entry the anchor publishes as the operation's
        // action, so what a client is told an edit needs is what is checked here. An edit about an
        // assignment is checked at that assignment's scope; one naming an assignment that does not
        // exist, cluster-wide, so an unknown id tells a caller nothing they could not already ask.
        AccessScope scope = edit switch
        {
            Assign a => a.Scope,
            Revoke r => snapshot.Assignments.FirstOrDefault(x => x.AssignmentId == r.AssignmentId)?.Scope ?? AccessScope.Cluster,
            _ => AccessScope.Cluster,
        };
        if (c.Lacks(edit.Kind.Action, scope) is { } refused)
            return refused;

        return edit switch
        {
            CreateRole e => CheckCreateRole(c, e),
            RenameRole e => CheckRenameRole(c, e),
            DeleteRole e => CheckRoleChange(c, e.RoleId, out _),
            RankRole e => CheckRankRole(c, e),
            SetRolePermissions e => CheckSetRolePermissions(c, e),
            CreatePermission e => CheckCreatePermission(c, e),
            RenamePermission e => CheckRenamePermission(c, e),
            DeletePermission e => CheckPermissionChange(c, e.PermissionId, out _),
            SetPermissionActions e => CheckSetPermissionActions(c, e),
            Assign e => CheckAssign(c, e),
            Revoke e => CheckRevoke(c, e),
            ApproveRequirement e => CheckApproveRequirement(c, e),
            NarrowRequirement e => CheckNarrowRequirement(c, e),
            RevokeRequirement e => CheckRevokeRequirement(c, e),
            DisableAccount e => CheckAccountRemoval(c, e.AccountId, deleting: false),
            DeleteAccount e => CheckAccountRemoval(c, e.AccountId, deleting: true),
            _ => throw new ArgumentOutOfRangeException(nameof(edit), edit.GetType().Name, "Not an authority edit."),
        };
    }

    /// <summary>
    /// The rank a role <paramref name="actorId"/> creates is given: directly below their own highest
    /// role at cluster scope. An Owner's lands first among the custom roles.
    /// </summary>
    public static int CreationRank(AuthoritySnapshot snapshot, string actorId) =>
        TopRank(snapshot, actorId, AccessScope.Cluster) + 1;

    /// <summary>
    /// The highest-ranked role <paramref name="accountId"/> holds at <paramref name="scope"/> or wider,
    /// as a rank: lower is higher. <c>everyone</c> counts for an active person.
    /// </summary>
    public static int TopRank(AuthoritySnapshot snapshot, string accountId, AccessScope scope)
    {
        if (!snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account))
            return RoleRanks.Service;

        int top = account.Kind == AccountKind.Person && account.Status == AccountStatus.Active
            ? RoleRanks.Everyone
            : RoleRanks.Service;

        foreach (Assignment assignment in snapshot.AssignmentsOf(accountId))
        {
            if (assignment.Scope.Contains(scope) && snapshot.Roles.TryGetValue(assignment.RoleId, out Role? role))
                top = Math.Min(top, role.Rank);
        }

        return top;
    }

    // ── roles ─────────────────────────────────────────────────────────────────────────────────

    private static AuthorityRefusal? CheckCreateRole(Context c, CreateRole e)
    {
        if (NameProblem(e.Name, c.Snapshot.Roles.Values.Select(r => (r.RoleId, r.Name)), except: null) is { } bad)
            return bad;

        if (!c.IsOwner && c.Top(AccessScope.Cluster) >= RoleRanks.Everyone)
        {
            return new AuthorityRefusal(RefusalCode.RankNotBelow,
                "A new role is created directly below your own highest role, and you hold no role above everyone.");
        }

        return null;
    }

    private static AuthorityRefusal? CheckRenameRole(Context c, RenameRole e)
    {
        if (CheckRoleChange(c, e.RoleId, out _) is { } refused)
            return refused;

        return NameProblem(e.Name, c.Snapshot.Roles.Values.Select(r => (r.RoleId, r.Name)), except: e.RoleId);
    }

    /// <summary>
    /// The checks every change to one role shares: that it exists, that it is not a built-in, and that
    /// it ranks below the caller.
    /// </summary>
    private static AuthorityRefusal? CheckRoleChange(Context c, string roleId, out Role? role, bool everyoneEditable = false)
    {
        role = null;
        if (!c.Snapshot.Roles.TryGetValue(roleId, out role))
            return NotFound("role", roleId);

        if (role.Kind == RoleKind.Owner || (role.Kind == RoleKind.Everyone && !everyoneEditable))
            return new AuthorityRefusal(RefusalCode.BuiltInRole, $"'{role.Name}' is built in and cannot be changed that way.");

        return c.RankBelow(role, AccessScope.Cluster);
    }

    private static AuthorityRefusal? CheckRankRole(Context c, RankRole e)
    {
        if (CheckRoleChange(c, e.RoleId, out _) is { } refused)
            return refused;

        int customs = c.Snapshot.Roles.Values.Count(r => r.Kind == RoleKind.Custom);
        if (e.Rank < RoleRanks.FirstCustom || e.Rank > customs)
            return new AuthorityRefusal(RefusalCode.InvalidRank, $"A rank runs from {RoleRanks.FirstCustom} to {customs}.");

        if (!c.IsOwner && e.Rank <= c.Top(AccessScope.Cluster))
        {
            return new AuthorityRefusal(RefusalCode.RankNotBelow,
                "A role cannot be raised to or above your own highest role.");
        }

        return null;
    }

    private static AuthorityRefusal? CheckSetRolePermissions(Context c, SetRolePermissions e)
    {
        if (CheckRoleChange(c, e.RoleId, out Role? role, everyoneEditable: true) is { } refused)
            return refused;

        foreach (string permissionId in e.PermissionIds)
        {
            if (!c.Snapshot.Permissions.ContainsKey(permissionId))
                return NotFound("permission", permissionId);
        }

        IEnumerable<string> added = e.PermissionIds
            .Where(p => !role!.Permissions.Contains(p))
            .SelectMany(p => c.Snapshot.Permissions[p].Actions);

        return c.Subset(added, AccessScope.Cluster);
    }

    // ── permissions ───────────────────────────────────────────────────────────────────────────

    private static AuthorityRefusal? CheckCreatePermission(Context c, CreatePermission e)
    {
        return NameProblem(e.Name, c.Snapshot.Permissions.Values.Select(p => (p.PermissionId, p.Name)), except: null);
    }

    private static AuthorityRefusal? CheckRenamePermission(Context c, RenamePermission e)
    {
        if (CheckPermissionChange(c, e.PermissionId, out _) is { } refused)
            return refused;

        return NameProblem(e.Name, c.Snapshot.Permissions.Values.Select(p => (p.PermissionId, p.Name)), except: e.PermissionId);
    }

    /// <summary>
    /// The checks every change to one permission shares: that it exists, and that every role holding it
    /// ranks below the caller.
    /// </summary>
    private static AuthorityRefusal? CheckPermissionChange(Context c, string permissionId, out Permission? permission)
    {
        permission = null;
        if (!c.Snapshot.Permissions.TryGetValue(permissionId, out permission))
            return NotFound("permission", permissionId);

        if (c.IsOwner)
            return null;

        int top = c.Top(AccessScope.Cluster);
        Role? above = c.Snapshot.RolesHolding(permissionId).FirstOrDefault(r => r.Rank <= top);
        if (above is not null)
        {
            return new AuthorityRefusal(RefusalCode.PermissionHeldAbove,
                $"'{permission.Name}' is held by '{above.Name}', which does not rank below your highest role.");
        }

        return null;
    }

    private static AuthorityRefusal? CheckSetPermissionActions(Context c, SetPermissionActions e)
    {
        if (CheckPermissionChange(c, e.PermissionId, out Permission? permission) is { } refused)
            return refused;

        foreach (string action in e.Actions)
        {
            if (!c.Snapshot.Catalog.TryGetValue(action, out CatalogAction? declared))
                return new AuthorityRefusal(RefusalCode.NotFileable, $"No member declares '{action}'.");

            if (declared.Self)
            {
                return new AuthorityRefusal(RefusalCode.NotFileable,
                    $"'{action}' acts only on the caller's own records; every person holds it already.");
            }
        }

        return c.Subset(e.Actions.Where(a => !permission!.Actions.Contains(a)), AccessScope.Cluster);
    }

    // ── assignments ───────────────────────────────────────────────────────────────────────────

    private static AuthorityRefusal? CheckAssign(Context c, Assign e)
    {
        if (!c.Snapshot.Accounts.TryGetValue(e.AccountId, out AccessAccount? account))
            return NotFound("account", e.AccountId);

        if (!c.Snapshot.Roles.TryGetValue(e.RoleId, out Role? role))
            return NotFound("role", e.RoleId);

        if (role.Kind == RoleKind.Everyone)
            return new AuthorityRefusal(RefusalCode.BuiltInRole, "Every active person holds everyone already; it is never assigned.");

        if (role.Kind == RoleKind.Owner)
        {
            if (!c.IsOwner)
                return new AuthorityRefusal(RefusalCode.OwnerOnly, "Only an Owner grants Owner.");

            if (e.Scope.Kind != ScopeKind.Cluster)
                return new AuthorityRefusal(RefusalCode.InvalidScope, "Owner is held across the whole cluster.");

            if (account.Kind != AccountKind.Person)
                return new AuthorityRefusal(RefusalCode.WrongAccountKind, "Owner is held by people, never by a service.");
        }
        else if (c.RankBelow(role, e.Scope) is { } rank)
        {
            return rank;
        }

        IEnumerable<string> granted = c.Snapshot.ActionsOf(role.RoleId).Where(a =>
            c.Snapshot.Catalog.TryGetValue(a, out CatalogAction? declared) && declared.Scope >= e.Scope.Kind);

        if (c.Subset(granted, e.Scope) is { } notHeld)
            return notHeld;

        bool duplicate = c.Snapshot.AssignmentsOf(e.AccountId).Any(a => a.RoleId == e.RoleId && a.Scope == e.Scope);
        return duplicate
            ? new AuthorityRefusal(RefusalCode.DuplicateAssignment, $"{account.Name} already holds '{role.Name}' at {e.Scope}.")
            : null;
    }

    private static AuthorityRefusal? CheckRevoke(Context c, Revoke e)
    {
        Assignment? assignment = c.Snapshot.Assignments.FirstOrDefault(a => a.AssignmentId == e.AssignmentId);
        if (assignment is null)
            return NotFound("assignment", e.AssignmentId);

        if (!c.Snapshot.Roles.TryGetValue(assignment.RoleId, out Role? role))
            return NotFound("role", assignment.RoleId);

        if (role.Kind == RoleKind.Owner)
        {
            if (!c.IsOwner)
                return new AuthorityRefusal(RefusalCode.OwnerOnly, "Only an Owner revokes Owner.");

            return LastOwner(c, assignment.AccountId);
        }

        return c.RankBelow(role, assignment.Scope);
    }

    // ── service requirements ──────────────────────────────────────────────────────────────────

    private static AuthorityRefusal? RequirementChange(Context c, string accountId, string action, out ServiceRequirement? requirement)
    {
        requirement = null;
        if (!c.Snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account))
            return NotFound("account", accountId);

        if (account.Kind != AccountKind.Service)
            return new AuthorityRefusal(RefusalCode.WrongAccountKind, $"{account.Name} is not a service account.");

        requirement = c.Snapshot.RequirementsOf(accountId).FirstOrDefault(r => r.Action == action);
        return requirement is null ? NotFound("requirement", action) : null;
    }

    private static AuthorityRefusal? CheckApproveRequirement(Context c, ApproveRequirement e)
    {
        if (RequirementChange(c, e.AccountId, e.Action, out _) is { } refused)
            return refused;

        if (ActionIds.IsAuth(e.Action) && !c.IsOwner)
            return new AuthorityRefusal(RefusalCode.OwnerOnly, $"Only an Owner approves '{e.Action}' for a service.");

        return c.Subset([e.Action], e.Scope);
    }

    private static AuthorityRefusal? CheckNarrowRequirement(Context c, NarrowRequirement e)
    {
        if (RequirementChange(c, e.AccountId, e.Action, out ServiceRequirement? requirement) is { } refused)
            return refused;

        if (requirement!.State != RequirementState.Approved || requirement.Grant is not { } grant)
            return new AuthorityRefusal(RefusalCode.WrongRequirementState, $"'{e.Action}' is not approved, so there is nothing to narrow.");

        if (grant == e.Scope || !grant.Contains(e.Scope))
            return new AuthorityRefusal(RefusalCode.InvalidScope, $"{e.Scope} is not inside {grant}.");

        return null;
    }

    private static AuthorityRefusal? CheckRevokeRequirement(Context c, RevokeRequirement e)
    {
        if (RequirementChange(c, e.AccountId, e.Action, out ServiceRequirement? requirement) is { } refused)
            return refused;

        return requirement!.State == RequirementState.Revoked
            ? new AuthorityRefusal(RefusalCode.WrongRequirementState, $"'{e.Action}' is already revoked.")
            : null;
    }

    // ── accounts ──────────────────────────────────────────────────────────────────────────────

    private static AuthorityRefusal? CheckAccountRemoval(Context c, string accountId, bool deleting)
    {
        if (!c.Snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account))
            return NotFound("account", accountId);

        if (deleting && account.Kind == AccountKind.Service)
        {
            return new AuthorityRefusal(RefusalCode.WrongAccountKind,
                "A service account is forgotten when its component stops being reported, never by hand.");
        }

        if (!c.Snapshot.IsOwner(accountId))
            return null;

        if (!c.IsOwner)
            return new AuthorityRefusal(RefusalCode.OwnerOnly, $"{account.Name} is an Owner; only an Owner acts on an Owner's account.");

        return LastOwner(c, accountId);
    }

    private static AuthorityRefusal? LastOwner(Context c, string accountId)
    {
        bool others = c.Snapshot.ActiveOwners().Any(id => id != accountId);
        bool isActive = c.Snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account) && account.Status == AccountStatus.Active;

        return isActive && !others
            ? new AuthorityRefusal(RefusalCode.LastOwner, "The cluster would be left with no active Owner.")
            : null;
    }

    // ── plumbing ──────────────────────────────────────────────────────────────────────────────

    private static AuthorityRefusal? NameProblem(string name, IEnumerable<(string Id, string Name)> existing, string? except)
    {
        string trimmed = name?.Trim() ?? string.Empty;
        if (trimmed.Length == 0 || trimmed.Length > MaxNameLength || trimmed.Any(char.IsControl))
            return new AuthorityRefusal(RefusalCode.InvalidName, $"A name is 1 to {MaxNameLength} characters.");

        foreach ((string id, string other) in existing)
        {
            if (id != except && string.Equals(NameKey(other), NameKey(trimmed), StringComparison.Ordinal))
                return new AuthorityRefusal(RefusalCode.DuplicateName, $"'{other}' already exists.");
        }

        return null;
    }

    /// <summary>The form a role or permission name is compared in: trimmed, case-insensitive.</summary>
    public static string NameKey(string name) => name.Trim().ToLowerInvariant();

    private static AuthorityRefusal NotFound(string what, string id) =>
        new(RefusalCode.NotFound, $"No {what} '{id}'.");

    /// <summary>The caller and the snapshot, with the questions every rule asks of them.</summary>
    private sealed class Context(AuthoritySnapshot snapshot, AccessEvaluator evaluator, string actorId)
    {
        public AuthoritySnapshot Snapshot { get; } = snapshot;

        /// <summary>
        /// Whether the caller is an Owner who can use it right now. Evaluated through the evaluator, so
        /// an Owner on a stale replica or a disabled account is exempt from nothing.
        /// </summary>
        public bool IsOwner { get; } =
            snapshot.IsOwner(actorId) && evaluator.Allows(actorId, AuthActions.RolesEdit, AccessScope.Cluster).Allowed;

        public int Top(AccessScope scope) => TopRank(Snapshot, actorId, scope);

        public AuthorityRefusal? Lacks(string action, AccessScope scope)
        {
            AccessDecision decision = evaluator.Allows(actorId, action, scope);
            return decision.Allowed
                ? null
                : new AuthorityRefusal(RefusalCode.NotPermitted, $"You do not hold '{action}' at {scope} ({decision.Reason}).");
        }

        public AuthorityRefusal? RankBelow(Role role, AccessScope scope)
        {
            if (IsOwner || role.Rank > Top(scope))
                return null;

            return new AuthorityRefusal(RefusalCode.RankNotBelow,
                $"'{role.Name}' does not rank below your highest role at {scope}.");
        }

        public AuthorityRefusal? Subset(IEnumerable<string> actions, AccessScope scope)
        {
            if (IsOwner)
                return null;

            string[] missing = actions
                .Distinct(StringComparer.Ordinal)
                .Where(a => !evaluator.Allows(actorId, a, scope).Allowed)
                .Order(StringComparer.Ordinal)
                .ToArray();

            return missing.Length == 0
                ? null
                : new AuthorityRefusal(RefusalCode.NotHeld,
                    $"You do not hold {string.Join(", ", missing)} at {scope}.", missing);
        }
    }
}
