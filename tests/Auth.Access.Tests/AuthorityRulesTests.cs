namespace TheKrystalShip.KGSM.Auth.Access.Tests;

/// <summary>
/// Who may change who may do what: the action each change needs, subset, ranking, the permission
/// rule, and Owner's guards.
/// </summary>
public class AuthorityRulesTests
{
    /// <summary>
    /// A cluster with an Owner, a moderator at rank 1 holding the admin actions and some operational
    /// ones, a helper at rank 2 below them, and a plain person.
    /// </summary>
    private sealed class Cluster
    {
        public World World { get; } = new();
        public string Owner { get; }
        public string Mod { get; }
        public string Helper { get; }
        public string Bob { get; }
        public string ModRole { get; }
        public string HelperRole { get; }

        public Cluster()
        {
            Owner = World.Owner();
            Mod = World.Person("mod");
            Helper = World.Person("helper");
            Bob = World.Person("bob");

            ModRole = World.Role("Moderator", 1,
                AuthActions.RolesEdit, AuthActions.PermissionsEdit, AuthActions.RolesAssign,
                AuthActions.ServicesManage, AuthActions.AccountsDisable, AuthActions.AccountsDelete,
                World.Start, World.Console);
            HelperRole = World.Role("Helper", 2, World.Console);

            World.Assign(Mod, ModRole, AccessScope.Cluster);
            World.Assign(Helper, HelperRole, AccessScope.Cluster);
        }
    }

    private static void Refused(RefusalCode code, AuthorityRefusal? refusal)
    {
        Assert.NotNull(refusal);
        Assert.Equal(code, refusal.Code);
    }

    // ── every change needs its action ─────────────────────────────────────────────────────────

    [Fact]
    public void EveryChangeNeedsItsAuthActionAtItsScope()
    {
        Cluster c = new();

        Refused(RefusalCode.NotPermitted, c.World.Check(c.Bob, new CreateRole("Mine")));
        Refused(RefusalCode.NotPermitted, c.World.Check(c.Bob, new CreatePermission("Mine")));
        Refused(RefusalCode.NotPermitted, c.World.Check(c.Bob, new Assign(c.Bob, c.HelperRole, World.Terraria)));
        Refused(RefusalCode.NotPermitted, c.World.Check(c.Bob, new DisableAccount(c.Helper)));
        Refused(RefusalCode.NotPermitted, c.World.Check(c.Bob, new DeleteAccount(c.Helper)));
    }

    [Fact]
    public void AStaleReplicaRefusesEveryChangeToAnOwnerToo()
    {
        Cluster c = new();
        c.World.Freshness = AuthorityFreshness.Replica(null, TimeSpan.FromMinutes(5));

        Refused(RefusalCode.NotPermitted, c.World.Check(c.Owner, new CreateRole("Mine")));
    }

    [Fact]
    public void ADisabledOwnerIsExemptFromNothing()
    {
        World world = new();
        string gone = world.Person("gone", AccountStatus.Disabled);
        world.Assign(gone, BuiltInRoles.OwnerId, AccessScope.Cluster);

        Refused(RefusalCode.NotPermitted, world.Check(gone, new CreateRole("Mine")));
    }

    // ── roles ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ANewRoleLandsDirectlyBelowItsCreatorsHighestRole()
    {
        Cluster c = new();
        AuthoritySnapshot snapshot = c.World.Snapshot();

        Assert.Null(c.World.Check(c.Mod, new CreateRole("Trusted")));
        Assert.Equal(2, AuthorityRules.CreationRank(snapshot, c.Mod));
        Assert.Equal(RoleRanks.FirstCustom, AuthorityRules.CreationRank(snapshot, c.Owner));
    }

    [Fact]
    public void SomebodyWhoseHighestRoleIsEveryoneCannotCreateARole()
    {
        World world = new();
        world.Owner();
        world.Everyone(AuthActions.RolesEdit);
        string bob = world.Person("bob");

        Refused(RefusalCode.RankNotBelow, world.Check(bob, new CreateRole("Mine")));
    }

    [Theory]
    [InlineData("helper")]
    [InlineData("  HELPER ")]
    [InlineData("owner")]
    [InlineData("Everyone")]
    public void RoleNamesAreUniqueCaseInsensitivelyBuiltInsIncluded(string name)
    {
        Cluster c = new();

        Refused(RefusalCode.DuplicateName, c.World.Check(c.Owner, new CreateRole(name)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("a\nb")]
    public void ARoleNeedsAName(string name)
    {
        Cluster c = new();

        Refused(RefusalCode.InvalidName, c.World.Check(c.Owner, new CreateRole(name)));
    }

    [Fact]
    public void RenamingARoleToItsOwnNameInAnotherCaseIsNotADuplicate()
    {
        Cluster c = new();

        Assert.Null(c.World.Check(c.Mod, new RenameRole(c.HelperRole, "HELPER")));
    }

    [Fact]
    public void RolesAreEditedOnlyBelowTheCallersHighestRole()
    {
        Cluster c = new();

        Assert.Null(c.World.Check(c.Mod, new RenameRole(c.HelperRole, "Helpers")));
        Assert.Null(c.World.Check(c.Mod, new DeleteRole(c.HelperRole)));
        Refused(RefusalCode.RankNotBelow, c.World.Check(c.Mod, new RenameRole(c.ModRole, "Mods")));
        Refused(RefusalCode.RankNotBelow, c.World.Check(c.Mod, new DeleteRole(c.ModRole)));
    }

    [Fact]
    public void TheBuiltInRolesAreNeitherRenamedDeletedNorRanked()
    {
        Cluster c = new();

        Refused(RefusalCode.BuiltInRole, c.World.Check(c.Owner, new RenameRole(BuiltInRoles.OwnerId, "Boss")));
        Refused(RefusalCode.BuiltInRole, c.World.Check(c.Owner, new DeleteRole(BuiltInRoles.OwnerId)));
        Refused(RefusalCode.BuiltInRole, c.World.Check(c.Owner, new DeleteRole(BuiltInRoles.EveryoneId)));
        Refused(RefusalCode.BuiltInRole, c.World.Check(c.Owner, new RankRole(BuiltInRoles.EveryoneId, 1)));
        Refused(RefusalCode.BuiltInRole,
            c.World.Check(c.Owner, new SetRolePermissions(BuiltInRoles.OwnerId, new HashSet<string>())));
    }

    [Fact]
    public void EveryonesPermissionsAreEditable()
    {
        Cluster c = new();
        string library = c.World.Permission("Library", World.Library);

        Assert.Null(c.World.Check(c.Owner, new SetRolePermissions(BuiltInRoles.EveryoneId, new HashSet<string> { library })));
    }

    [Fact]
    public void ARoleIsNeverRaisedToOrAboveTheCallersOwn()
    {
        Cluster c = new();

        Refused(RefusalCode.RankNotBelow, c.World.Check(c.Mod, new RankRole(c.HelperRole, 1)));
        Assert.Null(c.World.Check(c.Mod, new RankRole(c.HelperRole, 2)));
        Assert.Null(c.World.Check(c.Owner, new RankRole(c.HelperRole, 1)));
    }

    [Fact]
    public void ARankIsAPlaceAmongTheCustomRoles()
    {
        Cluster c = new();

        Refused(RefusalCode.InvalidRank, c.World.Check(c.Owner, new RankRole(c.HelperRole, 0)));
        Refused(RefusalCode.InvalidRank, c.World.Check(c.Owner, new RankRole(c.HelperRole, 3)));
    }

    [Fact]
    public void ARoleIsGivenOnlyActionsTheCallerHoldsAtClusterScope()
    {
        Cluster c = new();
        string thresholds = c.World.Permission("Thresholds", World.Thresholds);
        string console = c.World.Permission("Consoles", World.Console);

        AuthorityRefusal? refusal = c.World.Check(c.Mod,
            new SetRolePermissions(c.HelperRole, new HashSet<string> { thresholds, console }));

        Refused(RefusalCode.NotHeld, refusal);
        Assert.Equal([World.Thresholds], refusal!.Actions);
    }

    [Fact]
    public void RemovingPermissionsFromARoleNeedsNoSubset()
    {
        Cluster c = new();

        Assert.Null(c.World.Check(c.Mod, new SetRolePermissions(c.HelperRole, new HashSet<string>())));
    }

    [Fact]
    public void AnOwnerIsOutsideSubsetAndRanking()
    {
        Cluster c = new();
        string thresholds = c.World.Permission("Thresholds", World.Thresholds);

        Assert.Null(c.World.Check(c.Owner, new SetRolePermissions(c.ModRole, new HashSet<string> { thresholds })));
        Assert.Null(c.World.Check(c.Owner, new DeleteRole(c.ModRole)));
    }

    // ── permissions ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void APermissionIsEditedOnlyWhenEveryRoleHoldingItRanksBelowTheCaller()
    {
        Cluster c = new();
        string shared = c.World.Permission("Shared", World.Console);

        // Held by no role: editable. Held by the moderator's own role: not, because editing it would
        // change that role.
        Assert.Null(c.World.Check(c.Mod, new RenamePermission(shared, "Consoles")));

        World world = c.World;
        AuthoritySnapshot snapshot = world.Snapshot();
        Role mod = snapshot.Roles[c.ModRole];
        AuthoritySnapshot held = new(
            snapshot.Version, snapshot.Accounts.Values, snapshot.Catalog.Values, snapshot.Permissions.Values,
            snapshot.Roles.Values.Select(r => r.RoleId == c.ModRole
                ? mod with { Permissions = new HashSet<string>(mod.Permissions) { shared } }
                : r),
            snapshot.Assignments, snapshot.Requirements, snapshot.Freshness);

        Refused(RefusalCode.PermissionHeldAbove, AuthorityRules.Check(held, c.Mod, new RenamePermission(shared, "Consoles"), world.Clock));
        Refused(RefusalCode.PermissionHeldAbove, AuthorityRules.Check(held, c.Mod, new DeletePermission(shared), world.Clock));
        Refused(RefusalCode.PermissionHeldAbove,
            AuthorityRules.Check(held, c.Mod, new SetPermissionActions(shared, new HashSet<string>()), world.Clock));
        Assert.Null(AuthorityRules.Check(held, c.Owner, new DeletePermission(shared), world.Clock));
    }

    [Fact]
    public void TwoPeopleWhoCanEditPermissionsCannotEmptyEachOthersRolesThroughOneTheyShare()
    {
        World world = new();
        world.Owner();
        string ann = world.Person("ann");
        string ben = world.Person("ben");
        string shared = world.Permission("Shared", AuthActions.PermissionsEdit, World.Start);
        string annRole = "role_ann";
        string benRole = "role_ben";
        AuthoritySnapshot baseline = world.Snapshot();
        AuthoritySnapshot snapshot = new(
            baseline.Version, baseline.Accounts.Values, baseline.Catalog.Values, baseline.Permissions.Values,
            [
                .. baseline.Roles.Values,
                new Role(annRole, "Ann", RoleKind.Custom, 1, new HashSet<string> { shared }),
                new Role(benRole, "Ben", RoleKind.Custom, 2, new HashSet<string> { shared }),
            ],
            [
                .. baseline.Assignments,
                new Assignment("asg_a", ann, annRole, AccessScope.Cluster),
                new Assignment("asg_b", ben, benRole, AccessScope.Cluster),
            ],
            baseline.Requirements, baseline.Freshness);

        Refused(RefusalCode.PermissionHeldAbove,
            AuthorityRules.Check(snapshot, ann, new SetPermissionActions(shared, new HashSet<string>()), world.Clock));
        Refused(RefusalCode.PermissionHeldAbove,
            AuthorityRules.Check(snapshot, ben, new SetPermissionActions(shared, new HashSet<string>()), world.Clock));
    }

    [Fact]
    public void OnlyDeclaredNonSelfActionsAreFiledIntoAPermission()
    {
        Cluster c = new();
        string permission = c.World.Permission("New");

        Refused(RefusalCode.NotFileable,
            c.World.Check(c.Owner, new SetPermissionActions(permission, new HashSet<string> { "reactor:rules.write" })));
        Refused(RefusalCode.NotFileable,
            c.World.Check(c.Owner, new SetPermissionActions(permission, new HashSet<string> { World.Prefs })));
        Assert.Null(c.World.Check(c.Owner, new SetPermissionActions(permission, new HashSet<string> { World.Thresholds })));
    }

    [Fact]
    public void APermissionIsGivenOnlyActionsTheCallerHolds()
    {
        Cluster c = new();
        string permission = c.World.Permission("New");

        Refused(RefusalCode.NotHeld,
            c.World.Check(c.Mod, new SetPermissionActions(permission, new HashSet<string> { World.Thresholds })));
        Assert.Null(c.World.Check(c.Mod, new SetPermissionActions(permission, new HashSet<string> { World.Console })));
    }

    [Fact]
    public void PermissionNamesAreUnique()
    {
        Cluster c = new();
        c.World.Permission("Consoles");

        Refused(RefusalCode.DuplicateName, c.World.Check(c.Mod, new CreatePermission("consoles")));
    }

    // ── assignments ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AssigningIsRankedAndSubsetAtTheAssignmentsScope()
    {
        Cluster c = new();

        Assert.Null(c.World.Check(c.Mod, new Assign(c.Bob, c.HelperRole, World.Terraria)));
        Refused(RefusalCode.RankNotBelow, c.World.Check(c.Mod, new Assign(c.Bob, c.ModRole, World.Terraria)));
    }

    [Fact]
    public void TheTerrariaAdminCanHandTerrariaAccessToAFriend()
    {
        World world = new();
        world.Owner();
        string host = world.Person("host");
        string friend = world.Person("friend");
        string runner = world.Role("Terraria admin", 1, AuthActions.RolesAssign, World.Start, World.Console);
        string player = world.Role("Terraria player", 2, World.Console);
        world.Assign(host, runner, World.Terraria);

        Assert.Null(world.Check(host, new Assign(friend, player, World.Terraria)));
        Refused(RefusalCode.NotPermitted, world.Check(host, new Assign(friend, player, World.Factorio)));
        Refused(RefusalCode.NotPermitted, world.Check(host, new Assign(friend, player, World.Walter)));
    }

    [Fact]
    public void AnAssignmentCarriesOnlyActionsTheAssignerHoldsThere()
    {
        World world = new();
        world.Owner();
        string host = world.Person("host");
        string friend = world.Person("friend");
        world.Assign(host, world.Role("Terraria admin", 1, AuthActions.RolesAssign, World.Console), World.Terraria);
        string runner = world.Role("Runner", 2, World.Start, World.Console);

        AuthorityRefusal? refusal = world.Check(host, new Assign(friend, runner, World.Terraria));

        Refused(RefusalCode.NotHeld, refusal);
        Assert.Equal([World.Start], refusal!.Actions);
    }

    [Fact]
    public void TheSubsetCountsOnlyActionsTheAssignmentActuallyGrantsAtItsScope()
    {
        World world = new();
        world.Owner();
        string host = world.Person("host");
        string friend = world.Person("friend");
        world.Assign(host, world.Role("Terraria admin", 1, AuthActions.RolesAssign, World.Console), World.Terraria);
        // The library is a cluster action: assigned at an instance it grants nothing, so the host
        // need not hold it to hand this role out there.
        string viewer = world.Role("Viewer", 2, World.Console, World.Library);

        Assert.Null(world.Check(host, new Assign(friend, viewer, World.Terraria)));
    }

    [Fact]
    public void OnlyAnOwnerGrantsOwnerAndOnlyAtClusterScopeAndOnlyToAPerson()
    {
        Cluster c = new();
        string reactor = c.World.Service("reactor", "walter");

        Refused(RefusalCode.OwnerOnly, c.World.Check(c.Mod, new Assign(c.Bob, BuiltInRoles.OwnerId, AccessScope.Cluster)));
        Refused(RefusalCode.InvalidScope, c.World.Check(c.Owner, new Assign(c.Bob, BuiltInRoles.OwnerId, World.Walter)));
        Refused(RefusalCode.WrongAccountKind, c.World.Check(c.Owner, new Assign(reactor, BuiltInRoles.OwnerId, AccessScope.Cluster)));
        Assert.Null(c.World.Check(c.Owner, new Assign(c.Bob, BuiltInRoles.OwnerId, AccessScope.Cluster)));
    }

    [Fact]
    public void EveryoneIsNeverAssigned()
    {
        Cluster c = new();

        Refused(RefusalCode.BuiltInRole, c.World.Check(c.Owner, new Assign(c.Bob, BuiltInRoles.EveryoneId, AccessScope.Cluster)));
    }

    [Fact]
    public void TheSameRoleAtTheSameScopeIsNotAssignedTwice()
    {
        Cluster c = new();

        Refused(RefusalCode.DuplicateAssignment, c.World.Check(c.Owner, new Assign(c.Helper, c.HelperRole, AccessScope.Cluster)));
        Assert.Null(c.World.Check(c.Owner, new Assign(c.Helper, c.HelperRole, World.Terraria)));
    }

    [Fact]
    public void AssigningNamesThingsThatExist()
    {
        Cluster c = new();

        Refused(RefusalCode.NotFound, c.World.Check(c.Owner, new Assign("usr_nobody", c.HelperRole, AccessScope.Cluster)));
        Refused(RefusalCode.NotFound, c.World.Check(c.Owner, new Assign(c.Bob, "role_nothing", AccessScope.Cluster)));
    }

    [Fact]
    public void RevokingIsRankedAtTheAssignmentsScope()
    {
        Cluster c = new();
        string helper = c.World.Snapshot().AssignmentsOf(c.Helper).Single().AssignmentId;
        string mod = c.World.Snapshot().AssignmentsOf(c.Mod).Single().AssignmentId;

        Assert.Null(c.World.Check(c.Mod, new Revoke(helper)));
        Refused(RefusalCode.RankNotBelow, c.World.Check(c.Mod, new Revoke(mod)));
        Refused(RefusalCode.NotPermitted, c.World.Check(c.Helper, new Revoke(helper)));
    }

    [Fact]
    public void OnlyAnOwnerRevokesOwner()
    {
        Cluster c = new();
        string owner = c.World.Snapshot().AssignmentsOf(c.Owner).Single().AssignmentId;

        Refused(RefusalCode.OwnerOnly, c.World.Check(c.Mod, new Revoke(owner)));
    }

    [Fact]
    public void TheLastActiveOwnerCannotBeRevokedDisabledOrDeleted()
    {
        Cluster c = new();
        string owner = c.World.Snapshot().AssignmentsOf(c.Owner).Single().AssignmentId;

        Refused(RefusalCode.LastOwner, c.World.Check(c.Owner, new Revoke(owner)));
        Refused(RefusalCode.LastOwner, c.World.Check(c.Owner, new DisableAccount(c.Owner)));
        Refused(RefusalCode.LastOwner, c.World.Check(c.Owner, new DeleteAccount(c.Owner)));
    }

    [Fact]
    public void ADisabledSecondOwnerDoesNotCountTowardTheLast()
    {
        Cluster c = new();
        string asleep = c.World.Person("asleep", AccountStatus.Disabled);
        c.World.Assign(asleep, BuiltInRoles.OwnerId, AccessScope.Cluster);

        Refused(RefusalCode.LastOwner, c.World.Check(c.Owner, new DeleteAccount(c.Owner)));
    }

    [Fact]
    public void AnOwnerIsRemovableOnceAnotherActiveOwnerExists()
    {
        Cluster c = new();
        string second = c.World.Owner("second");
        string first = c.World.Snapshot().AssignmentsOf(c.Owner).Single().AssignmentId;

        Assert.Null(c.World.Check(second, new Revoke(first)));
        Assert.Null(c.World.Check(second, new DeleteAccount(c.Owner)));
        Assert.Null(c.World.Check(c.Owner, new DisableAccount(c.Owner)));
    }

    [Fact]
    public void OnlyAnOwnerDisablesOrDeletesAnOwnersAccount()
    {
        Cluster c = new();
        c.World.Owner("second");

        Refused(RefusalCode.OwnerOnly, c.World.Check(c.Mod, new DisableAccount(c.Owner)));
        Refused(RefusalCode.OwnerOnly, c.World.Check(c.Mod, new DeleteAccount(c.Owner)));
        Assert.Null(c.World.Check(c.Mod, new DisableAccount(c.Bob)));
    }

    [Fact]
    public void AServiceAccountIsNeverDeletedByHand()
    {
        Cluster c = new();
        string reactor = c.World.Service("reactor", "walter");

        Refused(RefusalCode.WrongAccountKind, c.World.Check(c.Owner, new DeleteAccount(reactor)));
        Assert.Null(c.World.Check(c.Owner, new DisableAccount(reactor)));
    }

    // ── service requirements ──────────────────────────────────────────────────────────────────

    [Fact]
    public void OnlyAnOwnerApprovesAnAuthRequirement()
    {
        Cluster c = new();
        string assistant = c.World.Service("assistant", "hotrod-assistant");
        c.World.Require(assistant, AuthActions.AccountsApprove, null, RequirementState.Waiting, kind: ScopeKind.Cluster);

        Refused(RefusalCode.OwnerOnly,
            c.World.Check(c.Mod, new ApproveRequirement(assistant, AuthActions.AccountsApprove, AccessScope.Cluster)));
        Assert.Null(c.World.Check(c.Owner, new ApproveRequirement(assistant, AuthActions.AccountsApprove, AccessScope.Cluster)));
    }

    [Fact]
    public void ApprovingARequirementIsSubsetAtItsScope()
    {
        Cluster c = new();
        string reactor = c.World.Service("reactor", "walter");
        c.World.Require(reactor, World.Start, null, RequirementState.Revoked, decidedBy: "local:owner");
        c.World.Require(reactor, World.Thresholds, null, RequirementState.Revoked, decidedBy: "local:owner", kind: ScopeKind.Node);

        Assert.Null(c.World.Check(c.Mod, new ApproveRequirement(reactor, World.Start, World.Walter)));
        Refused(RefusalCode.NotHeld, c.World.Check(c.Mod, new ApproveRequirement(reactor, World.Thresholds, World.Walter)));
    }

    [Fact]
    public void ARequirementNarrowsOnlyInsideTheScopeItHolds()
    {
        Cluster c = new();
        string reactor = c.World.Service("reactor", "walter");
        c.World.Require(reactor, World.Start, World.Walter);

        Assert.Null(c.World.Check(c.Mod, new NarrowRequirement(reactor, World.Start, World.Terraria)));
        Refused(RefusalCode.InvalidScope, c.World.Check(c.Mod, new NarrowRequirement(reactor, World.Start, World.Walter)));
        Refused(RefusalCode.InvalidScope, c.World.Check(c.Mod, new NarrowRequirement(reactor, World.Start, AccessScope.Cluster)));
        Refused(RefusalCode.InvalidScope, c.World.Check(c.Mod, new NarrowRequirement(reactor, World.Start, World.JessieTerraria)));
    }

    [Fact]
    public void OnlyAnApprovedRequirementNarrowsAndARevokedOneIsNotRevokedTwice()
    {
        Cluster c = new();
        string reactor = c.World.Service("reactor", "walter");
        c.World.Require(reactor, World.Start, null, RequirementState.Revoked, decidedBy: "local:owner");

        Refused(RefusalCode.WrongRequirementState, c.World.Check(c.Mod, new NarrowRequirement(reactor, World.Start, World.Terraria)));
        Refused(RefusalCode.WrongRequirementState, c.World.Check(c.Mod, new RevokeRequirement(reactor, World.Start)));
    }

    [Fact]
    public void RequirementChangesNeedTheServicesManageActionAndAServiceAccount()
    {
        Cluster c = new();
        string reactor = c.World.Service("reactor", "walter");
        c.World.Require(reactor, World.Start, World.Walter);

        Refused(RefusalCode.NotPermitted, c.World.Check(c.Helper, new RevokeRequirement(reactor, World.Start)));
        Refused(RefusalCode.WrongAccountKind, c.World.Check(c.Owner, new RevokeRequirement(c.Bob, World.Start)));
        Refused(RefusalCode.NotFound, c.World.Check(c.Owner, new RevokeRequirement(reactor, World.Console)));
        Assert.Null(c.World.Check(c.Mod, new RevokeRequirement(reactor, World.Start)));
    }
}
