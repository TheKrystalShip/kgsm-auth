namespace TheKrystalShip.KGSM.Auth.Access.Tests;

/// <summary>
/// The order of questions every evaluation asks, one step at a time.
/// </summary>
public class AccessEvaluatorTests
{
    // ── contract ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AMemberBelowTheClustersMinimumContractRefusesToEvaluate()
    {
        World world = new() { MinimumContract = AccessContract.Version + 1 };
        string owner = world.Owner();

        AccessDecision decision = world.Evaluator().Allows(owner, World.Library, AccessScope.Cluster);

        Assert.Equal(DenyReason.ContractOutdated, decision.Reason);
    }

    // ── 1 · the account ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AnUnknownAccountHoldsNothing()
    {
        World world = new();

        Assert.Equal(DenyReason.NoAccount, world.Evaluator().Allows("usr_nobody", World.Library, AccessScope.Cluster).Reason);
    }

    [Fact]
    public void APendingAccountHoldsNothingNotEvenEveryoneOrSelf()
    {
        World world = new();
        world.Everyone(World.Library);
        string pending = world.Person("newcomer", AccountStatus.Pending);

        AccessEvaluator evaluator = world.Evaluator();

        Assert.Equal(DenyReason.AccountPending, evaluator.Allows(pending, World.Library, AccessScope.Cluster).Reason);
        Assert.Equal(DenyReason.AccountPending, evaluator.Allows(pending, World.Prefs, AccessScope.Cluster).Reason);
    }

    [Fact]
    public void ADisabledOwnerHoldsNothing()
    {
        World world = new();
        string owner = world.Person("gone", AccountStatus.Disabled);
        world.Assign(owner, BuiltInRoles.OwnerId, AccessScope.Cluster);

        Assert.Equal(DenyReason.AccountDisabled, world.Evaluator().Allows(owner, World.Library, AccessScope.Cluster).Reason);
    }

    [Fact]
    public void AMalformedActionIsRefusedEvenToAnOwner()
    {
        World world = new();
        string owner = world.Owner();

        Assert.Equal(DenyReason.MalformedAction, world.Evaluator().Allows(owner, "start everything", AccessScope.Cluster).Reason);
    }

    // ── 2 · staleness ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AStaleReplicaServesReadsAndRefusesEverythingElseOwnersIncluded()
    {
        World world = new();
        world.Freshness = AuthorityFreshness.Replica(world.Clock.GetUtcNow(), TimeSpan.FromMinutes(5));
        string owner = world.Owner();
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Runner", 1, World.Start, World.Console), World.Walter);

        world.Clock.Advance(TimeSpan.FromMinutes(6));
        AccessEvaluator evaluator = world.Evaluator();

        Assert.True(evaluator.Allows(owner, World.Console, World.Terraria).Allowed);
        Assert.True(evaluator.Allows(alice, World.Console, World.Terraria).Allowed);
        Assert.Equal(DenyReason.Stale, evaluator.Allows(owner, World.Start, World.Terraria).Reason);
        Assert.Equal(DenyReason.Stale, evaluator.Allows(alice, World.Start, World.Terraria).Reason);
    }

    [Fact]
    public void AReplicaWithinItsBoundIsCurrent()
    {
        World world = new();
        world.Freshness = AuthorityFreshness.Replica(world.Clock.GetUtcNow(), TimeSpan.FromMinutes(5));
        string owner = world.Owner();

        world.Clock.Advance(TimeSpan.FromMinutes(5));

        Assert.True(world.Evaluator().Allows(owner, World.Start, World.Terraria).Allowed);
    }

    [Fact]
    public void AReplicaThatWasNeverConfirmedIsStale()
    {
        World world = new() { Freshness = AuthorityFreshness.Replica(null, TimeSpan.FromMinutes(5)) };
        string owner = world.Owner();

        Assert.Equal(DenyReason.Stale, world.Evaluator().Allows(owner, World.Start, World.Terraria).Reason);
    }

    [Fact]
    public void AStaleReplicaRefusesAnActionItDoesNotKnowBecauseNothingSaysItIsARead()
    {
        World world = new() { Freshness = AuthorityFreshness.Replica(null, TimeSpan.FromMinutes(5)) };
        string owner = world.Owner();

        Assert.Equal(DenyReason.Stale, world.Evaluator().Allows(owner, "reactor:rules.read", World.Walter).Reason);
    }

    // ── 3 · Owner ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AnOwnerHoldsEveryActionEverywhereIncludingUndeclaredOnes()
    {
        World world = new();
        string owner = world.Owner();
        AccessEvaluator evaluator = world.Evaluator();

        Assert.True(evaluator.Allows(owner, World.Start, World.JessieTerraria).Allowed);
        Assert.True(evaluator.Allows(owner, AuthActions.RolesEdit, AccessScope.Cluster).Allowed);
        Assert.True(evaluator.Allows(owner, "reactor:rules.write", World.Walter).Allowed);
    }

    [Fact]
    public void AnUndeclaredActionIsRefusedToEveryoneButAnOwner()
    {
        World world = new();
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Everything", 1, "reactor:rules.write"), AccessScope.Cluster);

        Assert.Equal(DenyReason.UnknownAction, world.Evaluator().Allows(alice, "reactor:rules.write", World.Walter).Reason);
    }

    // ── 4 · self actions ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void EveryActivePersonHoldsEverySelfAction()
    {
        World world = new();
        string alice = world.Person("alice");

        Assert.True(world.Evaluator().Allows(alice, World.Prefs, AccessScope.Cluster).Allowed);
    }

    [Fact]
    public void AServiceHoldsNoSelfAction()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");

        Assert.Equal(DenyReason.NotGranted, world.Evaluator().Allows(reactor, World.Prefs, AccessScope.Cluster).Reason);
    }

    // ── 5 · the union ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void NothingAssignedIsNothingGranted()
    {
        World world = new();
        string alice = world.Person("alice");

        Assert.Equal(DenyReason.NotGranted, world.Evaluator().Allows(alice, World.Start, World.Terraria).Reason);
    }

    [Fact]
    public void AnInstanceAssignmentGrantsAtThatInstanceOnly()
    {
        World world = new();
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Runner", 1, World.Start), World.Terraria);
        AccessEvaluator evaluator = world.Evaluator();

        Assert.True(evaluator.Allows(alice, World.Start, World.Terraria).Allowed);
        Assert.False(evaluator.Allows(alice, World.Start, World.Factorio).Allowed);
        Assert.False(evaluator.Allows(alice, World.Start, AccessScope.ForInstance("walter", "terraria", "fresh")).Allowed);
    }

    [Fact]
    public void ANodeAssignmentGrantsOnEveryInstanceOnTheNodeIncludingLaterOnes()
    {
        World world = new();
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Runner", 1, World.Start), World.Walter);
        AccessEvaluator evaluator = world.Evaluator();

        Assert.True(evaluator.Allows(alice, World.Start, World.Terraria).Allowed);
        Assert.True(evaluator.Allows(alice, World.Start, AccessScope.ForInstance("walter", "valheim", "0001")).Allowed);
        Assert.False(evaluator.Allows(alice, World.Start, World.JessieTerraria).Allowed);
    }

    [Fact]
    public void AClusterAssignmentGrantsEverywhere()
    {
        World world = new();
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Runner", 1, World.Start), AccessScope.Cluster);

        Assert.True(world.Evaluator().Allows(alice, World.Start, World.JessieTerraria).Allowed);
    }

    [Fact]
    public void ANarrowerAssignmentNeverGrantsAWiderKindOfAction()
    {
        World world = new();
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Watcher", 1, World.Metrics, World.Library), World.Terraria);
        AccessEvaluator evaluator = world.Evaluator();

        // A node action asked at one of its instances is asked of the node, which the instance does
        // not contain.
        Assert.False(evaluator.Allows(alice, World.Metrics, World.Terraria).Allowed);
        Assert.False(evaluator.Allows(alice, World.Metrics, World.Walter).Allowed);
        Assert.False(evaluator.Allows(alice, World.Library, World.Terraria).Allowed);
    }

    [Fact]
    public void ANodeActionIsGrantedByTheNodesAssignmentWhenAskedAtOneOfItsInstances()
    {
        World world = new();
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Watcher", 1, World.Metrics), World.Walter);

        Assert.True(world.Evaluator().Allows(alice, World.Metrics, World.Terraria).Allowed);
    }

    [Fact]
    public void AccessIsTheUnionOfEveryAssignment()
    {
        World world = new();
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Runner", 1, World.Start), World.Terraria);
        world.Assign(alice, world.Role("Reader", 2, World.Console), World.Walter);
        AccessEvaluator evaluator = world.Evaluator();

        Assert.True(evaluator.Allows(alice, World.Start, World.Terraria).Allowed);
        Assert.True(evaluator.Allows(alice, World.Console, World.Factorio).Allowed);
        Assert.False(evaluator.Allows(alice, World.Start, World.Factorio).Allowed);
    }

    [Fact]
    public void EveryoneIsHeldByEveryActivePersonAtClusterScope()
    {
        World world = new();
        world.Everyone(World.Library, World.Console);
        string alice = world.Person("alice");
        AccessEvaluator evaluator = world.Evaluator();

        Assert.True(evaluator.Allows(alice, World.Library, AccessScope.Cluster).Allowed);
        Assert.True(evaluator.Allows(alice, World.Console, World.JessieTerraria).Allowed);
    }

    [Fact]
    public void AServiceDoesNotHoldEveryone()
    {
        World world = new();
        world.Everyone(World.Library);
        string reactor = world.Service("reactor", "walter");

        Assert.False(world.Evaluator().Allows(reactor, World.Library, AccessScope.Cluster).Allowed);
    }

    [Fact]
    public void AServiceHoldsItsApprovedRequirementsWhereTheyAreApproved()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        world.Require(reactor, World.Start, World.Walter);
        AccessEvaluator evaluator = world.Evaluator();

        Assert.True(evaluator.Allows(reactor, World.Start, World.Terraria).Allowed);
        Assert.False(evaluator.Allows(reactor, World.Start, World.JessieTerraria).Allowed);
    }

    [Theory]
    [InlineData(RequirementState.Waiting, true)]
    [InlineData(RequirementState.Revoked, true)]
    [InlineData(RequirementState.Approved, false)]
    public void ARequirementGrantsOnlyWhileApprovedAndStillDeclared(RequirementState state, bool declared)
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        world.Require(reactor, World.Start, World.Walter, state, declared);

        Assert.False(world.Evaluator().Allows(reactor, World.Start, World.Terraria).Allowed);
    }

    [Fact]
    public void ANarrowedRequirementGrantsOnlyInsideItsNarrowerScope()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        world.Require(reactor, World.Start, World.Terraria, decidedBy: "local:owner");
        AccessEvaluator evaluator = world.Evaluator();

        Assert.True(evaluator.Allows(reactor, World.Start, World.Terraria).Allowed);
        Assert.False(evaluator.Allows(reactor, World.Start, World.Factorio).Allowed);
    }

    [Fact]
    public void AServiceCanHoldAssignedRolesLikeAPerson()
    {
        World world = new();
        string bot = world.Service("bot", "hotrod");
        world.Assign(bot, world.Role("Announcer", 1, World.Console), AccessScope.Cluster);

        Assert.True(world.Evaluator().Allows(bot, World.Console, World.Terraria).Allowed);
    }

    // ── 6 · author ∩ service ──────────────────────────────────────────────────────────────────

    [Fact]
    public void AnAutomationRunsWhenBothTheServiceAndItsAuthorMayAct()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        world.Require(reactor, World.Start, World.Walter);
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Runner", 1, World.Start), World.Terraria);

        Assert.True(world.Evaluator().AllowsAutomation(reactor, alice, World.Start, World.Terraria).Allowed);
    }

    [Fact]
    public void AnAutomationNeverLendsItsAuthorTheServicesReach()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        world.Require(reactor, World.Start, World.Walter);
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Runner", 1, World.Start), World.Terraria);

        AccessDecision decision = world.Evaluator().AllowsAutomation(reactor, alice, World.Start, World.Factorio);

        Assert.Equal(DenyReason.AuthorDenied, decision.Reason);
        Assert.Equal(alice, decision.Detail);
    }

    [Fact]
    public void AnAutomationStopsWhenItsAuthorIsDisabled()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        world.Require(reactor, World.Start, World.Walter);
        string alice = world.Person("alice", AccountStatus.Disabled);
        world.Assign(alice, world.Role("Runner", 1, World.Start), World.Walter);

        Assert.Equal(DenyReason.AuthorDenied, world.Evaluator().AllowsAutomation(reactor, alice, World.Start, World.Terraria).Reason);
    }

    [Fact]
    public void AnAutomationStopsWhenItsAuthorIsDeleted()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        world.Require(reactor, World.Start, World.Walter);

        Assert.Equal(DenyReason.AuthorDenied, world.Evaluator().AllowsAutomation(reactor, "usr_deleted", World.Start, World.Terraria).Reason);
    }

    [Fact]
    public void AnAutomationWithNoAuthorIsBlocked()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        world.Require(reactor, World.Start, World.Walter);

        Assert.Equal(DenyReason.NoAuthor, world.Evaluator().AllowsAutomation(reactor, null, World.Start, World.Terraria).Reason);
    }

    [Fact]
    public void AnAutomationIsRefusedWhenTheServiceItselfMayNotAct()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        string owner = world.Owner();

        Assert.Equal(DenyReason.NotGranted, world.Evaluator().AllowsAutomation(reactor, owner, World.Start, World.Terraria).Reason);
    }

    [Fact]
    public void AServiceCannotBeAnAuthor()
    {
        World world = new();
        string reactor = world.Service("reactor", "walter");
        string scheduler = world.Service("scheduler", "walter");
        world.Require(reactor, World.Start, World.Walter);
        world.Require(scheduler, World.Start, World.Walter);

        Assert.Equal(DenyReason.AuthorDenied, world.Evaluator().AllowsAutomation(reactor, scheduler, World.Start, World.Terraria).Reason);
    }

    // ── /me/access ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EffectiveActionsListWhatTheEvaluatorAllowsAtOneTarget()
    {
        World world = new();
        world.Everyone(World.Library);
        string alice = world.Person("alice");
        world.Assign(alice, world.Role("Runner", 1, World.Start), World.Terraria);

        IReadOnlySet<string> actions = world.Evaluator().EffectiveActions(alice, World.Terraria);

        Assert.Equal(
            new[] { World.Prefs, World.Library, World.Start }.Order(),
            actions.Order());
    }

    [Fact]
    public void AnOwnersEffectiveActionsAreTheWholeCatalog()
    {
        World world = new();
        string owner = world.Owner();
        AuthoritySnapshot snapshot = world.Snapshot();

        Assert.Equal(snapshot.Catalog.Count, new AccessEvaluator(snapshot, world.Clock).EffectiveActions(owner, World.Walter).Count);
    }
}
