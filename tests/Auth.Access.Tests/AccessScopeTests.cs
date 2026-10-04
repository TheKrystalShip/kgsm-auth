namespace TheKrystalShip.Auth.Access.Tests;

/// <summary>
/// A scope's one spelling, and how scopes nest.
/// </summary>
public class AccessScopeTests
{
    [Theory]
    [InlineData("cluster")]
    [InlineData("node:walter")]
    [InlineData("instance:walter/terraria#9f3c")]
    public void EveryScopeRoundTripsThroughItsWireForm(string wire) =>
        Assert.Equal(wire, AccessScope.Parse(wire).ToString());

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Cluster")]
    [InlineData("node:")]
    [InlineData("node:wal ter")]
    [InlineData("instance:walter/terraria")]
    [InlineData("instance:walter#9f3c")]
    [InlineData("instance:/terraria#9f3c")]
    [InlineData("instance:walter/#9f3c")]
    [InlineData("instance:walter/terraria#")]
    [InlineData("server:walter/terraria")]
    public void AnythingMalformedIsNoScopeAtAll(string? wire) =>
        Assert.False(AccessScope.TryParse(wire, out _));

    [Fact]
    public void TheClusterContainsEveryScope()
    {
        Assert.True(AccessScope.Cluster.Contains(AccessScope.Cluster));
        Assert.True(AccessScope.Cluster.Contains(World.Walter));
        Assert.True(AccessScope.Cluster.Contains(World.Terraria));
    }

    [Fact]
    public void ANodeContainsItselfAndItsInstancesOnly()
    {
        Assert.True(World.Walter.Contains(World.Walter));
        Assert.True(World.Walter.Contains(World.Terraria));
        Assert.True(World.Walter.Contains(AccessScope.ForInstance("walter", "installed-later", "0001")));

        Assert.False(World.Walter.Contains(AccessScope.Cluster));
        Assert.False(World.Walter.Contains(World.Jessie));
        Assert.False(World.Walter.Contains(World.JessieTerraria));
    }

    [Fact]
    public void AnInstanceContainsOnlyItself()
    {
        Assert.True(World.Terraria.Contains(World.Terraria));
        Assert.False(World.Terraria.Contains(World.Walter));
        Assert.False(World.Terraria.Contains(World.Factorio));
    }

    [Fact]
    public void AReinstallUnderTheSameNameIsADifferentInstance() =>
        // The nonce is what keeps a grant from crossing to whatever is installed next under the name.
        Assert.False(World.Terraria.Contains(AccessScope.ForInstance("walter", "terraria", "fresh")));

    [Fact]
    public void WideningAnInstanceToANodeGivesTheNodeItIsOn()
    {
        Assert.Equal(World.Walter, World.Terraria.WidenedTo(ScopeKind.Node));
        Assert.Equal(AccessScope.Cluster, World.Terraria.WidenedTo(ScopeKind.Cluster));
        Assert.Equal(World.Terraria, World.Terraria.WidenedTo(ScopeKind.Instance));
        Assert.Equal(AccessScope.Cluster, AccessScope.Cluster.WidenedTo(ScopeKind.Instance));
    }

    [Fact]
    public void UnreadableWireValuesFailClosed()
    {
        Assert.Equal(ScopeKind.Cluster, ScopeKinds.Parse("galaxy"));
        Assert.Equal(ActionEffect.Write, ActionEffects.Parse("peek"));
        Assert.Equal(RoleKind.Custom, RoleKinds.Parse("superuser"));
        Assert.Equal(RequirementState.Revoked, RequirementStates.Parse("maybe"));
    }

    [Theory]
    [InlineData("kgsm:server.start", true)]
    [InlineData("monitor:audit.personal-fields", true)]
    [InlineData("kgsm-dns:names.write", true)]
    [InlineData("kgsm:", false)]
    [InlineData(":start", false)]
    [InlineData("KGSM:server.start", false)]
    [InlineData("kgsm:server start", false)]
    [InlineData("kgsm", false)]
    public void ActionIdsAreComponentColonId(string action, bool valid) =>
        Assert.Equal(valid, ActionIds.IsValid(action));

    [Fact]
    public void OnlyTheAuthComponentsActionsAreAuthActions()
    {
        Assert.True(ActionIds.IsAuth(AuthActions.RolesAssign));
        Assert.False(ActionIds.IsAuth("authz:roles.assign"));
        Assert.False(ActionIds.IsAuth(World.Start));
    }
}
