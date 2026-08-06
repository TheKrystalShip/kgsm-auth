using TheKrystalShip.KGSM.Auth;

namespace TheKrystalShip.KGSM.Auth.Tests;

/// <summary>
/// The resolve matrix. This is the whole authorization decision for the ecosystem, so every branch
/// is pinned here rather than re-proved in each consuming repo.
/// </summary>
public class KgsmRoleMapTests
{
    private const string AdminRole = "1520175931828867193";
    private const string OperatorRole = "1520175983880179804";
    private const string UnrelatedRole = "385732343740235778";

    private static KgsmRoleMap Map() => new([AdminRole], [OperatorRole]);

    [Fact]
    public void NotAGuildMember_ResolvesToNone()
    {
        // null is "no member object" — the 404 from a member lookup. Membership is the access gate.
        Assert.Equal(KgsmTier.None, Map().Resolve(null));
    }

    [Fact]
    public void MemberWithNoRoles_FloorsAtViewer()
    {
        // An EMPTY collection is a real member holding only @everyone — deliberately distinct from
        // null. Conflating the two would either lock every plain member out or let a failed lookup in.
        Assert.Equal(KgsmTier.Viewer, Map().Resolve([]));
    }

    [Fact]
    public void OperatorRole_ResolvesToOperator() =>
        Assert.Equal(KgsmTier.Operator, Map().Resolve([OperatorRole]));

    [Fact]
    public void AdminRole_ResolvesToAdmin() =>
        Assert.Equal(KgsmTier.Admin, Map().Resolve([AdminRole]));

    [Fact]
    public void BothRoles_ResolveToTheHigher() =>
        Assert.Equal(KgsmTier.Admin, Map().Resolve([OperatorRole, AdminRole]));

    [Fact]
    public void UnknownRole_LeavesTheViewerFloor()
    {
        // A role this host does not name — someone else's role, or one that was deleted — contributes
        // nothing. It neither elevates nor denies.
        Assert.Equal(KgsmTier.Viewer, Map().Resolve([UnrelatedRole]));
    }

    [Fact]
    public void EmptyMap_GrantsViewerAndNothingMore()
    {
        Assert.Equal(KgsmTier.Viewer, KgsmRoleMap.Empty.Resolve([AdminRole, OperatorRole]));
        Assert.Equal(KgsmTier.None, KgsmRoleMap.Empty.Resolve(null));
        Assert.True(KgsmRoleMap.Empty.IsEmpty);
    }

    [Fact]
    public void SnowflakeOverload_MatchesTheStringForm()
    {
        // A gateway client holds numeric snowflakes; a REST caller holds strings. Both must reach the
        // same verdict, or authority would depend on which surface asked.
        KgsmRoleMap map = Map();
        Assert.Equal(KgsmTier.Admin, map.ResolveSnowflakes([ulong.Parse(AdminRole)]));
        Assert.Equal(KgsmTier.Operator, map.ResolveSnowflakes([ulong.Parse(OperatorRole)]));
        Assert.Equal(KgsmTier.Viewer, map.ResolveSnowflakes([]));
        Assert.Equal(KgsmTier.None, map.ResolveSnowflakes(null));
    }

    [Fact]
    public void ConfiguredIds_TolerateBlanksAndWhitespace()
    {
        // The ids arrive from a comma-separated environment variable, so this is normal input.
        KgsmRoleMap map = new([" " + AdminRole + " ", ""], ["", "  "]);
        Assert.Equal(KgsmTier.Admin, map.Resolve([AdminRole]));
        Assert.Empty(map.OperatorRoleIds);
    }

    [Fact]
    public void RoleIdsAreComparedExactly()
    {
        // Snowflakes are opaque; a prefix or suffix is a different role, not a near-match.
        KgsmRoleMap map = Map();
        Assert.Equal(KgsmTier.Viewer, map.Resolve([AdminRole[..^1]]));
        Assert.Equal(KgsmTier.Viewer, map.Resolve([AdminRole + "0"]));
    }

    [Fact]
    public void TiersAreOrdered()
    {
        // The hierarchy is what lets a viewer requirement admit an operator, so it is load-bearing.
        Assert.True(KgsmTier.Admin > KgsmTier.Operator);
        Assert.True(KgsmTier.Operator > KgsmTier.Viewer);
        Assert.True(KgsmTier.Viewer > KgsmTier.None);
    }
}
