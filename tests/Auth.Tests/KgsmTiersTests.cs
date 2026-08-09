using TheKrystalShip.KGSM.Auth;

namespace TheKrystalShip.KGSM.Auth.Tests;

public class KgsmTiersTests
{
    [Theory]
    [InlineData(KgsmTier.None, "none")]
    [InlineData(KgsmTier.Viewer, "viewer")]
    [InlineData(KgsmTier.Operator, "operator")]
    [InlineData(KgsmTier.Admin, "admin")]
    public void WireFormRoundTrips(KgsmTier tier, string wire)
    {
        Assert.Equal(wire, KgsmTiers.ToWire(tier));
        Assert.Equal(tier, KgsmTiers.Parse(wire));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("owner")]        // a tier this build does not know
    [InlineData("administrator")] // near-miss
    [InlineData("true")]          // a boolean where a tier was expected
    public void UnrecognisedWireFormDenies(string? wire)
    {
        // Fail-closed. A relay header this build cannot read, or one a newer peer invented, must never
        // resolve to anything that grants.
        Assert.Equal(KgsmTier.None, KgsmTiers.Parse(wire));
    }

    [Theory]
    [InlineData("ADMIN")]
    [InlineData("  Operator ")]
    public void WireFormIsCaseAndWhitespaceTolerant(string wire) =>
        Assert.NotEqual(KgsmTier.None, KgsmTiers.Parse(wire));
}

public class KgsmActorTests
{
    [Fact]
    public void FormatsAnActorForAnyProvider()
    {
        Assert.Equal("discord:haru", KgsmActor.Format("discord", "haru"));
        Assert.Equal("github:haru", KgsmActor.Format("github", "haru"));
    }

    [Theory]
    [InlineData("discord:haru", "discord", "haru")]
    [InlineData("local:cli", "local", "cli")]
    [InlineData("discord:has:colons", "discord", "has:colons")]
    public void ParsesProviderAndName(string actor, string provider, string name)
    {
        Assert.True(KgsmActor.TryParse(actor, out string p, out string n));
        Assert.Equal(provider, p);
        Assert.Equal(name, n);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("noprovider")]
    [InlineData(":noprovider")]
    [InlineData("noname:")]
    public void RefusesAMalformedActor(string? actor)
    {
        // The caller treats an unparseable actor as unknown. Inventing a provider here would put a
        // fabricated identity into the audit log.
        Assert.False(KgsmActor.TryParse(actor, out _, out _));
    }
}

public class KgsmAuthOptionsTests
{
    [Fact]
    public void ParsesCommaSeparatedRoleIds()
    {
        KgsmAuthOptions options = new()
        {
            RoleAdminIds = "1,2",
            RoleOperatorIds = " 3 , ,4,",
        };

        KgsmRoleMap map = options.ToRoleMap();
        Assert.Equal(["1", "2"], map.AdminRoleIds);
        Assert.Equal(["3", "4"], map.OperatorRoleIds);
    }

    [Fact]
    public void UnconfiguredRolesYieldAnEmptyMap()
    {
        KgsmRoleMap map = new KgsmAuthOptions().ToRoleMap();
        Assert.True(map.IsEmpty);
        Assert.Equal(KgsmTier.Viewer, map.Resolve(["anything"]));
    }

    [Fact]
    public void ResolvingRolesNeedsAGuildAndABotToken()
    {
        Assert.False(new KgsmAuthOptions().CanResolveRoles);
        Assert.False(new KgsmAuthOptions { GuildId = "1" }.CanResolveRoles);
        Assert.False(new KgsmAuthOptions { BotToken = "t" }.CanResolveRoles);
        Assert.True(new KgsmAuthOptions { GuildId = "1", BotToken = "t" }.CanResolveRoles);
    }
}
