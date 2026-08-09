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
    /// <summary>
    /// The section name and the property names are the contract: three repos bind this type from
    /// their own configuration, and one of them spelling a key differently is how a host ends up
    /// pointing two surfaces at two applications.
    /// </summary>
    [Fact]
    public void TheOptionsCarryTheApplicationsAndNothingElse()
    {
        Assert.Equal("KgsmAuth", KgsmAuthOptions.Section);
        Assert.Equal(["Providers"], typeof(KgsmAuthOptions).GetProperties().Select(p => p.Name).Order());
        Assert.Equal(
            ["ClientId", "ClientSecret", "Configured"],
            typeof(KgsmOAuthApplication).GetProperties().Select(p => p.Name).Order());
    }

    /// <summary>
    /// A provider name is written in an environment key, in a route and in a credential handle. The
    /// answer must not depend on which of those three a person capitalised.
    /// </summary>
    [Fact]
    public void AProviderIsFoundWhateverItsCasing()
    {
        var options = new KgsmAuthOptions();
        options.Providers["GitHub"] = new KgsmOAuthApplication { ClientId = "cid", ClientSecret = "sec" };

        Assert.True(options.For("github").Configured);
        Assert.True(options.For("GITHUB").Configured);
    }

    /// <summary>
    /// A provider nobody wired up and a provider nobody has heard of are one answer, so a caller asks
    /// whether it is configured and never whether it exists.
    /// </summary>
    [Fact]
    public void AnUnwiredAndAnUnknownProviderAnswerTheSame()
    {
        var options = new KgsmAuthOptions();
        options.Providers["discord"] = new KgsmOAuthApplication { ClientId = "cid" };  // no secret

        Assert.False(options.For("discord").Configured);
        Assert.False(options.For("nobody-has-heard-of-this").Configured);
        Assert.Empty(options.ConfiguredProviders());
    }

    /// <summary>
    /// The catalog a login page renders is the configured set — a button drawn for an unwired
    /// provider is a bounce that 503s.
    /// </summary>
    [Fact]
    public void OnlyWiredProvidersAreReported()
    {
        var options = new KgsmAuthOptions();
        options.Providers["discord"] = new KgsmOAuthApplication { ClientId = "cid", ClientSecret = "sec" };
        options.Providers["github"] = new KgsmOAuthApplication();

        Assert.Equal(["discord"], options.ConfiguredProviders());
    }
}
