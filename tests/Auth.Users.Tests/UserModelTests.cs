namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>The account model's own rules — the ones no database enforces.</summary>
public class UserModelTests
{
    [Fact]
    public void ALocalAccountsHandleIsItsOpaqueIdAndItsActorStringIsItsUsername()
    {
        // Two different strings on purpose: the handle keys sessions and credentials and must
        // survive a rename, while the actor string is what a person reads in an audit log.
        KgsmUser user = Make.User("haru") with { UserId = "usr_abc" };

        Assert.Equal("local:usr_abc", user.AsIdentity().Handle);
        Assert.Equal("local:haru", user.AsIdentity().ActorString);
    }

    [Fact]
    public void ARenameLeavesTheHandleAlone()
    {
        KgsmUser user = Make.User("haru") with { UserId = "usr_abc" };
        Assert.Equal(user.AsIdentity().Handle, (user with { Username = "kaito" }).AsIdentity().Handle);
    }

    [Theory]
    [InlineData(UserStatus.Active, KgsmTier.Admin)]
    [InlineData(UserStatus.Pending, KgsmTier.None)]
    [InlineData(UserStatus.Disabled, KgsmTier.None)]
    public void OnlyAnActiveAccountHoldsTheTierWrittenOnIt(UserStatus status, KgsmTier expected)
    {
        Assert.Equal(expected, (Make.User(tier: KgsmTier.Admin, status: status)).EffectiveTier);
    }

    [Fact]
    public void IdsCarryTheirPrefixAreUnguessableAndNeverRepeat()
    {
        string[] ids = [.. Enumerable.Range(0, 200).Select(_ => UserIds.NewUserId())];

        Assert.All(ids, id => Assert.StartsWith(UserIds.UserPrefix, id, StringComparison.Ordinal));
        Assert.All(ids, id => Assert.Equal(UserIds.UserPrefix.Length + 32, id.Length));
        Assert.Equal(ids.Length, ids.Distinct().Count());
        Assert.StartsWith(UserIds.CredentialPrefix, UserIds.NewCredentialId(), StringComparison.Ordinal);
    }

    [Fact]
    public void APasswordIsFiledUnderTheAccountIdNotTheUsername()
    {
        // Which is what makes "one password per account" fall out of the unique index on the handle,
        // and what keeps the row attached through a rename.
        Assert.Equal("local:usr_abc", UserCredentials.LocalHandle("usr_abc"));
    }
}

/// <summary>What a username may be.</summary>
public class UsernamesTests
{
    [Theory]
    [InlineData("haru")]
    [InlineData("Haru")]
    [InlineData("h4ru")]
    [InlineData("haru.kun")]
    [InlineData("haru_kun")]
    [InlineData("haru-kun")]
    [InlineData("abc")]
    public void AnOrdinaryNameIsAccepted(string username) => Assert.True(Usernames.IsValid(username));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("ab")]
    [InlineData("_haru")]
    [InlineData(".haru")]
    [InlineData("-haru")]
    [InlineData("haru kun")]
    [InlineData("haru@example.com")]
    [InlineData("harú")]
    [InlineData("хару")]
    public void AnythingThatWouldMakeMatchingAmbiguousIsRefused(string? username) =>
        Assert.False(Usernames.IsValid(username));

    [Fact]
    public void ThirtyThreeCharactersIsTooMany()
    {
        Assert.True(Usernames.IsValid(new string('a', Usernames.MaxLength)));
        Assert.False(Usernames.IsValid(new string('a', Usernames.MaxLength + 1)));
    }

    [Fact]
    public void TheMatchingKeyIsCaseAndWhitespaceInsensitive() =>
        Assert.Equal("haru", Usernames.Key("  HaRu  "));
}

/// <summary>The lockout curve.</summary>
public class LockoutPolicyTests
{
    private static readonly LockoutPolicy Policy = new(
        Threshold: 3, BaseDelay: TimeSpan.FromSeconds(5), MaxDelay: TimeSpan.FromMinutes(15),
        FailureWindow: TimeSpan.FromHours(1));

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public void FailuresUpToTheThresholdCostNothing(int count) =>
        Assert.Equal(TimeSpan.Zero, Policy.DelayAfter(count));

    [Fact]
    public void PastTheThresholdTheDelayDoubles()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), Policy.DelayAfter(4));
        Assert.Equal(TimeSpan.FromSeconds(10), Policy.DelayAfter(5));
        Assert.Equal(TimeSpan.FromSeconds(20), Policy.DelayAfter(6));
    }

    [Fact]
    public void TheDoublingStopsAtTheCeilingRatherThanOverflowing()
    {
        // A sustained attack is a large number here, and the cap is also what keeps someone who
        // knows a username from locking its owner out indefinitely.
        Assert.Equal(Policy.MaxDelay, Policy.DelayAfter(100));
        Assert.Equal(Policy.MaxDelay, Policy.DelayAfter(int.MaxValue));
    }

    [Fact]
    public void AStoredLockIsOnlyLiveUntilItExpires()
    {
        DateTimeOffset now = Make.Now;
        LoginLockout locked = new(4, now.AddSeconds(5));

        Assert.True(locked.IsLocked(now));
        Assert.False(locked.IsLocked(now.AddSeconds(6)));
        Assert.False(LoginLockout.Clear.IsLocked(now));
    }
}

/// <summary>The spelling shared by the file and the wire, and what an unknown value reads as.</summary>
public class UserWireTests
{
    [Theory]
    [InlineData(UserStatus.Active, "active")]
    [InlineData(UserStatus.Pending, "pending")]
    [InlineData(UserStatus.Disabled, "disabled")]
    public void AStatusRoundTripsAsAWord(UserStatus status, string wire)
    {
        Assert.Equal(wire, UserStatuses.ToWire(status));
        Assert.Equal(status, UserStatuses.Parse(wire));
    }

    [Fact]
    public void AStatusThisBuildDoesNotKnowReadsAsDisabled()
    {
        // Fail closed, the same rule KgsmTiers.Parse follows: an unreadable account is one nobody
        // can sign in to, never one that defaults to working.
        Assert.Equal(UserStatus.Disabled, UserStatuses.Parse("suspended-pending-review"));
        Assert.Equal(UserStatus.Disabled, UserStatuses.Parse(""));
        Assert.Equal(UserStatus.Disabled, UserStatuses.Parse(null));
    }

    [Fact]
    public void AStatusIsMatchedWithoutRegardToCaseOrPadding() =>
        Assert.Equal(UserStatus.Active, UserStatuses.Parse("  Active "));

    [Fact]
    public void AProvenanceThisBuildDoesNotKnowReadsAsDerived()
    {
        // So it lands in the drift report rather than passing for a tier an admin chose.
        Assert.Equal(TierSource.Granted, TierSources.Parse("granted"));
        Assert.Equal(TierSource.Derived, TierSources.Parse("inherited-from-somewhere"));
        Assert.Equal(TierSource.Derived, TierSources.Parse(null));
    }

    [Fact]
    public void ACredentialKindThisBuildDoesNotKnowReadsAsAnIdentity()
    {
        // The kind that carries no secret, so it can never be verified against one.
        Assert.Equal(CredentialKind.Password, CredentialKinds.Parse("password"));
        Assert.Equal(CredentialKind.Identity, CredentialKinds.Parse("passkey"));
        Assert.Equal(CredentialKind.Identity, CredentialKinds.Parse(null));
    }

    [Fact]
    public void TimesAreStoredSortableAndComeBackAsUtc()
    {
        DateTimeOffset local = new(2026, 8, 9, 14, 30, 0, TimeSpan.FromHours(2));
        string wire = UserWire.ToWire(local);

        Assert.EndsWith("Z", wire, StringComparison.Ordinal);
        Assert.Equal(local.ToUniversalTime(), UserWire.ReadTime(wire));
        Assert.Equal(TimeSpan.Zero, UserWire.ReadTime(wire).Offset);
    }
}
