namespace TheKrystalShip.KGSM.Auth.Users.Tests;

/// <summary>
/// The counter that orders account changes between members of a cluster.
/// </summary>
/// <remarks>
/// One writer assigns, every replica compares. The whole value of it is that a change arriving late
/// cannot move an account backwards — the case the design exists for is a tier and a disable
/// delivered out of order, where applying the tier second would quietly re-enable somebody an admin
/// had just switched off.
/// </remarks>
public class AccountVersionsTests
{
    private static SqliteAccountVersions Versions(TempStore temp) => new(temp.Options);

    private static readonly DateTimeOffset Now = Make.Now;

    [Fact]
    public async Task AnAccountNobodyHasChangedIsAtZero()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);

        // Zero rather than an absence, so a caller compares numbers rather than branching on null.
        Assert.Equal(0, await versions.CurrentAsync("usr_unknown"));
    }

    [Fact]
    public async Task TheWriterAssignsAStrictlyRisingVersion()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);

        Assert.Equal(1, await versions.NextAsync("usr_a", Now));
        Assert.Equal(2, await versions.NextAsync("usr_a", Now));
        Assert.Equal(3, await versions.NextAsync("usr_a", Now));
        Assert.Equal(3, await versions.CurrentAsync("usr_a"));
    }

    [Fact]
    public async Task EachAccountCountsOnItsOwn()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);

        await versions.NextAsync("usr_a", Now);
        await versions.NextAsync("usr_a", Now);

        // A shared counter would make one person's change look newer than another's, and every
        // replica would drop the older-numbered one.
        Assert.Equal(1, await versions.NextAsync("usr_b", Now));
    }

    [Fact]
    public async Task ConcurrentAssignmentsTakeDifferentVersions()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);

        long[] assigned = await Task.WhenAll(
            Enumerable.Range(0, 20).Select(_ => versions.NextAsync("usr_a", Now)));

        // The read and the increment are one statement precisely so two changes cannot take the
        // same number and leave one of them undroppable by every replica.
        Assert.Equal(20, assigned.Distinct().Count());
        Assert.Equal(20, await versions.CurrentAsync("usr_a"));
    }

    [Fact]
    public async Task AReplicaAcceptsSomethingNewerAndRecordsIt()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);

        Assert.True(await versions.TryAdvanceAsync("usr_a", 5, Now));
        Assert.Equal(5, await versions.CurrentAsync("usr_a"));
    }

    [Fact]
    public async Task AReplicaRefusesWhatItAlreadyHolds()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);
        await versions.TryAdvanceAsync("usr_a", 5, Now);

        // At-least-once delivery means the same change arrives twice as a matter of course. The
        // second delivery must be a no-op rather than a re-application.
        Assert.False(await versions.TryAdvanceAsync("usr_a", 5, Now));
        Assert.Equal(5, await versions.CurrentAsync("usr_a"));
    }

    [Fact]
    public async Task ADisableIsNotUndoneByATierThatWasSentBeforeIt()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);

        // The disable is version 7 and arrives first; the tier change is version 6 and arrives
        // second. This is the whole reason the counter exists: without it the tier lands last and
        // an account an admin just switched off is usable again.
        Assert.True(await versions.TryAdvanceAsync("usr_a", 7, Now));
        Assert.False(await versions.TryAdvanceAsync("usr_a", 6, Now));
        Assert.Equal(7, await versions.CurrentAsync("usr_a"));
    }

    [Fact]
    public async Task AVersionThatNamesNothingIsRefused()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);

        // Zero and below are never assigned, so nothing carrying one can be newer than anything.
        Assert.False(await versions.TryAdvanceAsync("usr_a", 0, Now));
        Assert.False(await versions.TryAdvanceAsync("usr_a", -1, Now));
        Assert.Equal(0, await versions.CurrentAsync("usr_a"));
    }

    [Fact]
    public async Task AVersionOutlivesTheAccountItBelongsTo()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);

        KgsmUser user = Make.User();
        await temp.Store.CreateAsync(user);
        await versions.TryAdvanceAsync(user.UserId, 4, Now);

        // The account goes; the counter stays. That row IS the tombstone — without it a change
        // issued before the deletion would be seen as new and would re-create somebody who was
        // deliberately removed.
        Assert.True(await temp.Store.DeleteAsync(user.UserId));
        Assert.Equal(4, await versions.CurrentAsync(user.UserId));
        Assert.False(await versions.TryAdvanceAsync(user.UserId, 3, Now));
    }

    [Fact]
    public async Task TheVersionsAreReadableAsASetForReconciliation()
    {
        using TempStore temp = new();
        IAccountVersions versions = Versions(temp);
        await versions.TryAdvanceAsync("usr_a", 2, Now);
        await versions.TryAdvanceAsync("usr_b", 9, Now);

        IReadOnlyDictionary<string, long> all = await versions.AllAsync();

        Assert.Equal(2, all["usr_a"]);
        Assert.Equal(9, all["usr_b"]);
    }

    [Fact]
    public async Task AnOlderBuildStillOpensTheAccountsBesideIt()
    {
        using TempStore temp = new();
        _ = Versions(temp);

        // The reason this is a table and not a column, and the reason UserSchema.Version does not
        // move: a build that has never heard of it reads accounts exactly as it did. Raising the
        // declared version would instead refuse the Control Panel, the bot and the assistant at once.
        SqliteUserStore reopened = temp.OpenAgain();
        KgsmUser user = Make.User();
        await reopened.CreateAsync(user);

        Assert.NotNull(await reopened.FindByIdAsync(user.UserId));
        Assert.Equal(UserSchema.Version, 1);
    }
}
