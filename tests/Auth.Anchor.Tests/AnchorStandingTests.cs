using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// Where an anchor stands, and what follows from it. Three states rather than two, because a machine
/// that is not in a cluster is not "not the holder" — there is nothing to hold.
/// </summary>
public sealed class AnchorStandingTests
{
    private static ClusterOptions Options(string secret) => new()
    {
        MemberId = "hotrod-auth",
        Kind = MemberKind.Anchor,
        Secret = secret,
        StorePath = "/tmp/unused-by-this-test.db",
    };

    [Fact]
    public void A_machine_with_no_cluster_holds_its_own_accounts()
    {
        var role = new AnchorRole(Options(secret: ""));

        // The standalone install the plan promises is unaffected: no assignment to read, and every
        // door open exactly as it was.
        Assert.Equal(AnchorStanding.Standalone, role.Standing);
        Assert.True(role.IsAuthority);
        Assert.Null(role.Holder);
    }

    [Fact]
    public void A_clustered_anchor_stands_by_until_it_has_read_the_assignment()
    {
        var role = new AnchorRole(Options(secret: "a shared cluster secret"));

        // Not "assume I hold it until told otherwise": that would make this member the authority for
        // exactly the window in which it does not know whether it is one.
        Assert.Equal(AnchorStanding.StandingBy, role.Standing);
        Assert.False(role.IsAuthority);
    }

    [Fact]
    public void Holding_the_capability_makes_it_the_authority()
    {
        var role = new AnchorRole(Options(secret: "a shared cluster secret"));

        Assert.True(role.Update(AnchorStanding.Holder, "hotrod-auth"));
        Assert.True(role.IsAuthority);
        Assert.Equal("hotrod-auth", role.Holder);
    }

    [Fact]
    public void Losing_the_capability_stands_it_down_and_names_the_holder()
    {
        var role = new AnchorRole(Options(secret: "a shared cluster secret"));
        role.Update(AnchorStanding.Holder, "hotrod-auth");

        // The §7·a safeguard: a member that believed it was the anchor while the cluster names
        // another serves nothing on the strength of its own opinion.
        Assert.True(role.Update(AnchorStanding.StandingBy, "node-b-auth"));
        Assert.False(role.IsAuthority);
        Assert.Equal("node-b-auth", role.Holder);
    }

    [Fact]
    public void An_unchanged_standing_is_not_reported_as_a_change()
    {
        var role = new AnchorRole(Options(secret: "a shared cluster secret"));
        Assert.True(role.Update(AnchorStanding.Holder, "hotrod-auth"));

        // The worker logs on change, so a steady state must not narrate itself once per interval.
        Assert.False(role.Update(AnchorStanding.Holder, "hotrod-auth"));
    }

    [Fact]
    public void A_change_of_holder_alone_is_still_a_change()
    {
        var role = new AnchorRole(Options(secret: "a shared cluster secret"));
        role.Update(AnchorStanding.StandingBy, null);

        // "Nobody has it yet" and "somebody else has it" are the same standing and different facts,
        // and an operator reading a refusal needs the second one.
        Assert.True(role.Update(AnchorStanding.StandingBy, "node-b-auth"));
    }
}

/// <summary>
/// Who takes the accounts when nobody holds them: the anchor on the machine that founded the cluster,
/// and nobody else.
/// </summary>
/// <remarks>
/// Anywhere else an empty assignment means gossip has not arrived yet, and a claim made in that window
/// competes with the real holder under a tie-break that can hand this anchor the cluster's accounts.
/// </remarks>
public sealed class AnchorClaimTests : IDisposable
{
    private const string Secret = "a secret this machine holds";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "kgsm-anchor-claim", Guid.NewGuid().ToString("N"));

    public AnchorClaimTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private string FoundedPath => Path.Combine(_dir, "cluster-founded");

    /// <summary>Runs one anchor for a few passes and reports who holds the accounts afterwards.</summary>
    private async Task<(string? Holder, AnchorRole Role)> RunAsync()
    {
        var cluster = new ClusterOptions
        {
            MemberId = "joining-auth", Kind = MemberKind.Anchor, Secret = Secret,
            StorePath = Path.Combine(_dir, "cluster.db"), FoundedPath = FoundedPath, GossipMs = 250,
        };
        var store = new TheKrystalShip.KGSM.Cluster.Storage.ClusterStore(
            cluster, Microsoft.Extensions.Logging.Abstractions.NullLogger<TheKrystalShip.KGSM.Cluster.Storage.ClusterStore>.Instance);
        var state = new ClusterStateStore(store, cluster);
        var role = new AnchorRole(cluster);
        using var signer = EcdsaSessionSigner.Generate();

        var worker = new ClusterMembershipWorker(
            cluster,
            AnchorOptions.FromSettings(new AnchorSettings { ClusterId = "test-cluster", Issuer = "https://auth.test" }),
            state,
            new SelfPublications(new SelfIncarnation()),
            signer,
            role,
            new MembersStore(store),
            new ClientRegistry(new SqliteSessionRegistry(Path.Combine(_dir, "sessions.db"))),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ClusterMembershipWorker>.Instance);

        await worker.StartAsync(default);
        await Task.Delay(800);
        await worker.StopAsync(default);

        return (await state.HolderAsync(ClusterCapability.Auth, default), role);
    }

    [Fact]
    public async Task The_anchor_on_the_machine_that_founded_the_cluster_claims_the_accounts()
    {
        File.WriteAllText(FoundedPath, ClusterFounding.Fingerprint(Secret) + "\n");

        (string? holder, AnchorRole role) = await RunAsync();

        Assert.Equal("joining-auth", holder);
        Assert.True(role.IsAuthority);
    }

    [Fact]
    public async Task An_anchor_on_a_machine_that_joined_never_claims_them()
    {
        (string? holder, AnchorRole role) = await RunAsync();

        Assert.Null(holder);
        Assert.False(role.IsAuthority);
    }

    [Fact]
    public async Task A_founding_machine_that_took_another_clusters_secret_never_claims_them()
    {
        // The record stays behind when the secret changes, naming the cluster this machine left.
        File.WriteAllText(FoundedPath, ClusterFounding.Fingerprint("the cluster this machine founded") + "\n");

        (string? holder, _) = await RunAsync();

        Assert.Null(holder);
    }
}

/// <summary>
/// What an anchor states about itself, which is everything a member needs to accept a session it
/// cannot mint and everything a browser needs to find the door.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class PublishedFactTests(AnchorFixture anchor)
{
    private IReadOnlyDictionary<string, string> Facts =>
        anchor.Service<SelfPublications>().Current;

    [Fact]
    public void The_verification_keys_are_published()
    {
        Assert.True(Facts.TryGetValue(ClusterAuthFacts.PublicKey, out string? published));

        SessionJwks? keys = EcdsaSessionSigner.ReadKeys(published!);
        Assert.NotNull(keys);
        Assert.NotEmpty(keys.Keys);

        // The published document carries the public half and nothing else. A private parameter here
        // would hand every member in the cluster the ability to mint what it is meant only to check.
        Assert.DoesNotContain("\"d\"", published);
    }

    [Fact]
    public void The_audience_is_published()
    {
        // Without it a member holds keys it cannot decide what to accept with, and refuses every
        // session rather than guessing which cluster one was minted for.
        Assert.Equal(AnchorFixture.ClusterId, Facts[ClusterAuthFacts.Audience]);
    }

    [Fact]
    public void The_issuer_is_published()
    {
        // Every surface stamps its own, and a member holding only its own would refuse every session
        // the anchor mints while reporting nothing more specific than an invalid token.
        Assert.Equal(AnchorFixture.Issuer, Facts[ClusterAuthFacts.Issuer]);
    }

    [Fact]
    public void The_browser_address_is_published()
    {
        Assert.Equal(AnchorFixture.SignInUrl, Facts[ClusterAuthFacts.SignInUrl]);
    }
}
