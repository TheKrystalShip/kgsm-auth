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
/// Who may write the file members on one machine verify sessions against.
/// </summary>
/// <remarks>
/// The gossiped fact and this file are not the same mechanism and do not need the same rule. A reader
/// resolves the fact through the holder, so a candidate stating a key is simply never consulted; a
/// path resolves through nothing, so the writer has to scope it or a candidate hands every member on
/// the machine a key that verifies nothing anybody signed with.
/// </remarks>
public sealed class PublishedKeyFileTests : IDisposable
{
    private readonly string _dir = Path.Combine(
        Path.GetTempPath(), "kgsm-anchor-key-tests", Guid.NewGuid().ToString("N"));

    private string Path_ => System.IO.Path.Combine(_dir, "auth-public-key.json");

    public PublishedKeyFileTests() => Directory.CreateDirectory(_dir);

    [Fact]
    public void A_key_is_written_once_and_left_alone_when_it_has_not_changed()
    {
        Assert.True(SigningKeyStore.Publish(Path_, "{\"keys\":[\"mine\"]}"));
        DateTime first = File.GetLastWriteTimeUtc(Path_);

        Assert.True(SigningKeyStore.Publish(Path_, "{\"keys\":[\"mine\"]}"));

        // A restart that changes nothing must not wake a member watching the file.
        Assert.Equal(first, File.GetLastWriteTimeUtc(Path_));
    }

    [Fact]
    public void A_member_withdraws_its_own_key_when_it_stands_down()
    {
        SigningKeyStore.Publish(Path_, "{\"keys\":[\"mine\"]}");

        Assert.True(SigningKeyStore.Withdraw(Path_, "{\"keys\":[\"mine\"]}"));
        Assert.False(File.Exists(Path_));
    }

    [Fact]
    public void It_never_removes_a_key_that_is_not_its_own()
    {
        // Written by whoever holds the capability. Taking it away would break every member reading it.
        SigningKeyStore.Publish(Path_, "{\"keys\":[\"the holder's\"]}");

        Assert.False(SigningKeyStore.Withdraw(Path_, "{\"keys\":[\"mine\"]}"));
        Assert.True(File.Exists(Path_));
    }

    [Fact]
    public void Publishing_where_no_shared_directory_exists_is_not_a_failure()
    {
        // A machine with no other member has nothing to read the file. The key is still served over
        // HTTP and still gossiped, which is how a member elsewhere finds it.
        Assert.False(SigningKeyStore.Publish(
            System.IO.Path.Combine(_dir, "absent", "key.json"), "{}"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
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
        Assert.Equal("kgsm", Facts[ClusterAuthFacts.Issuer]);
    }

    [Fact]
    public void The_browser_address_is_published()
    {
        Assert.Equal(AnchorFixture.SignInUrl, Facts[ClusterAuthFacts.SignInUrl]);
    }
}
