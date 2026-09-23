using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Storage;

namespace TheKrystalShip.KGSM.Auth.Cluster.Tests;

/// <summary>
/// The file a machine's leaves verify sessions against: written by the member on the machine from what
/// it read through the holder, and read back by a leaf that never joins the cluster.
/// </summary>
public sealed class HostProviderFileTests : IDisposable
{
    private const string Issuer = "https://auth.anchors.test";
    private const string Audience = "test-cluster";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "kgsm-host-provider", Guid.NewGuid().ToString("N"));
    private readonly EcdsaSessionSigner _signer = EcdsaSessionSigner.Generate();

    public HostProviderFileTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        _signer.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private string FilePath => Path.Combine(_dir, "auth-provider.json");

    private ClusterOptions Options => new()
    {
        MemberId = "node-a", Secret = "host-file-secret", StorePath = Path.Combine(_dir, "cluster.db"), GossipMs = 250,
    };

    /// <summary>A member whose cluster has <c>holder</c> holding the accounts and stating <paramref name="facts"/>.</summary>
    private async Task<ClusterSessionKeys> MemberAsync(IReadOnlyDictionary<string, string>? facts, string holder = "anchor-a")
    {
        var store = new ClusterStore(Options, NullLogger<ClusterStore>.Instance);
        var members = new MembersStore(store);
        var state = new ClusterStateStore(store, Options);

        if (facts is not null)
        {
            await members.UpsertAsync(
                MemberRow.New(holder, MemberKind.Anchor) with { Published = PublishedFacts.Encode(facts) }, default);
            await state.TryClaimAsync(ClusterCapability.Auth, holder, default);
        }

        var keys = new ClusterSessionKeys(new ClusterFacts(members, state), Options, NullLogger<ClusterSessionKeys>.Instance);
        await keys.StartAsync(default);
        for (int i = 0; i < 100 && !keys.HasRead; i++)
            await Task.Delay(20);
        Assert.True(keys.HasRead);
        return keys;
    }

    private Dictionary<string, string> Stated() => new()
    {
        [ClusterAuthFacts.PublicKey] = _signer.PublicKeysJson,
        [ClusterAuthFacts.Audience] = Audience,
        [ClusterAuthFacts.Issuer] = Issuer,
    };

    private HostProviderFileWriter Writer(ClusterSessionKeys keys) =>
        new(keys, Options, FilePath, NullLogger<HostProviderFileWriter>.Instance);

    [Fact]
    public async Task The_member_writes_what_it_verifies_with_and_a_leaf_reads_the_same()
    {
        ClusterSessionKeys member = await MemberAsync(Stated());
        Writer(member).Reconcile();

        var leaf = new HostSessionKeys(FilePath, NullLogger<HostSessionKeys>.Instance);

        Assert.Equal(Issuer, leaf.Issuer);
        Assert.Equal(Audience, leaf.Audience);
        Assert.Equal(
            member.Keys.Select(k => k.KeyId),
            leaf.Keys.Select(k => k.KeyId));

        // World-readable: every leaf on the machine runs as some user, and nothing in it is secret.
        Assert.True(File.GetUnixFileMode(FilePath).HasFlag(UnixFileMode.OtherRead));
        Assert.False(File.Exists(FilePath + ".tmp"));

        await member.StopAsync(default);
    }

    [Fact]
    public async Task A_session_the_anchor_signed_verifies_against_what_the_leaf_read()
    {
        ClusterSessionKeys member = await MemberAsync(Stated());
        Writer(member).Reconcile();
        var leaf = new HostSessionKeys(FilePath, NullLogger<HostSessionKeys>.Instance);

        var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
        string token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = Audience,
            SigningCredentials = _signer.Credentials,
        });

        TokenValidationResult result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = leaf.Issuer,
            ValidAudience = leaf.Audience,
            IssuerSigningKeys = leaf.Keys,
        });
        Assert.True(result.IsValid, result.Exception?.Message);

        await member.StopAsync(default);
    }

    [Fact]
    public async Task An_unchanged_answer_leaves_the_file_alone()
    {
        ClusterSessionKeys member = await MemberAsync(Stated());
        HostProviderFileWriter writer = Writer(member);
        writer.Reconcile();
        DateTime first = File.GetLastWriteTimeUtc(FilePath);

        await Task.Delay(20);
        writer.Reconcile();

        Assert.Equal(first, File.GetLastWriteTimeUtc(FilePath));
        await member.StopAsync(default);
    }

    [Fact]
    public async Task A_member_whose_holder_states_nothing_removes_the_file()
    {
        // A machine that has moved to another cluster and has not been told who holds its accounts yet:
        // a file naming the old cluster would have its leaves accept that cluster's sessions.
        File.WriteAllText(FilePath, new HostProviderFile(Issuer, Audience,
            EcdsaSessionSigner.ReadKeys(_signer.PublicKeysJson)!.Keys).ToJson());

        ClusterSessionKeys member = await MemberAsync(facts: null);
        Writer(member).Reconcile();

        Assert.False(File.Exists(FilePath));
        await member.StopAsync(default);
    }

    [Fact]
    public async Task A_member_that_has_not_read_the_cluster_yet_leaves_the_file_alone()
    {
        File.WriteAllText(FilePath, "what the last run wrote");
        var keys = new ClusterSessionKeys(
            new ClusterFacts(
                new MembersStore(new ClusterStore(Options, NullLogger<ClusterStore>.Instance)),
                new ClusterStateStore(new ClusterStore(Options, NullLogger<ClusterStore>.Instance), Options)),
            Options, NullLogger<ClusterSessionKeys>.Instance);

        Writer(keys).Reconcile();

        Assert.Equal("what the last run wrote", File.ReadAllText(FilePath));
    }

    [Fact]
    public void A_leaf_with_no_file_or_an_incomplete_one_accepts_nothing()
    {
        var leaf = new HostSessionKeys(FilePath, NullLogger<HostSessionKeys>.Instance);
        Assert.Null(leaf.Issuer);
        Assert.Empty(leaf.Keys);

        File.WriteAllText(FilePath, """{"issuer":"https://auth.anchors.test","audience":"","keys":[]}""");
        var another = new HostSessionKeys(FilePath, NullLogger<HostSessionKeys>.Instance);
        Assert.Null(another.Issuer);
        Assert.Null(another.Audience);
        Assert.Empty(another.Keys);
    }

    [Fact]
    public async Task A_leaf_follows_the_file_when_it_changes()
    {
        var clock = new ManualClock();
        var leaf = new HostSessionKeys(FilePath, NullLogger<HostSessionKeys>.Instance, clock);
        Assert.Null(leaf.Issuer);

        ClusterSessionKeys member = await MemberAsync(Stated());
        Writer(member).Reconcile();

        // Answered from the snapshot until the recheck interval has passed.
        Assert.Null(leaf.Issuer);
        clock.Advance(HostSessionKeys.RecheckInterval);
        Assert.Equal(Issuer, leaf.Issuer);

        await member.StopAsync(default);
    }

    private sealed class ManualClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UnixEpoch.AddYears(56);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}

/// <summary>
/// What every member says about who signs its sessions.
/// </summary>
public class ProtectedResourceMetadataTests
{
    [Fact]
    public void A_url_issuer_is_named_as_the_resources_authorization_server()
    {
        string? json = ProtectedResourceMetadata.Document("https://walter.nodes.test", "https://auth.anchors.test");

        using var document = System.Text.Json.JsonDocument.Parse(json!);
        Assert.Equal("https://walter.nodes.test", document.RootElement.GetProperty("resource").GetString());
        Assert.Equal("https://auth.anchors.test",
            Assert.Single(document.RootElement.GetProperty("authorization_servers").EnumerateArray()).GetString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("kgsm")]
    [InlineData("ftp://auth.anchors.test")]
    [InlineData("https://auth.anchors.test/?next=elsewhere")]
    public void An_issuer_a_browser_cannot_be_sent_to_is_not_named(string? issuer)
    {
        Assert.Null(ProtectedResourceMetadata.Document("https://walter.nodes.test", issuer));
    }
}
