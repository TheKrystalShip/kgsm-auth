namespace TheKrystalShip.KGSM.Auth.Access.Tests;

/// <summary>
/// The catalog every member's report adds up to, and the manifests those reports are made of.
/// </summary>
public sealed class CatalogUnionTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "kgsm-manifests-" + Guid.NewGuid().ToString("N"));

    public CatalogUnionTests() => Directory.CreateDirectory(_directory);

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static ActionManifest Manifest(string version, string title) =>
        new(1, "reactor", version, [new ManifestAction("rules.write", title, "write", "node", null)], []);

    private static IReadOnlyList<CatalogEntry> Union(params (string Member, ActionManifest Manifest)[] reports) =>
        CatalogUnion.Of(reports.ToDictionary(r => r.Member, r => new MemberCatalogReport(false, [r.Manifest])));

    [Theory]
    [InlineData("0.4.0", "0.10.0")]
    [InlineData("1.0.0-dev.3", "1.0.0")]
    [InlineData("1.0.0-dev.2", "1.0.0-dev.3")]
    [InlineData("not-a-version", "0.0.1")]
    [InlineData(null, "0.0.1")]
    public void TheHighestVersionsWordingWins(string? older, string newer)
    {
        CatalogEntry entry = Union(("walter", Manifest(older!, "Old wording")), ("jessie", Manifest(newer, "New wording"))).Single();

        Assert.Equal("New wording", entry.Action.Title);
        Assert.Equal(2, entry.DeclaredBy.Count);
    }

    [Fact]
    public void AtOneVersionTheMemberThatSortsFirstWinsWhateverOrderReportsArrive()
    {
        CatalogEntry one = Union(("walter", Manifest("1.0.0", "Walter's")), ("jessie", Manifest("1.0.0", "Jessie's"))).Single();
        CatalogEntry two = Union(("jessie", Manifest("1.0.0", "Jessie's")), ("walter", Manifest("1.0.0", "Walter's"))).Single();

        Assert.Equal("Jessie's", one.Action.Title);
        Assert.Equal(one.Action, two.Action);
        Assert.Equal(one.DeclaredBy, two.DeclaredBy);
    }

    [Fact]
    public void AnEntryThatIsNotAnActionIsLeftOut()
    {
        ActionManifest manifest = new(1, "reactor", "1.0.0",
        [
            new ManifestAction("rules.write", "Change rules", "write", "node", null),
            new ManifestAction("Bad Id", "Broken", "write", "node", null),
            new ManifestAction("untitled", " ", "write", "node", null),
        ], []);

        Assert.Equal(["reactor:rules.write"], manifest.CatalogActions().Select(a => a.Id));
    }

    [Fact]
    public void AManifestIsReadFromDisk()
    {
        string path = Path.Combine(_directory, "reactor.json");
        File.WriteAllText(path, """
            { "schemaVersion": 1, "component": "reactor", "version": "0.4.0",
              "actions": [ { "id": "rules.write", "title": "Change reactor rules", "effect": "write", "scope": "node" },
                           { "id": "view.write", "title": "Change own view", "effect": "write", "scope": "cluster", "self": true } ],
              "requires": [ { "action": "kgsm:server.restart", "scope": "instance", "why": "restart" } ] }
            """);

        ActionManifest? manifest = ActionManifests.TryRead(path, out string? problem);

        Assert.Null(problem);
        CatalogAction[] actions = [.. manifest!.CatalogActions()];
        Assert.Equal(new CatalogAction("reactor:rules.write", "Change reactor rules", ActionEffect.Write, ScopeKind.Node), actions[0]);
        Assert.True(actions[1].Self);
        Assert.Equal("kgsm:server.restart", manifest.Requires!.Single().Action);
    }

    [Theory]
    [InlineData("""{ "schemaVersion": 2, "component": "reactor", "actions": [] }""", "schema version 2")]
    [InlineData("""{ "schemaVersion": 1, "component": "Re Actor", "actions": [] }""", "not a component")]
    [InlineData("""{ "schemaVersion": 1, "component": """, "")]
    public void AManifestThatCannotBeTrustedIsRefusedWithTheReason(string json, string reason)
    {
        string path = Path.Combine(_directory, "bad.json");
        File.WriteAllText(path, json);

        Assert.Null(ActionManifests.TryRead(path, out string? problem));
        Assert.Contains(reason, problem);
    }
}
