using TheKrystalShip.Auth.Access;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// The anchor's action manifest, as its build wrote it, against <see cref="AuthActions"/>, which names
/// the same actions for every evaluator. The two are declared apart, so this is what holds them together.
/// </summary>
public class AnchorManifestTests
{
    /// <summary>The manifest the anchor's build wrote, found by walking up from the test's output.</summary>
    private static ActionManifest Manifest()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string path = Path.Combine(dir.FullName, "deploy", "tks-auth.anchor.actions.json");
            if (File.Exists(path))
                return ActionManifests.TryRead(path, out string? problem) ?? throw new InvalidOperationException(problem);
        }

        throw new FileNotFoundException("deploy/tks-auth.anchor.actions.json was not found above the test output");
    }

    [Fact]
    public void EveryAuthAction_IsInTheManifest_AsAuthActionsDeclaresIt()
    {
        ActionManifest manifest = Manifest();
        Assert.Equal("auth", manifest.Component);

        foreach (CatalogAction declared in AuthActions.Declared)
        {
            string local = declared.Id["auth:".Length..];
            ManifestAction? written = manifest.Actions.SingleOrDefault(a => a.Id == local);
            Assert.True(written is not null, $"{declared.Id} is not in the anchor's manifest");
            Assert.Equal(declared.Title, written.Title);
            Assert.Equal(ActionEffects.ToWire(declared.Effect), written.Effect);
            Assert.Equal(ScopeKinds.ToWire(declared.Scope), written.Scope);
        }
    }

    [Fact]
    public void TheManifestDeclaresNoAuthActionAuthActionsDoesNotName()
    {
        string[] named = [.. AuthActions.Declared.Select(a => a.Id["auth:".Length..])];
        string[] standard = ["config.read", "config.write", "journal.read", "lifecycle.restart"];

        Assert.All(Manifest().Actions ?? [], a => Assert.True(named.Contains(a.Id) || standard.Contains(a.Id), $"auth:{a.Id} is not in AuthActions"));
    }
}
