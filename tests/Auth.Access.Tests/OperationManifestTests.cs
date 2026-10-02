using System.Text.Json;

namespace TheKrystalShip.KGSM.Auth.Access.Tests;

/// <summary>The operations document: one spelling of every route, whatever order a member found them in.</summary>
public class OperationManifestTests
{
    [Fact]
    public void RoutesAndMethodsAreNormalizedAndDuplicatesDropped()
    {
        OperationManifest m = OperationManifest.Of("api/v1/", [
            new Operation("post", "servers/{id}/backups/", "kgsm:server.backups.create", Operation.Scopes.Instance, "id"),
            new Operation("POST", "/servers/{id}/backups", "kgsm:server.backups.create", Operation.Scopes.Instance, "id"),
            new Operation("get", "/alerts", "api:alerts.read", Operation.Scopes.Node),
        ]);

        Assert.Equal("/api/v1", m.Base);
        Assert.Equal(2, m.Operations.Count);
        Assert.Equal(new Operation("GET", "/alerts", "api:alerts.read", "node"), m.Operations[0]);
        Assert.Equal("POST", m.Operations[1].Method);
        Assert.Equal("/servers/{id}/backups", m.Operations[1].Route);
    }

    [Fact]
    public void ARouteOfSeveralActionsIsOneEntryPerValue_InValueOrder()
    {
        OperationManifest m = OperationManifest.Of("", [
            new Operation("POST", "/servers/{id}/commands", "kgsm:server.stop", "instance", "id", "verb", "stop"),
            new Operation("POST", "/servers/{id}/commands", "kgsm:server.restart", "instance", "id", "verb", "restart"),
        ]);

        Assert.Equal(["restart", "stop"], m.Operations.Select(o => o.Value));
        Assert.Equal("", m.Base);
    }

    [Fact]
    public void TheWireShapeIsCamelCaseAndOmitsWhatIsAbsent()
    {
        string json = JsonSerializer.Serialize(
            OperationManifest.Of("/api/v1", [new Operation("GET", "/alerts", "api:alerts.read", "node")]),
            AccessJsonContext.Default.OperationManifest);

        Assert.Contains("\"schemaVersion\":1", json);
        Assert.Contains("\"route\":\"/alerts\"", json);
        Assert.DoesNotContain("\"field\"", json);
        Assert.DoesNotContain("\"target\"", json);
    }
}
