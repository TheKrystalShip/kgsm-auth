using System.Net;
using System.Net.Http.Json;

using TheKrystalShip.Auth.Access;

namespace TheKrystalShip.Auth.Anchor.Tests;

/// <summary>
/// <c>GET /auth/cluster/operations</c>: every gated route the anchor serves and the action it requires,
/// built from the routes and the edit table the rules enforce — so a client is told exactly what is
/// checked.
/// </summary>
[Collection(AnchorCollection.Name)]
public sealed class AnchorOperationsTests(AnchorFixture anchor)
{
    // The daemon's own Program, so the document is built from the routes it really maps.
    private async Task<OperationManifest> ReadAsync()
    {
        HttpResponseMessage response = await anchor.Client.GetAsync("/auth/cluster/operations");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync(AccessJsonContext.Default.OperationManifest))!;
    }

    [Fact]
    public async Task EveryEditKind_IsPublishedOnTheEditsRoute_WithTheActionTheRulesCheck()
    {
        OperationManifest m = await ReadAsync();

        foreach (EditKind kind in EditKind.Wire)
        {
            Operation op = Assert.Single(m.Operations,
                o => o.Method == "POST" && o.Route == AnchorOperations.EditsRoute && o.Value == kind.Name);
            Assert.Equal(kind.Action, op.Action);
            Assert.Equal("kind", op.Field);
            Assert.Equal(kind.ScopedByRequest ? Operation.Scopes.Request : Operation.Scopes.Cluster, op.Scope);
        }
    }

    [Fact]
    public void EveryPublishedEditKind_ParsesToAnEditOfThatKind()
    {
        // The request parser spells the kinds; the table publishes them. A kind the parser does not
        // read, or reads as another kind, would be published with an action the rules never check.
        foreach (EditKind kind in EditKind.Wire)
        {
            AuthorityEdit? edit = AuthorityEndpoints.ToEdit(new AuthorityEditRequest(
                Version: 1, Kind: kind.Name, RoleId: "r", PermissionId: "p", AccountId: "a", AssignmentId: "x",
                Name: "n", Rank: 1, PermissionIds: ["p"], Actions: ["a:b"], Scope: "cluster", Action: "a:b"));
            Assert.NotNull(edit);
            Assert.Same(kind, edit!.Kind);
        }
    }

    [Fact]
    public async Task TheAccountRoutes_AreEachPublishedWithTheActionTheirHandlerChecks()
    {
        OperationManifest m = await ReadAsync();

        Assert.Contains(m.Operations, o => o is { Method: "POST", Route: "/auth/cluster/users" } && o.Action == AuthActions.AccountsCreate);
        Assert.Contains(m.Operations, o => o is { Method: "DELETE", Route: "/auth/cluster/users/{userId}" } && o.Action == AuthActions.AccountsDelete);
        Assert.Contains(m.Operations, o => o is { Method: "PATCH", Route: "/auth/cluster/users/{userId}", Field: "status", Value: "disabled" }
            && o.Action == AuthActions.AccountsDisable);
        Assert.Contains(m.Operations, o => o is { Method: "PATCH", Route: "/auth/cluster/users/{userId}", Field: "status", Value: "active" }
            && o.Action == AuthActions.AccountsApprove);
        Assert.Contains(m.Operations, o => o is { Method: "GET", Route: "/auth/cluster/users/{userId}/sessions" } && o.Action == AuthActions.AccountsDisable);
    }

    [Fact]
    public async Task TheAnchorsOwnSurface_IsPublishedWithTheStandardActions()
    {
        OperationManifest m = await ReadAsync();

        Assert.Contains(m.Operations, o => o.Route.StartsWith("/auth/", StringComparison.Ordinal)
            && o.Route.EndsWith("/config", StringComparison.Ordinal) && o.Method == "PUT" && o.Action == "auth:config.write");
        Assert.Contains(m.Operations, o => o.Route.StartsWith("/auth/", StringComparison.Ordinal)
            && o.Route.Contains("/logs", StringComparison.Ordinal) && o.Action == "auth:journal.read");
    }
}
