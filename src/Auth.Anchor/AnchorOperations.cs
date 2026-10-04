using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

using TheKrystalShip.Auth.Access;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// The action an anchor route requires, declared on the route and read by the handler that enforces it.
/// </summary>
/// <remarks>
/// A route that performs several actions carries one entry per value of the body field that says which
/// (<see cref="Field"/>, <see cref="Value"/>). The handler asks <c>Of</c> for its action, so the
/// action this anchor publishes for a route and the one it checks are the same entry.
/// </remarks>
/// <param name="Action">The <c>auth:*</c> action, checked cluster-wide.</param>
/// <param name="Field">The body field that picks among several actions, or null.</param>
/// <param name="Value">The field's value this entry answers for.</param>
internal sealed record AuthAction(string Action, string? Field = null, string? Value = null)
{
    /// <summary>The single action the current route declares.</summary>
    public static string Of(HttpContext ctx) =>
        ctx.GetEndpoint()?.Metadata.GetMetadata<AuthAction>()?.Action
        ?? throw new InvalidOperationException($"{ctx.Request.Method} {ctx.Request.Path} declares no action.");

    /// <summary>The action the current route declares for <paramref name="value"/> of its field.</summary>
    public static string Of(HttpContext ctx, string value) =>
        ctx.GetEndpoint()?.Metadata.GetOrderedMetadata<AuthAction>().FirstOrDefault(a => a.Value == value)?.Action
        ?? throw new InvalidOperationException($"{ctx.Request.Method} {ctx.Request.Path} declares no action for '{value}'.");
}

/// <summary>
/// What this anchor publishes at <c>GET /auth/cluster/operations</c>: every gated route and the action it
/// requires, so a client names no action of its own.
/// </summary>
/// <remarks>
/// Built from the anchor's own routes: each route's <see cref="AuthAction"/> metadata, the standard
/// surface's actions from <see cref="OwnSurfaceFilter"/>, and the authority edits from
/// <see cref="EditKind.Wire"/> — the table <see cref="AuthorityRules.Check"/> enforces. Nothing is
/// written here twice.
/// </remarks>
internal static class AnchorOperations
{
    /// <summary>The route authority edits are made at.</summary>
    public const string EditsRoute = "/auth/cluster/authority/edits";

    /// <summary>The route the rules are asked at without making a change — the same actions as an edit.</summary>
    public const string ChecksRoute = "/auth/cluster/authority/checks";

    /// <summary><c>GET /auth/cluster/operations</c>.</summary>
    public static Task Serve(HttpContext ctx) =>
        ctx.Response.WriteAsJsonAsync(
            Build(ctx.RequestServices.GetRequiredService<EndpointDataSource>()),
            AccessJsonContext.Default.OperationManifest, contentType: null, ctx.RequestAborted);

    public static OperationManifest Build(EndpointDataSource endpoints)
    {
        var ops = new List<Operation>();
        foreach (RouteEndpoint e in endpoints.Endpoints.OfType<RouteEndpoint>())
        {
            string route = OperationManifest.NormalizeRoute(e.RoutePattern.RawText ?? "");
            IReadOnlyList<string> methods = e.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? [];

            foreach (string method in methods)
            {
                foreach (AuthAction a in e.Metadata.GetOrderedMetadata<AuthAction>())
                    ops.Add(new Operation(method, route, a.Action, Operation.Scopes.Cluster, Field: a.Field, Value: a.Value));

                if (e.Metadata.GetMetadata<OwnSurfaceFilter.OwnSurface>() is not null)
                    ops.Add(new Operation(method, route, OwnSurfaceFilter.ActionFor(method, route), Operation.Scopes.Cluster));

                if (route is EditsRoute or ChecksRoute)
                {
                    foreach (EditKind kind in EditKind.Wire)
                    {
                        ops.Add(new Operation(method, route, kind.Action,
                            kind.ScopedByRequest ? Operation.Scopes.Request : Operation.Scopes.Cluster,
                            Target: kind.ScopedByRequest ? "scope" : null, Field: "kind", Value: kind.Name));
                    }
                }
            }
        }

        return OperationManifest.Of("", ops);
    }
}
