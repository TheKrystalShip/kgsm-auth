using System.Text.Json.Serialization;

namespace TheKrystalShip.Auth.Access;

/// <summary>
/// The operations a member serves, and the action each one requires: what a client gates a control on.
/// </summary>
/// <remarks>
/// <para>
/// <b>A client names no action.</b> It knows the request it is about to make — the method, the path, the
/// body — because it has to make it, and it asks the member that will answer that request which action
/// it needs and where. The member builds this document from the same metadata it enforces with, so
/// nothing is enforced that is not published here, and a renamed action reaches every client the
/// moment the member serving it is deployed.
/// </para>
/// <para>
/// A caller's answer is still <c>GET /me/access</c>, from the same member: this document says which
/// action a request is, the report says whether the caller holds it at the target.
/// </para>
/// </remarks>
/// <param name="SchemaVersion">The shape's version. A client that does not know it gates nothing open.</param>
/// <param name="Base">The path prefix every route is under on this member (<c>/api/v1</c>), or empty.</param>
/// <param name="Operations">Every gated operation, in route order.</param>
public sealed record OperationManifest(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("base")] string Base,
    [property: JsonPropertyName("operations")] IReadOnlyList<Operation> Operations)
{
    /// <summary>The only schema version this shape is.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>
    /// The document for <paramref name="operations"/>: methods upper-cased, routes with one leading slash
    /// and none trailing, duplicates dropped, sorted so two builds of one member serve identical bytes.
    /// </summary>
    public static OperationManifest Of(string basePath, IEnumerable<Operation> operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        Operation[] normalized = [.. operations
            .Select(o => o with { Method = o.Method.ToUpperInvariant(), Route = NormalizeRoute(o.Route) })
            .Distinct()
            .OrderBy(o => o.Route, StringComparer.Ordinal)
            .ThenBy(o => o.Method, StringComparer.Ordinal)
            .ThenBy(o => o.Value ?? "", StringComparer.Ordinal)];
        string prefix = string.IsNullOrWhiteSpace(basePath) ? "" : NormalizeRoute(basePath);
        return new OperationManifest(CurrentSchemaVersion, prefix, normalized);
    }

    /// <summary>A route with exactly one leading slash and no trailing one.</summary>
    public static string NormalizeRoute(string route)
    {
        ArgumentNullException.ThrowIfNull(route);
        string trimmed = route.Trim().Trim('/');
        return trimmed.Length == 0 ? "/" : "/" + trimmed;
    }
}

/// <summary>One request a member serves, and what it takes to make it.</summary>
/// <param name="Method">The HTTP method, upper-case.</param>
/// <param name="Route">
/// The route template under the document's base, with parameters in braces (<c>/servers/{id}/backups</c>).
/// A client matches a concrete path against it segment by segment, and a literal segment is more
/// specific than a parameter, so <c>/hosts/{id}/services/kgsm/config</c> answers for the engine where
/// <c>/hosts/{id}/services/{leaf}/config</c> answers for every other leaf.
/// </param>
/// <param name="Action">
/// The action the operation requires. It may name a route parameter in braces —
/// <c>{leaf}:config.write</c> — which the client fills from the path it matched.
/// </param>
/// <param name="Scope">
/// Where the action is checked: <c>cluster</c>; <c>node</c>, the member itself; <c>instance</c>, the
/// server named by <see cref="Target"/>; or <c>request</c>, a scope the request is about.
/// </param>
/// <param name="Target">
/// For an <c>instance</c> operation, the route parameter naming the server; for a <c>request</c> one, the
/// body field carrying the scope.
/// </param>
/// <param name="Field">
/// For a route that performs several actions, the body field that says which — a lifecycle command's
/// <c>verb</c>, an authority edit's <c>kind</c>. Null when the route is one action.
/// </param>
/// <param name="Value">The value of <see cref="Field"/> this entry answers for.</param>
public sealed record Operation(
    [property: JsonPropertyName("method")] string Method,
    [property: JsonPropertyName("route")] string Route,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("target")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Target = null,
    [property: JsonPropertyName("field")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Field = null,
    [property: JsonPropertyName("value")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Value = null)
{
    /// <summary>The scope words an operation is checked at.</summary>
    public static class Scopes
    {
        /// <summary>Cluster-wide.</summary>
        public const string Cluster = "cluster";

        /// <summary>The member serving the operation.</summary>
        public const string Node = "node";

        /// <summary>One server, named by the operation's <see cref="Operation.Target"/> parameter.</summary>
        public const string Instance = "instance";

        /// <summary>
        /// The scope the request is about, written as an <see cref="AccessScope"/> — in the body field
        /// named by <see cref="Operation.Target"/> where the request carries it (an assignment's
        /// <c>scope</c>), and otherwise known to the client from what it is acting on (the assignment it
        /// revokes).
        /// </summary>
        public const string Request = "request";
    }
}
