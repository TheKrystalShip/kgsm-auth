using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Access;

/// <summary>
/// What <c>GET /me/access</c> answers: the caller's effective actions at every target the answering
/// member holds, already evaluated.
/// </summary>
/// <remarks>
/// <para>
/// A surface gates a control by looking an action up here. It holds no copy of the rules, so it cannot
/// disagree with them, and a control for a target the report does not name is closed.
/// </para>
/// <para>
/// Each member answers for its own targets: a node for itself and its instances, an anchor for the
/// actions it performs. An instance is keyed <c>&lt;node&gt;/&lt;name&gt;#&lt;nonce&gt;</c>.
/// </para>
/// </remarks>
/// <param name="Version">The authority version the answer was evaluated at.</param>
/// <param name="Current">Whether the answering member was current: when it was not, only reads are listed.</param>
/// <param name="Cluster">The actions allowed cluster-wide.</param>
/// <param name="Nodes">The actions allowed on each node, by member id.</param>
/// <param name="Instances">The actions allowed on each instance.</param>
public sealed record AccessReport(
    [property: JsonPropertyName("version")] long Version,
    [property: JsonPropertyName("current")] bool Current,
    [property: JsonPropertyName("cluster")] IReadOnlyList<string> Cluster,
    [property: JsonPropertyName("nodes")] IReadOnlyDictionary<string, IReadOnlyList<string>> Nodes,
    [property: JsonPropertyName("instances")] IReadOnlyDictionary<string, IReadOnlyList<string>> Instances)
{
    /// <summary>
    /// The report for <paramref name="accountId"/> at <paramref name="targets"/>, listing only the
    /// actions <paramref name="include"/> accepts — the ones the answering member performs.
    /// </summary>
    /// <remarks>
    /// The cluster is always answered. A target named twice is answered once, and one where nothing is
    /// allowed is left out, so an empty report is a caller who may do nothing here.
    /// </remarks>
    public static AccessReport For(
        AccessEvaluator evaluator, string accountId, IEnumerable<AccessScope> targets, Func<string, bool> include,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(evaluator);
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(include);

        string[] Allowed(AccessScope target) =>
            [.. evaluator.EffectiveActions(accountId, target).Where(include).Order(StringComparer.Ordinal)];

        Dictionary<string, IReadOnlyList<string>> nodes = new(StringComparer.Ordinal);
        Dictionary<string, IReadOnlyList<string>> instances = new(StringComparer.Ordinal);

        foreach (AccessScope target in targets.Distinct())
        {
            if (target.Kind == ScopeKind.Cluster)
                continue;

            string[] actions = Allowed(target);
            if (actions.Length == 0)
                continue;

            if (target.Kind == ScopeKind.Node)
                nodes[target.Node!] = actions;
            else
                instances[$"{target.Node}/{target.Instance}#{target.Nonce}"] = actions;
        }

        return new AccessReport(
            evaluator.Snapshot.Version, evaluator.Snapshot.Freshness.IsCurrent(now),
            Allowed(AccessScope.Cluster), nodes, instances);
    }
}
