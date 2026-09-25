using System.Diagnostics.CodeAnalysis;

namespace TheKrystalShip.KGSM.Auth.Access;

/// <summary>
/// How wide a scope is. The ordinal runs from widest to narrowest, so a larger value is narrower.
/// </summary>
public enum ScopeKind
{
    /// <summary>The whole cluster.</summary>
    Cluster = 0,

    /// <summary>One node and every instance on it.</summary>
    Node = 1,

    /// <summary>One installed instance.</summary>
    Instance = 2,
}

/// <summary>Wire strings for <see cref="ScopeKind"/>, and the parse back.</summary>
public static class ScopeKinds
{
    public const string Cluster = "cluster";
    public const string Node = "node";
    public const string Instance = "instance";

    /// <summary>The wire form of a scope kind.</summary>
    public static string ToWire(ScopeKind kind) => kind switch
    {
        ScopeKind.Instance => Instance,
        ScopeKind.Node => Node,
        _ => Cluster,
    };

    /// <summary>
    /// The scope kind a string names, with anything unrecognised read as <see cref="ScopeKind.Cluster"/>.
    /// </summary>
    /// <remarks>
    /// Fail-closed: an action whose scope kind is cluster is granted only by a cluster-wide
    /// assignment, so an unreadable kind can never make a narrow assignment reach further.
    /// </remarks>
    public static ScopeKind Parse(string? wire) => wire?.Trim().ToLowerInvariant() switch
    {
        Instance => ScopeKind.Instance,
        Node => ScopeKind.Node,
        _ => ScopeKind.Cluster,
    };
}

/// <summary>
/// Where an assignment applies, and where an action is performed: the cluster, a node, or one
/// instance on a node.
/// </summary>
/// <remarks>
/// <para>
/// Written <c>cluster</c>, <c>node:&lt;id&gt;</c> or <c>instance:&lt;node&gt;/&lt;name&gt;#&lt;nonce&gt;</c>.
/// A node is named by its member id, which does not change for the member's life. An instance is
/// named by its node, its name and the nonce the engine wrote at install, so a reinstall under the
/// same name is a different instance and inherits nothing.
/// </para>
/// <para>
/// Scopes nest downward: the cluster contains every node, and a node contains every instance on it,
/// including ones installed after an assignment naming the node was made.
/// </para>
/// </remarks>
public readonly record struct AccessScope
{
    private const string NodePrefix = "node:";
    private const string InstancePrefix = "instance:";

    private AccessScope(ScopeKind kind, string? node, string? instance, string? nonce)
    {
        Kind = kind;
        Node = node;
        Instance = instance;
        Nonce = nonce;
    }

    /// <summary>How wide this scope is.</summary>
    public ScopeKind Kind { get; }

    /// <summary>The node's member id, for a node or an instance scope.</summary>
    public string? Node { get; }

    /// <summary>The instance's name, for an instance scope.</summary>
    public string? Instance { get; }

    /// <summary>The instance's install nonce, for an instance scope.</summary>
    public string? Nonce { get; }

    /// <summary>The whole cluster.</summary>
    public static AccessScope Cluster { get; } = new(ScopeKind.Cluster, null, null, null);

    /// <summary>One node, by member id.</summary>
    public static AccessScope ForNode(string node)
    {
        if (!IsPart(node))
            throw new ArgumentException($"'{node}' is not a node id.", nameof(node));

        return new AccessScope(ScopeKind.Node, node, null, null);
    }

    /// <summary>One instance, by its node, its name and its install nonce.</summary>
    public static AccessScope ForInstance(string node, string instance, string nonce)
    {
        if (!IsPart(node))
            throw new ArgumentException($"'{node}' is not a node id.", nameof(node));
        if (!IsPart(instance))
            throw new ArgumentException($"'{instance}' is not an instance name.", nameof(instance));
        if (!IsPart(nonce))
            throw new ArgumentException($"'{nonce}' is not an install nonce.", nameof(nonce));

        return new AccessScope(ScopeKind.Instance, node, instance, nonce);
    }

    /// <summary>
    /// Whether <paramref name="other"/> lies within this scope. Every scope contains itself.
    /// </summary>
    public bool Contains(AccessScope other) => Kind switch
    {
        ScopeKind.Cluster => true,
        ScopeKind.Node => other.Kind != ScopeKind.Cluster && string.Equals(Node, other.Node, StringComparison.Ordinal),
        _ => other.Kind == ScopeKind.Instance
             && string.Equals(Node, other.Node, StringComparison.Ordinal)
             && string.Equals(Instance, other.Instance, StringComparison.Ordinal)
             && string.Equals(Nonce, other.Nonce, StringComparison.Ordinal),
    };

    /// <summary>
    /// This scope, widened until it is no narrower than <paramref name="kind"/>: an instance widened to
    /// a node is the node it is on. A scope already as wide is returned as it is.
    /// </summary>
    /// <remarks>
    /// An action is evaluated at its target widened to the action's own scope kind, which is what
    /// keeps an assignment at a narrower scope from granting a wider-kind action there.
    /// </remarks>
    public AccessScope WidenedTo(ScopeKind kind)
    {
        if (Kind <= kind)
            return this;

        return kind == ScopeKind.Cluster ? Cluster : new AccessScope(ScopeKind.Node, Node, null, null);
    }

    /// <summary>The wire form: <c>cluster</c>, <c>node:&lt;id&gt;</c> or <c>instance:&lt;node&gt;/&lt;name&gt;#&lt;nonce&gt;</c>.</summary>
    public override string ToString() => Kind switch
    {
        ScopeKind.Node => NodePrefix + Node,
        ScopeKind.Instance => $"{InstancePrefix}{Node}/{Instance}#{Nonce}",
        _ => ScopeKinds.Cluster,
    };

    /// <summary>
    /// Read a scope's wire form. Returns <see langword="false"/> for anything malformed; a caller then
    /// has no scope, never a guessed one.
    /// </summary>
    public static bool TryParse(string? wire, [NotNullWhen(true)] out AccessScope? scope)
    {
        scope = null;
        if (wire is null)
            return false;

        if (wire == ScopeKinds.Cluster)
        {
            scope = Cluster;
            return true;
        }

        if (wire.StartsWith(NodePrefix, StringComparison.Ordinal))
        {
            string node = wire[NodePrefix.Length..];
            if (!IsPart(node))
                return false;

            scope = new AccessScope(ScopeKind.Node, node, null, null);
            return true;
        }

        if (wire.StartsWith(InstancePrefix, StringComparison.Ordinal))
        {
            string rest = wire[InstancePrefix.Length..];
            int slash = rest.IndexOf('/');
            int hash = rest.LastIndexOf('#');
            if (slash <= 0 || hash <= slash + 1 || hash == rest.Length - 1)
                return false;

            string node = rest[..slash];
            string instance = rest[(slash + 1)..hash];
            string nonce = rest[(hash + 1)..];
            if (!IsPart(node) || !IsPart(instance) || !IsPart(nonce))
                return false;

            scope = new AccessScope(ScopeKind.Instance, node, instance, nonce);
            return true;
        }

        return false;
    }

    /// <summary>Read a scope's wire form, throwing on anything malformed.</summary>
    public static AccessScope Parse(string wire) =>
        TryParse(wire, out AccessScope? scope)
            ? scope.Value
            : throw new FormatException($"'{wire}' is not a scope.");

    /// <summary>
    /// A node id, an instance name or a nonce: non-empty, and free of the separators the wire form is
    /// split on and of whitespace, so every scope has exactly one spelling.
    /// </summary>
    private static bool IsPart(string? part)
    {
        if (string.IsNullOrEmpty(part))
            return false;

        foreach (char c in part)
        {
            if (c is '/' or '#' or ':' || char.IsWhiteSpace(c) || char.IsControl(c))
                return false;
        }

        return true;
    }
}
