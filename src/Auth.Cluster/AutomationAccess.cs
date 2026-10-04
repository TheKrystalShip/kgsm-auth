using TheKrystalShip.Auth.Access;

namespace TheKrystalShip.Auth.Cluster;

/// <summary>Whether an automation may do something now, and why not when it may not.</summary>
/// <param name="Allowed">Whether it may.</param>
/// <param name="Reason">Why not, as a sentence a status page or a record can carry. Null when allowed.</param>
public readonly record struct AutomationVerdict(bool Allowed, string? Reason)
{
    /// <summary>It may.</summary>
    public static AutomationVerdict Allow { get; } = new(true, null);

    /// <summary>It may not, for <paramref name="reason"/>.</summary>
    public static AutomationVerdict Block(string reason) => new(false, reason);
}

/// <summary>
/// Whether a leaf may do something it was switched on to do: both the leaf's own service account and the
/// person who switched it on must hold every action it performs, at the server, at that moment.
/// </summary>
/// <remarks>
/// <para>
/// <b>Author ∩ service, at every firing.</b> Writing a rule or a window, or switching on a sweep, never
/// lends its author the leaf's reach — an automation restarts only what its author could restart by
/// hand — and an author who loses access, is disabled or is deleted stops what they switched on at the
/// next firing. Nobody recorded as the author stops it the same way.
/// </para>
/// <para>
/// <b>The service account is derived, never configured:</b> <c>svc:&lt;component&gt;@&lt;node&gt;</c>, the
/// node being the member id the node on the leaf's machine writes into its host file. A setting naming
/// it would let whoever can edit the leaf's configuration point it at a more powerful account.
/// </para>
/// <para>
/// <b>"Cannot tell" blocks too.</b> A replica that cannot be read, a node that has not named itself, a
/// service account not yet created: each is a reason nothing runs, reported as itself. Running on a guess
/// is the one thing an automation must not do.
/// </para>
/// </remarks>
/// <param name="access">The leaf's view of the node's replica.</param>
/// <param name="component">The component half of the leaf's service account: <c>scheduler</c>, <c>reactor</c>.</param>
/// <param name="node">The node the leaf sits on, as that node wrote it, or null while it has not.</param>
public sealed class AutomationAccess(MemberAccess access, string component, Func<string?> node)
{
    /// <summary>The component half of the leaf's service account.</summary>
    public string Component { get; } = component;

    /// <summary>
    /// Whether the leaf may perform every one of <paramref name="actions"/> at the server
    /// <paramref name="instance"/> for <paramref name="author"/>. A blank author is nobody.
    /// </summary>
    /// <param name="actions">The actions the automation performs.</param>
    /// <param name="instance">The server's name.</param>
    /// <param name="installNonce">
    /// The install the server is, or null when it cannot be read — then the node, where a grant on one
    /// install does not reach.
    /// </param>
    /// <param name="author">The account that switched the automation on, or null for nobody.</param>
    /// <param name="ct">Cancels the read.</param>
    public async Task<AutomationVerdict> DecideAsync(
        IEnumerable<string> actions, string instance, string? installNonce, string? author, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(actions);

        if (string.IsNullOrWhiteSpace(author))
            author = null;

        if (node() is not { Length: > 0 } nodeId)
        {
            return AutomationVerdict.Block(
                $"this node has not said which it is, so the {Component}'s own account cannot be found");
        }

        if (await access.EvaluatorAsync(ct).ConfigureAwait(false) is not { } evaluator)
        {
            return AutomationVerdict.Block(
                "this node's copy of the cluster's accounts could not be read"
                + (access.UnavailableReason is { } why ? $" ({why})" : string.Empty));
        }

        ServiceIdentity service = new(Component, nodeId);
        string? serviceAccount = evaluator.Snapshot.Accounts.Values
            .FirstOrDefault(a => a.Service == service)?.AccountId;
        if (serviceAccount is null)
        {
            return AutomationVerdict.Block(
                $"the {Component} has no account on {nodeId} yet; it is made when the node reports what "
                + $"the {Component} requires");
        }

        // At the install, named by its nonce, so a grant on a server removed and installed again under the
        // same name does not carry across.
        AccessScope target = installNonce is { Length: > 0 } nonce
            ? AccessScope.ForInstance(nodeId, instance, nonce)
            : AccessScope.ForNode(nodeId);

        foreach (string action in actions)
        {
            AccessDecision decision = evaluator.AllowsAutomation(serviceAccount, author, action, target);
            if (!decision.Allowed)
                return AutomationVerdict.Block(Explain(decision, action, author, evaluator.Snapshot));
        }

        return AutomationVerdict.Allow;
    }

    private string Explain(AccessDecision decision, string action, string? author, AuthoritySnapshot snapshot)
    {
        string who = author is not null && snapshot.Accounts.TryGetValue(author, out AccessAccount? account)
            ? account.Name
            : "the account that set it up, which no longer exists";

        return decision.Reason switch
        {
            DenyReason.NoAuthor =>
                "nobody is recorded as having set this up; saving it again makes whoever saves it its author",
            DenyReason.AuthorDenied => $"{who} set this up and may not {action} here any more",
            DenyReason.Stale => "this node's copy of the cluster's accounts is out of date",
            DenyReason.UnknownAction => $"nothing in this cluster declares {action}, so only an Owner holds it",
            DenyReason.ContractOutdated => $"this {Component} is older than the cluster's accounts allow",
            _ => $"the {Component}'s own account does not hold {action} here",
        };
    }
}
