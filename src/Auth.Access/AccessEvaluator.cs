namespace TheKrystalShip.Auth.Access;

/// <summary>Why an action was refused.</summary>
public enum DenyReason
{
    /// <summary>Not refused.</summary>
    None = 0,

    /// <summary>This build evaluates by a contract older than the cluster's minimum.</summary>
    ContractOutdated,

    /// <summary>The action id is not a well-formed action id.</summary>
    MalformedAction,

    /// <summary>No account has this id.</summary>
    NoAccount,

    /// <summary>The account is awaiting approval and holds nothing.</summary>
    AccountPending,

    /// <summary>The account is switched off.</summary>
    AccountDisabled,

    /// <summary>The replica is past its staleness bound and the action is not a read.</summary>
    Stale,

    /// <summary>No member has declared the action; only an Owner performs it.</summary>
    UnknownAction,

    /// <summary>No assignment, requirement or implicit role grants the action at the target.</summary>
    NotGranted,

    /// <summary>An automation has no person recorded as its author.</summary>
    NoAuthor,

    /// <summary>The person who authored an automation may not perform the action themselves.</summary>
    AuthorDenied,
}

/// <summary>An answer to an access question: allowed, or refused with the reason.</summary>
/// <param name="Allowed">Whether the action may be performed.</param>
/// <param name="Reason">Why not, when it may not.</param>
/// <param name="Detail">The account, action or author the reason is about, for a message.</param>
public readonly record struct AccessDecision(bool Allowed, DenyReason Reason, string? Detail = null)
{
    /// <summary>Allowed.</summary>
    public static AccessDecision Allow { get; } = new(true, DenyReason.None);

    /// <summary>Refused, for <paramref name="reason"/>.</summary>
    public static AccessDecision Deny(DenyReason reason, string? detail = null) => new(false, reason, detail);
}

/// <summary>
/// The one function every access question goes through: may this account perform this action at
/// this target.
/// </summary>
/// <remarks>
/// <para>
/// The questions are asked in one order, and the order is the contract:
/// </para>
/// <list type="number">
/// <item>Is the account active? A pending account holds nothing; a disabled one does not authenticate.</item>
/// <item>Is the replica current? If not, only a <c>read</c> is served — to Owners as well.</item>
/// <item>Is the account an Owner? Allowed, including actions no member has declared.</item>
/// <item>Is it a self action, asked by an active person? Allowed.</item>
/// <item>
///   Does any assignment whose scope contains the target grant it, or <c>everyone</c> for a person, or
///   an approved requirement for a service? Allowed.
/// </item>
/// <item>For an automation, the person who authored it must pass steps 1–5 as well.</item>
/// </list>
/// <para>
/// The target is widened to the action's own scope kind before anything is matched against it, so an
/// assignment at a narrower scope than an action's kind never grants that action.
/// </para>
/// <para>
/// There is no deny: every answer is a union of grants, so why somebody may do something is always
/// answered by listing the grants that allow it.
/// </para>
/// </remarks>
public sealed class AccessEvaluator(AuthoritySnapshot snapshot, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// <summary>The snapshot this evaluator answers from.</summary>
    public AuthoritySnapshot Snapshot { get; } = snapshot;

    /// <summary>
    /// Whether <paramref name="accountId"/> may perform <paramref name="action"/> at
    /// <paramref name="target"/>, on its own behalf.
    /// </summary>
    public AccessDecision Allows(string accountId, string action, AccessScope target) =>
        Evaluate(accountId, action, target, _clock.GetUtcNow());

    /// <summary>
    /// Whether a service may perform <paramref name="action"/> at <paramref name="target"/> as part of
    /// an automation <paramref name="authorId"/> switched on.
    /// </summary>
    /// <remarks>
    /// Both the service and the author must hold the action at the target, at this moment. Writing a
    /// rule never lends its author the service's reach, and an author who has since lost access stops
    /// their automations at the next firing. An automation nobody authored is refused.
    /// </remarks>
    public AccessDecision AllowsAutomation(string serviceAccountId, string? authorId, string action, AccessScope target)
    {
        DateTimeOffset now = _clock.GetUtcNow();

        AccessDecision service = Evaluate(serviceAccountId, action, target, now);
        if (!service.Allowed)
            return service;

        if (authorId is null)
            return AccessDecision.Deny(DenyReason.NoAuthor, action);

        if (!Snapshot.Accounts.TryGetValue(authorId, out AccessAccount? author) || author.Kind != AccountKind.Person)
            return AccessDecision.Deny(DenyReason.AuthorDenied, authorId);

        AccessDecision byAuthor = Evaluate(authorId, action, target, now);
        return byAuthor.Allowed ? byAuthor : AccessDecision.Deny(DenyReason.AuthorDenied, authorId);
    }

    /// <summary>
    /// Whether <paramref name="accountId"/> may perform every action at every target, including actions
    /// no member has declared: an active Owner, on a replica that is current and evaluates by the
    /// cluster's contract.
    /// </summary>
    /// <remarks>
    /// Steps 1 to 3 of the order, for an action that is not a read. A catalog lists only declared
    /// actions, so this is the one answer a list of them cannot give.
    /// </remarks>
    public bool HoldsEverything(string accountId) =>
        AccessContract.Version >= Snapshot.MinimumContractVersion
        && Snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account)
        && account.Status == AccountStatus.Active
        && Snapshot.Freshness.IsCurrent(_clock.GetUtcNow())
        && Snapshot.IsOwner(accountId);

    /// <summary>
    /// Every catalog action <paramref name="accountId"/> may perform at <paramref name="target"/>:
    /// what <c>GET /me/access</c> reports for one target.
    /// </summary>
    public IReadOnlySet<string> EffectiveActions(string accountId, AccessScope target)
    {
        DateTimeOffset now = _clock.GetUtcNow();
        HashSet<string> actions = new(StringComparer.Ordinal);

        foreach (string action in Snapshot.Catalog.Keys)
        {
            if (Evaluate(accountId, action, target, now).Allowed)
                actions.Add(action);
        }

        return actions;
    }

    private AccessDecision Evaluate(string accountId, string action, AccessScope target, DateTimeOffset now)
    {
        if (AccessContract.Version < Snapshot.MinimumContractVersion)
            return AccessDecision.Deny(DenyReason.ContractOutdated, Snapshot.MinimumContractVersion.ToString(System.Globalization.CultureInfo.InvariantCulture));

        if (!ActionIds.IsValid(action))
            return AccessDecision.Deny(DenyReason.MalformedAction, action);

        // 1 · the account itself.
        if (!Snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account))
            return AccessDecision.Deny(DenyReason.NoAccount, accountId);

        switch (account.Status)
        {
            case AccountStatus.Pending:
                return AccessDecision.Deny(DenyReason.AccountPending, accountId);
            case AccountStatus.Disabled:
                return AccessDecision.Deny(DenyReason.AccountDisabled, accountId);
        }

        // 2 · a stale replica serves reads only. An action the replica does not know has no effect it
        // can vouch for, so it is not a read.
        Snapshot.Catalog.TryGetValue(action, out CatalogAction? declared);
        if (!Snapshot.Freshness.IsCurrent(now) && declared?.Effect != ActionEffect.Read)
            return AccessDecision.Deny(DenyReason.Stale, action);

        // 3 · Owner holds everything, declared or not.
        if (Snapshot.IsOwner(accountId))
            return AccessDecision.Allow;

        if (declared is null)
            return AccessDecision.Deny(DenyReason.UnknownAction, action);

        // 4 · a person's own records.
        if (declared.Self)
        {
            return account.Kind == AccountKind.Person
                ? AccessDecision.Allow
                : AccessDecision.Deny(DenyReason.NotGranted, action);
        }

        // 5 · the union of what is granted where the target is.
        AccessScope at = target.WidenedTo(declared.Scope);

        foreach (Assignment assignment in Snapshot.AssignmentsOf(accountId))
        {
            if (assignment.Scope.Contains(at) && Snapshot.ActionsOf(assignment.RoleId).Contains(action))
                return AccessDecision.Allow;
        }

        if (account.Kind == AccountKind.Person)
        {
            if (Snapshot.ActionsOf(BuiltInRoles.EveryoneId).Contains(action))
                return AccessDecision.Allow;
        }
        else
        {
            foreach (ServiceRequirement requirement in Snapshot.RequirementsOf(accountId))
            {
                if (requirement.Grants && requirement.Action == action && requirement.Grant!.Value.Contains(at))
                    return AccessDecision.Allow;
            }
        }

        return AccessDecision.Deny(DenyReason.NotGranted, action);
    }
}
