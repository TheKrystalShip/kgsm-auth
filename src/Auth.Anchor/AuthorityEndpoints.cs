using TheKrystalShip.Api.Contracts;
using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>A signed-in person as the authority store knows them, or why there is none.</summary>
/// <param name="Refusal">Why there is no caller, or <see cref="CallerRefusal.None"/>.</param>
/// <param name="AccountId">The account the session's identity belongs to.</param>
/// <param name="SessionId">The session the bearer belongs to.</param>
/// <param name="Actor">The actor string the journal names them by.</param>
/// <param name="Identity">The identity the session proved.</param>
internal readonly record struct AccessCaller(
    CallerRefusal Refusal, string? AccountId, string? SessionId, string? Actor, KgsmIdentity? Identity = null);

/// <summary>
/// Resolves the caller behind a request against the authority store: the session, then the account its
/// identity is a credential of, then whether that account is switched off.
/// </summary>
/// <remarks>
/// Nothing about what the caller may do is resolved here or read off the token. The evaluator answers
/// that, per action, from the snapshot the request is decided against.
/// </remarks>
internal sealed class AuthorityCaller(SessionReader sessions, AnchorAuthority authority)
{
    /// <exception cref="InvalidOperationException">The store holds no authority.</exception>
    internal async Task<AccessCaller> ResolveAsync(HttpRequest request, CancellationToken ct)
    {
        (CallerRefusal refusal, string? sessionId, KgsmIdentity? identity) =
            await sessions.ReadAsync(request, ct).ConfigureAwait(false);

        if (refusal != CallerRefusal.None || identity is null)
            return new AccessCaller(refusal, null, sessionId, null);

        SqliteAuthorityStore store = authority.Store
            ?? throw new InvalidOperationException(authority.UnavailableReason ?? "The account store holds no authority.");

        // An account deleted since the session was minted is a stranger holding a token.
        string? accountId = await store.FindAccountIdByHandleAsync(identity.Handle, ct).ConfigureAwait(false);
        if (accountId is null)
            return new AccessCaller(CallerRefusal.Unauthenticated, null, sessionId, null);

        AuthoritySnapshot snapshot = await authority.Source!.CurrentAsync(ct).ConfigureAwait(false);
        if (snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account) && account.Status == AccountStatus.Disabled)
            return new AccessCaller(CallerRefusal.AccountDisabled, accountId, sessionId, identity.ActorString, identity);

        return new AccessCaller(CallerRefusal.None, accountId, sessionId, identity.ActorString, identity);
    }
}

/// <summary>
/// Administering who may do what: reading the authority, changing it, and a caller's own access here.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every change goes through the store's rules, and every refusal says why.</b>
/// <see cref="AuthorityRules"/> decides each edit against the snapshot it will land on; this answers
/// with the rule's code — <c>not_permitted</c>, <c>rank_not_below</c>, <c>not_held</c> with the actions
/// not held, <c>permission_held_above</c>, <c>last_owner</c> and the rest — so a page shows the reason
/// rather than hiding the control.
/// </para>
/// <para>
/// <b>An edit is decided before it asks for a recent sign-in.</b> Every edit is an <c>auth:*</c> action,
/// and one the rules refuse is refused; only one they allow is sent to prove a credential again,
/// answered <c>reauth_required</c>.
/// </para>
/// <para>
/// <b>An edit names the version it was made against</b> and one made against an older version is
/// answered <c>409 stale_authority</c> with the authority as it stands, so two people editing at once
/// never overwrite each other.
/// </para>
/// </remarks>
internal static class AuthorityEndpoints
{
    /// <summary><c>GET /auth/cluster/authority</c>: everything that decides access, for a caller who administers some of it.</summary>
    internal static async Task Read(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await RequireCallerAsync(ctx) is not { } caller)
            return;

        AnchorAuthority authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>();
        AccessEvaluator evaluator = new(await authority.Source!.CurrentAsync(ctx.RequestAborted));
        if (!Administers(evaluator, caller.AccountId!))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "not_permitted",
                "You hold no action that administers access.");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            await ViewAsync(authority.Store!, ctx.RequestAborted), AuthorityWireJson.Default.AuthorityView);
    }

    /// <summary><c>POST /auth/cluster/authority/edits</c>: make one change.</summary>
    internal static async Task Edit(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await RequireCallerAsync(ctx) is not { } caller)
            return;

        AuthorityEditRequest? body = await Endpoints.ReadBodyAsync(ctx, AuthorityWireJson.Default.AuthorityEditRequest);
        if (body?.Version is not { } version || ToEdit(body) is not { } edit)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request",
                "The edit names no version, no kind this anchor knows, or not what that kind needs.");
            return;
        }

        AnchorAuthority authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>();
        SqliteAuthorityStore store = authority.Store!;
        AuthoritySnapshot snapshot = await authority.Source!.CurrentAsync(ctx.RequestAborted);

        if (snapshot.Version != version)
        {
            await StaleAsync(ctx, store);
            return;
        }

        if (AuthorityRules.Check(snapshot, caller.AccountId!, edit) is { } refused)
        {
            await RefuseAsync(ctx, refused);
            return;
        }

        if (!await RecentlyProvedAsync(ctx, caller.SessionId!))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "reauth_required",
                "Prove it is you again to change who may do what.");
            return;
        }

        AuthorityWrite write;
        try
        {
            write = await store.ApplyAsync(caller.AccountId!, edit, version, DateTimeOffset.UtcNow, ctx.RequestAborted);
        }
        catch (StaleAuthorityException)
        {
            await StaleAsync(ctx, store);
            return;
        }
        catch (AuthorityRefusedException e)
        {
            await RefuseAsync(ctx, e.Refusal);
            return;
        }

        await AuthorityJournaling.JournalAsync(
            ctx.RequestServices.GetRequiredService<AnchorJournal>(), write, caller.Actor!, AnchorJournal.OriginUi,
            member: null, ctx.RequestAborted);
        await ctx.RequestServices.GetRequiredService<AuthorityBroadcast>().DrainAsync(ctx.RequestAborted);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new AuthorityEditResult(write.Version, write.CreatedId, write.Changes.Count),
            AuthorityWireJson.Default.AuthorityEditResult);
    }

    /// <summary>
    /// <c>POST /auth/cluster/authority/checks</c>: whether the rules would allow each of several edits,
    /// and why not, changing nothing.
    /// </summary>
    /// <remarks>
    /// This is how a page says why a control is closed before anybody reaches for it — a role above the
    /// caller's in the assignment picker, a permission a higher role holds — without holding a copy of the
    /// rules. Each edit is judged by <see cref="AuthorityRules"/> against the same snapshot; nothing is
    /// held to a recent sign-in, because nothing is written.
    /// </remarks>
    internal static async Task Check(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await RequireCallerAsync(ctx) is not { } caller)
            return;

        AuthorityCheckRequest? body = await Endpoints.ReadBodyAsync(ctx, AuthorityWireJson.Default.AuthorityCheckRequest);
        if (body?.Edits is not { Count: > 0 and <= MaxChecks } edits)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request",
                $"A check names between 1 and {MaxChecks} edits.");
            return;
        }

        AnchorAuthority authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>();
        AuthoritySnapshot snapshot = await authority.Source!.CurrentAsync(ctx.RequestAborted);

        List<AuthorityCheckResult> results = new(edits.Count);
        foreach (AuthorityEditRequest request in edits)
        {
            if (ToEdit(request) is not { } edit)
            {
                results.Add(new AuthorityCheckResult(false, "malformed_request",
                    "The edit names no kind this anchor knows, or not what that kind needs."));
                continue;
            }

            results.Add(AuthorityRules.Check(snapshot, caller.AccountId!, edit) is { } refused
                ? new AuthorityCheckResult(false, Code(refused.Code), refused.Message, refused.Actions)
                : new AuthorityCheckResult(true));
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new AuthorityCheckResponse(snapshot.Version, results), AuthorityWireJson.Default.AuthorityCheckResponse);
    }

    /// <summary>The most edits one check names: a page's worth of roles, never an enumeration.</summary>
    internal const int MaxChecks = 200;

    /// <summary><c>GET /me/access</c>: the caller's own <c>auth:*</c> actions, at every scope they hold a role in.</summary>
    internal static async Task MeAccess(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await RequireCallerAsync(ctx) is not { } caller)
            return;

        AnchorAuthority authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>();
        AccessEvaluator evaluator = new(await authority.Source!.CurrentAsync(ctx.RequestAborted));

        IEnumerable<AccessScope> targets = evaluator.Snapshot.AssignmentsOf(caller.AccountId!).Select(a => a.Scope);
        AccessReport report = AccessReport.For(evaluator, caller.AccountId!, targets, ActionIds.IsAuth, DateTimeOffset.UtcNow);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, report, AccessJsonContext.Default.AccessReport);
    }

    // ── the parts ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Whether the caller holds any <c>auth:*</c> action anywhere: cluster-wide, or at a scope one of
    /// their roles is assigned at — which is where <c>auth:roles.assign</c> can be held alone. A usable
    /// Owner holds every action whether or not the catalog lists it yet.
    /// </summary>
    internal static bool Administers(AccessEvaluator evaluator, string accountId) =>
        evaluator.Allows(accountId, AuthActions.RolesEdit, AccessScope.Cluster).Allowed
        || evaluator.Snapshot.AssignmentsOf(accountId).Select(a => a.Scope).Append(AccessScope.Cluster)
            .Any(scope => evaluator.EffectiveActions(accountId, scope).Any(ActionIds.IsAuth));

    /// <remarks>
    /// A pending account is a caller who holds nothing: it reads its own empty access, and is refused
    /// everything else by the evaluator like anybody else holding nothing.
    /// </remarks>
    private static Task<AccessCaller?> RequireCallerAsync(HttpContext ctx) => Endpoints.RequireAccessCallerAsync(ctx);

    private static async Task<bool> RecentlyProvedAsync(HttpContext ctx, string sessionId)
    {
        DateTimeOffset? proved = await ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>()
            .CredentialAtAsync(sessionId, ctx.RequestAborted);
        return proved is { } at
            && DateTimeOffset.UtcNow - at <= ctx.RequestServices.GetRequiredService<AnchorOptions>().ReauthWindow;
    }

    private static async Task StaleAsync(HttpContext ctx, SqliteAuthorityStore store)
    {
        AuthorityView view = await ViewAsync(store, ctx.RequestAborted);
        await Endpoints.WriteJson(ctx, StatusCodes.Status409Conflict,
            new StaleAuthorityEnvelope(
                new ErrorBody("stale_authority",
                    $"Access changed while you were editing; it is now at version {view.Version}. Review it and make the change again."),
                view),
            AuthorityWireJson.Default.StaleAuthorityEnvelope);
    }

    internal static Task RefuseAsync(HttpContext ctx, AuthorityRefusal refusal)
    {
        int status = refusal.Code switch
        {
            RefusalCode.NotFound => StatusCodes.Status404NotFound,
            RefusalCode.NotPermitted or RefusalCode.OwnerOnly or RefusalCode.BuiltInRole or RefusalCode.RankNotBelow
                or RefusalCode.NotHeld or RefusalCode.PermissionHeldAbove or RefusalCode.LastOwner
                => StatusCodes.Status403Forbidden,
            _ => StatusCodes.Status400BadRequest,
        };

        return Endpoints.WriteJson(ctx, status,
            new AuthorityRefusalEnvelope(new ErrorBody(Code(refusal.Code), refusal.Message), refusal.Actions),
            AuthorityWireJson.Default.AuthorityRefusalEnvelope);
    }

    /// <summary>A refusal code's wire spelling: <c>RankNotBelow</c> → <c>rank_not_below</c>.</summary>
    internal static string Code(RefusalCode code)
    {
        string name = code.ToString();
        System.Text.StringBuilder wire = new(name.Length + 4);
        for (int i = 0; i < name.Length; i++)
        {
            if (i > 0 && char.IsUpper(name[i]))
                wire.Append('_');
            wire.Append(char.ToLowerInvariant(name[i]));
        }

        return wire.ToString();
    }

    /// <summary>The edit a request names, or null when it names none or lacks what its kind needs.</summary>
    internal static AuthorityEdit? ToEdit(AuthorityEditRequest r)
    {
        HashSet<string>? Set(IReadOnlyList<string>? items) => items is null ? null : new HashSet<string>(items, StringComparer.Ordinal);
        AccessScope? Scope() => AccessScope.TryParse(r.Scope, out AccessScope? scope) ? scope : null;

        return r.Kind switch
        {
            "role.create" when r.Name is { } name => new CreateRole(name),
            "role.rename" when r is { RoleId: { } id, Name: { } name } => new RenameRole(id, name),
            "role.delete" when r.RoleId is { } id => new DeleteRole(id),
            "role.rank" when r is { RoleId: { } id, Rank: { } rank } => new RankRole(id, rank),
            "role.permissions" when r.RoleId is { } id && Set(r.PermissionIds) is { } permissions => new SetRolePermissions(id, permissions),
            "permission.create" when r.Name is { } name => new CreatePermission(name),
            "permission.rename" when r is { PermissionId: { } id, Name: { } name } => new RenamePermission(id, name),
            "permission.delete" when r.PermissionId is { } id => new DeletePermission(id),
            "permission.actions" when r.PermissionId is { } id && Set(r.Actions) is { } actions => new SetPermissionActions(id, actions),
            "assign" when r is { AccountId: { } account, RoleId: { } role } && Scope() is { } scope => new Assign(account, role, scope),
            "revoke" when r.AssignmentId is { } id => new Revoke(id),
            "requirement.approve" when r is { AccountId: { } account, Action: { } action } && Scope() is { } scope
                => new ApproveRequirement(account, action, scope),
            "requirement.narrow" when r is { AccountId: { } account, Action: { } action } && Scope() is { } scope
                => new NarrowRequirement(account, action, scope),
            "requirement.revoke" when r is { AccountId: { } account, Action: { } action } => new RevokeRequirement(account, action),
            _ => null,
        };
    }

    /// <summary>The authority as the pages read it, from one consistent read of the store.</summary>
    internal static async Task<AuthorityView> ViewAsync(SqliteAuthorityStore store, CancellationToken ct)
    {
        AuthorityReplicaSnapshot s = await store.ExportAsync(TimeSpan.Zero, DateTimeOffset.UtcNow, ct);
        IReadOnlyList<CatalogEntry> declared = await store.CatalogAsync(ct);
        Dictionary<string, CatalogEntry> byAction = declared.ToDictionary(e => e.Action.Id, StringComparer.Ordinal);
        HashSet<string> filed = s.Permissions.SelectMany(p => p.Actions).ToHashSet(StringComparer.Ordinal);

        return new AuthorityView(
            s.Version,
            [.. s.Roles.Select(r => new AuthorityRoleView(r.RoleId, r.Name, r.Kind, r.Rank, r.Permissions))],
            [.. s.Permissions.Select(p => new AuthorityPermissionView(p.PermissionId, p.Name, p.Actions,
                [.. s.Roles.Where(r => r.Permissions.Contains(p.PermissionId)).Select(r => r.RoleId)]))],
            [.. s.Catalog.Actions.Select(a => new AuthorityCatalogView(
                a.Action, a.Title, a.Effect, a.Scope, a.Self, Unmapped: !a.Self && !filed.Contains(a.Action),
                byAction.TryGetValue(a.Action, out CatalogEntry? entry)
                    ? [.. entry.DeclaredBy.Select(d => new AuthorityDeclarer(d.Member, d.Version))]
                    : []))],
            [.. s.Assignments.Select(a => new AuthorityAssignmentView(a.AssignmentId, a.AccountId, a.RoleId, a.Scope, a.GrantedBy, a.Created))],
            [.. s.Accounts.Select(a => new AuthorityAccountView(
                a.UserId, a.Username, a.DisplayName, a.Kind, a.Status,
                a.Service is { } svc ? new AuthorityServiceView(svc.Component, svc.Member) : null,
                [.. a.Requirements.Select(q => new AuthorityRequirementView(q.Action, q.ScopeKind, q.Why, q.State, q.Grant, q.DecidedBy, q.Declared))]))]);
    }
}
