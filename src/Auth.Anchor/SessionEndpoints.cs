using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The sessions a person holds, and ending them.
/// </summary>
/// <remarks>
/// <para>
/// <b>They are listed here because they exist only here.</b> A cluster session is minted by the
/// anchor and has a row on the anchor; every member verifies one offline against a published key and
/// stores nothing. So a member asked what devices somebody is signed in on has an honest answer of
/// none — which reads as an empty list rather than as the wrong question, and is the failure this
/// surface exists to prevent.
/// </para>
/// <para>
/// <b>Ending a session is never gated on holding the capability.</b> Every other door here refuses
/// while another member holds the accounts, because minting or writing would be answering for
/// something that is not this member's. Revoking takes authority away, and a member that has stood
/// down still holds the rows for the sessions it minted — refusing would strand somebody signed in.
/// </para>
/// </remarks>
internal static class SessionEndpoints
{
    /// <summary>Every live session for the caller, or for the account an admin names.</summary>
    internal static async Task List(HttpContext ctx)
    {
        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.None);
        if (maybe is not { } caller || caller.User is not { } user)
            return;

        // An admin may read somebody else's. Anybody may read their own, and a viewer asking for
        // another account gets their own rather than a refusal that confirms the account exists.
        string? asked = ctx.Request.Query["userId"].ToString();
        KgsmUser subject = user;

        if (!string.IsNullOrWhiteSpace(asked)
            && !string.Equals(asked, user.UserId, StringComparison.Ordinal)
            && caller.Holds(KgsmTier.Admin))
        {
            if (await ctx.RequestServices.GetRequiredService<IUserStore>()
                    .FindByIdAsync(asked, ctx.RequestAborted) is not { } other)
            {
                await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_account",
                    "No account has that id.");
                return;
            }

            subject = other;
        }

        IReadOnlyList<SqliteSessionRegistry.LiveSession> live =
            await RegistryOf(ctx).ListAsync(await HandlesOf(ctx, subject), ctx.RequestAborted);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new SessionsPage(
            [.. live.Select(s => new SessionRecord(
                s.SessionId, s.UserId, s.Created, s.Expires, s.UserAgent, s.LastSeen,
                // True on exactly the row the calling bearer belongs to, so a surface can say "this
                // device" rather than making somebody work out which is theirs.
                Current: string.Equals(s.SessionId, caller.SessionId, StringComparison.Ordinal)))]),
            AnchorJsonContext.Default.SessionsPage);
    }

    /// <summary>End one of the caller's own sessions, or all of them.</summary>
    /// <remarks>
    /// A named session must be the caller's. A sid is opaque and unguessable, but one that leaks must
    /// not become a way to sign somebody else out — and "not yours" answers the same as "not real",
    /// because telling those apart says whether an id exists.
    /// </remarks>
    internal static async Task Revoke(HttpContext ctx)
    {
        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.None);
        if (maybe is not { } caller || caller.User is not { } user)
            return;

        RevokeRequest? body = await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.RevokeRequest);
        IReadOnlyList<string> handles = await HandlesOf(ctx, user);

        if (body?.All == true)
        {
            await EndAllAsync(ctx, user, handles, SessionRevokeScopes.All, caller);
            return;
        }

        // Neither set ends the calling session, which is what a sign-out is.
        string? sid = body?.Sid is { Length: > 0 } named ? named : caller.SessionId;
        if (sid is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_session",
                "No session to end.");
            return;
        }

        SqliteSessionRegistry registry = RegistryOf(ctx);
        if (await registry.OwnerAsync(sid, ctx.RequestAborted) is not { } owner
            || !handles.Contains(owner, StringComparer.Ordinal))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_session",
                "You hold no session with that id.");
            return;
        }

        await EndAsync(ctx, sid);
        await RecordAsync(ctx, SessionRevokeScopes.Self, user, sid, 1, caller);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new RevokeResult(1),
            AnchorJsonContext.Default.RevokeResult);
    }

    /// <summary>End every session an account holds — an administrator's door.</summary>
    /// <remarks>
    /// The one a person cannot do for themselves and the one an incident needs: somebody's access is
    /// withdrawn and every device they are signed in on has to stop, without waiting for a bearer to
    /// expire on each.
    /// </remarks>
    internal static async Task RevokeAll(HttpContext ctx)
    {
        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.Admin);
        if (maybe is not { } caller)
            return;

        if (ctx.Request.RouteValues["userId"] as string is not { Length: > 0 } userId)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_user",
                "A user id is required.");
            return;
        }

        if (await ctx.RequestServices.GetRequiredService<IUserStore>()
                .FindByIdAsync(userId, ctx.RequestAborted) is not { } subject)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_account",
                "No account has that id.");
            return;
        }

        await EndAllAsync(
            ctx, subject, await HandlesOf(ctx, subject), SessionRevokeScopes.Admin, caller);
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    private static async Task EndAllAsync(
        HttpContext ctx, KgsmUser subject, IReadOnlyList<string> handles, string scope, Caller caller)
    {
        IReadOnlyList<string> ended =
            await RegistryOf(ctx).RevokeAllAsync(handles, ctx.RequestAborted);

        var validator = ctx.RequestServices.GetRequiredService<ISessionValidator>();
        var gate = ctx.RequestServices.GetRequiredService<ReauthGate>();
        var broadcast = ctx.RequestServices.GetRequiredService<SessionBroadcast>();

        foreach (string sid in ended)
        {
            validator.Evict(sid);
            gate.Forget(sid);

            // Each one, because a cluster session is accepted on every member and has a row only
            // here. Ending them locally without saying so leaves somebody signed out on the door
            // they used and signed in on every other one.
            await broadcast.RevokedAsync(sid, ctx.RequestAborted);
        }

        // Zero is a real answer and not a failure: an account with nothing live is exactly what an
        // admin wanted, and reporting it as an error would invite them to try again.
        if (ended.Count > 0)
            await RecordAsync(ctx, scope, subject, sid: null, ended.Count, caller);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new RevokeResult(ended.Count),
            AnchorJsonContext.Default.RevokeResult);
    }

    private static async Task EndAsync(HttpContext ctx, string sid)
    {
        await ctx.RequestServices.GetRequiredService<ISessionRegistry>()
            .RevokeAsync(sid, ctx.RequestAborted);

        ctx.RequestServices.GetRequiredService<ISessionValidator>().Evict(sid);
        ctx.RequestServices.GetRequiredService<ReauthGate>().Forget(sid);

        await ctx.RequestServices.GetRequiredService<SessionBroadcast>()
            .RevokedAsync(sid, ctx.RequestAborted);
    }

    /// <summary>
    /// Record what was ended.
    /// </summary>
    /// <remarks>
    /// A single revocation names the session; a sweep names how many it ended. Neither fabricates the
    /// other, which is why both ride as nullable rather than being defaulted to each other.
    /// </remarks>
    private static Task RecordAsync(
        HttpContext ctx, string scope, KgsmUser subject, string? sid, int? count, Caller caller) =>
        ctx.RequestServices.GetRequiredService<AnchorJournal>().SessionRevokedAsync(
            scope, subject.UserId, subject.Username, sid, count,
            // Whoever acted. An admin ending somebody else's sessions is the substantial-power case,
            // and the account acted upon is in the payload rather than in the actor.
            actor: caller.Identity?.ActorString
                ?? (caller.User is { } self ? self.AsIdentity().ActorString : string.Empty),
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

    private static SqliteSessionRegistry RegistryOf(HttpContext ctx) =>
        (SqliteSessionRegistry)ctx.RequestServices.GetRequiredService<ISessionRegistry>();

    /// <summary>
    /// Every handle an account's sessions could be keyed by.
    /// </summary>
    /// <remarks>
    /// Never the user id and never the username. A session is keyed by the provider-qualified handle
    /// somebody <em>arrived</em> with, so one account signed in with a password and with Discord has
    /// two keys — asking under one finds half the devices and reports the other half as nothing,
    /// which reads as an empty card rather than as a wrong question. Every credential the account
    /// holds is checked, which is what makes "sign me out everywhere" mean everywhere rather than
    /// everywhere-I-used-this-door.
    /// </remarks>
    private static async Task<IReadOnlyList<string>> HandlesOf(HttpContext ctx, KgsmUser user)
    {
        IReadOnlyList<UserCredential> credentials = await ctx.RequestServices
            .GetRequiredService<IUserStore>()
            .ListCredentialsAsync(user.UserId, ctx.RequestAborted);

        // The password handle is included by the credential list itself (a password is filed under
        // local:<user id>), so nothing is added here that the store did not say the account holds.
        return [.. credentials.Select(c => c.Handle).Distinct(StringComparer.Ordinal)];
    }
}
