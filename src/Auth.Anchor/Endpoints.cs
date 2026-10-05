using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

using TheKrystalShip.Auth;
using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Journal;
using TheKrystalShip.KGSM.Events;
using TheKrystalShip.Auth.Minting;
using TheKrystalShip.Auth.Users;
using TheKrystalShip.Api.Contracts;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// What every door here shares — checking a password, minting and rotating a session, reading the
/// caller — and the administration of the accounts.
/// </summary>
/// <remarks>
/// <para>
/// Every handler is a plain <see cref="RequestDelegate"/> that reads its own request and writes its
/// own response. The convenient routing overloads bind an arbitrary delegate's parameters by
/// reflecting over them, which no Native-AOT service can do — and the failure appears at publish
/// time rather than at build time, so it is avoided by construction rather than caught.
/// </para>
/// <para>
/// Bodies are deserialized through <see cref="AnchorJsonContext"/> for the same reason: there is no
/// reflection fallback, so every shape on the wire is one this assembly generated metadata for.
/// </para>
/// </remarks>
internal static class Endpoints
{
    /// <summary>The largest body any of these endpoints accepts.</summary>
    /// <remarks>
    /// A sign-in is a username and a password. A cap this size costs nothing legitimate and stops an
    /// unauthenticated caller from making this daemon buffer whatever it feels like sending.
    /// </remarks>
    private const int MaxBodyBytes = 8 * 1024;

    /// <summary>
    /// Whether this anchor may answer as the cluster's account authority, with the refusal already
    /// written when it may not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A member standing by is not broken and not denying anybody — it is not the authority, and the
    /// sessions it could mint would be signed with a key no member verifies against. So it answers
    /// <c>503</c> and names the holder, which reads as an outage with a cause rather than as a
    /// denial, and tells an operator where to go.
    /// </para>
    /// <para>
    /// A standalone install never reaches this: with no cluster there is no assignment, this anchor
    /// holds the machine's accounts, and every door is open exactly as it was.
    /// </para>
    /// </remarks>
    internal static async Task<bool> RequireAuthorityAsync(HttpContext ctx)
    {
        var role = ctx.RequestServices.GetRequiredService<AnchorRole>();
        if (role.IsAuthority)
            return true;

        // Named so a client can route to the member that can actually answer, rather than retrying
        // against one that never will.
        if (role.Holder is { Length: > 0 } holder)
            ctx.Response.Headers["X-Kgsm-Auth-Holder"] = holder;

        await Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "not_the_anchor",
            role.Holder is { Length: > 0 } h
                ? $"This member does not hold the cluster's accounts. {h} does."
                : "No member holds the cluster's accounts yet.");
        return false;
    }

    // ── Proving a password ────────────────────────────────────────────────────

    /// <summary>
    /// Check a KGSM password, with everything a check has to record already recorded.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every door that takes a password goes through here, so a lockout is journaled, a refusal is logged
    /// and the bootstrap password file is consumed the same way whichever door somebody typed into. The
    /// door decides only how to answer.
    /// </para>
    /// <para>
    /// The attempted name is logged and nothing else. It is what an operator needs to tell one person
    /// mistyping from somebody working through a list, and the answer to the caller stays one outcome at
    /// one cost either way — this log is not reachable by whoever is guessing.
    /// </para>
    /// </remarks>
    /// <returns>The outcome, or null when the account store could not be read.</returns>
    internal static async Task<LocalSignInResult?> CheckPasswordAsync(
        HttpContext ctx, string? username, string? password, DateTimeOffset now)
    {
        var signIn = ctx.RequestServices.GetRequiredService<LocalSignInService>();

        LocalSignInResult result;
        try
        {
            result = await signIn.SignInAsync(username, password, now, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            return null;
        }

        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.Auth.Anchor.SignIn");

        switch (result.Outcome)
        {
            case LocalSignInOutcome.LockedOut:
                logger.LogWarning(
                    "sign-in refused for '{Username}': locked out until {Until}", username, result.RetryAfter);

                // Recorded on the attempt that CAUSED the lock and on none of the ones it then
                // refuses. Whoever is guessing retries at once, so a line per refusal would bury the
                // one line that reports the run.
                if (result is { JustLocked: true, User: { } locked, Lockout: { } standing }
                    && result.RetryAfter is { } lockedUntil)
                {
                    KgsmIdentity who = locked.AsIdentity();
                    await ctx.RequestServices.GetRequiredService<AnchorJournal>().LockedOutAsync(
                        userId: locked.UserId,
                        username: locked.Username,
                        identity: who.Handle,
                        failedCount: standing.FailedCount,
                        until: lockedUntil,
                        // The account the attempts were made against. Not a claim about who made
                        // them: nobody authenticated, so there is nobody to name.
                        actor: who.ActorString,
                        ct: ctx.RequestAborted);
                }
                break;

            case LocalSignInOutcome.Disabled:
                logger.LogWarning("sign-in refused for '{Username}': the account is switched off", username);
                break;

            case LocalSignInOutcome.Success when result.User is { } user:
                logger.LogInformation("'{Username}' signed in with a password", user.Username);

                // The one-time password file has done its job the moment the account it names signs
                // in with a password: what it holds has stopped being the only way into this cluster.
                // Scoped to that account, so somebody else's first sign-in does not tidy away a
                // credential still nobody has used.
                ConsumeBootstrapFile(ctx, user.Username, logger);
                break;

            default:
                logger.LogWarning(
                    "sign-in refused for '{Username}': no account matched that name and password", username);
                break;
        }

        return result;
    }

    /// <summary>The seconds a locked-out caller is told to wait, never less than one.</summary>
    internal static int RetryAfterSeconds(DateTimeOffset until, DateTimeOffset now) =>
        (int)Math.Max(1, Math.Ceiling((until - now).TotalSeconds));


    /// <summary>
    /// Record a session and answer with it.
    /// </summary>
    /// <remarks>
    /// <b>The one place a session begins, and therefore the one place a sign-in is recorded.</b> A
    /// second mint site would be a second place to remember to write the line, and the failure of
    /// forgetting is silent: the person is signed in and no record says so.
    /// </remarks>
    /// <param name="ctx">The request the session is being minted for.</param>
    /// <param name="identity">Who was proved, and by which provider. The token carries this and nothing
    /// about what they may do, which every member resolves on every request.</param>
    /// <param name="user">The account behind that identity.</param>
    /// <param name="now">The clock, so a session's row and its tokens agree on when it started.</param>
    /// <param name="respond">Answers the caller with the session.</param>
    /// <param name="providerSession">
    /// The browser's sign-in this was minted under, so ending that sign-in ends this too.
    /// </param>
    /// <param name="client">The client it is minted for, which every refresh of it is held to.</param>
    /// <param name="application">
    /// The application that client signs people in to, which decides the access token's audience,
    /// lifetime and whether it lists actions.
    /// </param>
    /// <returns>False, with nothing minted, when the account store could not be read.</returns>
    internal static async Task<bool> MintSessionFor(
        HttpContext ctx, KgsmIdentity identity, KgsmUser user, DateTimeOffset now,
        Func<MintedToken, MintedToken, Task> respond, string providerSession,
        RegisteredClient client, Application application)
    {
        var registry = ctx.RequestServices.GetRequiredService<ISessionRegistry>();
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();

        string sessionId = NewSessionId();
        if (await MintPairAsync(ctx, identity, user, sessionId, client.ClientId, application) is not ({ } access, { } refresh))
            return false;

        var registration = new SessionRegistration(
            SessionId: sessionId,
            // Keyed by the provider-qualified handle, never the username: a rename must not
            // detach somebody from their own sessions.
            UserId: identity.Handle,
            HostId: options.ClusterId,
            Created: now,
            Expires: refresh.ExpiresAt,
            UserAgent: UserAgentOf(ctx),
            CurrentJti: refresh.Jti);

        await ((SqliteSessionRegistry)registry).CreateAsync(registration, providerSession, client.ClientId, ctx.RequestAborted);

        // Recorded after the session exists and before the caller is answered. The actor is the
        // identity that arrived rather than this daemon: nobody else was involved in a sign-in, and
        // naming the component that minted the token would hide who came through the door.
        await ctx.RequestServices.GetRequiredService<AnchorJournal>().SessionAsync(
            AuthEvents.SignedIn,
            userId: user.UserId,
            username: user.Username,
            identity: identity.Handle,
            provider: identity.Provider,
            sid: sessionId,
            userAgent: UserAgentOf(ctx),
            actor: identity.ActorString,
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

        await respond(access, refresh);
        return true;
    }

    /// <summary>
    /// The access token and refresh token a session of <paramref name="application"/> gets, or null when
    /// the actions its token lists could not be evaluated.
    /// </summary>
    /// <remarks>
    /// KGSM's are the cluster's session: audienced to the cluster, carrying no actions, verified by every
    /// member and evaluated there from its replica. Any other application's access token is audienced to
    /// it, lives its lifetime and lists its actions the account holds, evaluated here at every mint; its
    /// refresh token is audienced to this provider, the one place it is presented.
    /// </remarks>
    private static async Task<(MintedToken Access, MintedToken Refresh)?> MintPairAsync(
        HttpContext ctx, KgsmIdentity identity, KgsmUser user, string sessionId,
        string? clientId, Application application)
    {
        var tokens = ctx.RequestServices.GetRequiredService<ISessionTokenService>();
        if (application.IsKgsm)
            return (tokens.MintAccess(identity, sessionId), tokens.MintRefresh(identity, sessionId));

        IReadOnlyList<string> held;
        try
        {
            held = await ctx.RequestServices.GetRequiredService<ApplicationCatalog>()
                .HeldAsync(application, user.UserId, ctx.RequestAborted);
        }
        catch (Exception e) when (e is InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            return null;
        }

        MintedToken access = tokens.MintApplicationAccess(new ApplicationAccess(
            Subject: user.UserId,
            Username: user.Username,
            DisplayName: user.DisplayName,
            Picture: identity.AvatarUrl,
            SessionId: sessionId,
            ClientId: clientId ?? throw new InvalidOperationException("An application's session is minted for a client."),
            Audience: application.Audience,
            Lifetime: application.AccessLifetime,
            Actions: held));
        return (access, tokens.MintApplicationRefresh(identity, sessionId));
    }

    // ── Keep a session ────────────────────────────────────────────────────────

    /// <summary>What presenting a refresh token came to.</summary>
    internal enum RotationOutcome
    {
        /// <summary>A new access bearer and a new refresh token.</summary>
        Rotated,

        /// <summary>Not a refresh token this anchor holds a live session for, or one already rotated away.</summary>
        Invalid,

        /// <summary>The account behind it is switched off or gone, and the session has been ended.</summary>
        Withdrawn,

        /// <summary>The account store could not be read.</summary>
        Unavailable,

        /// <summary>The session belongs to a confidential client, and the request did not authenticate as it.</summary>
        ClientRefused,
    }

    /// <summary>A rotation's outcome, with the new tokens when there are some.</summary>
    internal sealed record Rotation(RotationOutcome Outcome, MintedToken? Access, MintedToken? Refresh);

    /// <summary>
    /// Rotate the session a refresh token belongs to, with the account's standing re-read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The refresh grant at <c>/token</c>. Nothing on this path leaves the machine, which is what makes
    /// a session survive an outage of anything else — the standing comes from the account store on this
    /// host, and the signature from the key this daemon holds.
    /// </para>
    /// <para>
    /// A session is continued only for the client it was minted for (RFC 6749 §6): a confidential one
    /// authenticates as itself, and nobody presents another client's refresh token as their own. An
    /// application's next access token is minted afresh — its actions evaluated again — so a role taken
    /// away reaches it at the next refresh.
    /// </para>
    /// </remarks>
    internal static async Task<Rotation> RotateAsync(HttpContext ctx, string presented, ClientAuthentication auth)
    {
        var tokens = ctx.RequestServices.GetRequiredService<ISessionTokenService>();
        RefreshClaims? claims = await tokens.ReadRefreshAsync(presented);
        if (claims is null)
            return new Rotation(RotationOutcome.Invalid, null, null);

        var registry = ctx.RequestServices.GetRequiredService<ISessionRegistry>();
        var validator = ctx.RequestServices.GetRequiredService<ISessionValidator>();
        var accounts = ctx.RequestServices.GetRequiredService<AccountResolver>();
        var applications = ctx.RequestServices.GetRequiredService<ApplicationRegistry>();
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();

        // A session recorded without a client is KGSM's, and any request may continue it as it always could.
        string? clientId = ((SqliteSessionRegistry)registry).SessionClient(claims.SessionId);
        RegisteredClient? client = null;
        if (clientId is not null)
        {
            client = ctx.RequestServices.GetRequiredService<ClientRegistry>().Find(clientId);
            if (client is null)
                return new Rotation(RotationOutcome.Invalid, null, null);

            if (!auth.Speaks(client))
            {
                return client.Confidential && auth.Result == ClientAuthentication.Outcome.Unauthenticated
                    ? new Rotation(RotationOutcome.ClientRefused, null, null)
                    : new Rotation(RotationOutcome.Invalid, null, null);
            }
        }

        if ((client is null ? applications.Kgsm : applications.Of(client)) is not { } application)
            return new Rotation(RotationOutcome.Invalid, null, null);

        // The token says which kind of session it continues; the row says which client. They agree for every
        // token this provider minted.
        string expectedAudience = application.IsKgsm ? options.ClusterId : options.Issuer;
        if (!string.Equals(claims.Audience, expectedAudience, StringComparison.Ordinal))
            return new Rotation(RotationOutcome.Invalid, null, null);

        // Standing is re-read rather than carried over from the presented token, so a disable takes
        // effect at the next rotation instead of at the end of the session.
        AccountAnswer answer;
        try
        {
            answer = await accounts.ResolveAsync(claims.Identity, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            return new Rotation(RotationOutcome.Unavailable, null, null);
        }

        if (answer.Outcome != AccountOutcome.Ok)
        {
            // A withdrawn account keeps no session. Killing the row here is what stops the remaining
            // access bearer from being refreshed into a new one for its whole lifetime, and telling
            // the other members is what stops that bearer from being spent on them meanwhile.
            await registry.RevokeAsync(claims.SessionId, ctx.RequestAborted);
            validator.Evict(claims.SessionId);
            await ctx.RequestServices.GetRequiredService<ISessionAnnouncer>()
                .RevokedAsync(claims.SessionId, ctx.RequestAborted);

            // A separate fact from the disable that caused it, and worth its own line because the two
            // can be hours apart: an account switched off at noon keeps working until its access
            // bearer runs out and the client comes back here. This is when the access actually ended.
            //
            // The actor is this daemon, honestly: nobody acted just now. It carried out a standing
            // instruction, which is what a system actor is for.
            await ctx.RequestServices.GetRequiredService<AnchorJournal>().SessionRevokedAsync(
                scope: SessionRevokeScopes.Withdrawn,
                userId: answer.User?.UserId ?? string.Empty,
                username: answer.User?.Username ?? claims.Identity.Username,
                sid: claims.SessionId,
                count: 1,
                actor: JournalProducer.SystemActorFor(AnchorJournal.ProducerId),
                origin: null,
                ct: ctx.RequestAborted);

            return new Rotation(RotationOutcome.Withdrawn, null, null);
        }

        if (await MintPairAsync(ctx, claims.Identity, answer.User!, claims.SessionId, clientId, application)
            is not ({ } access, { } refresh))
            return new Rotation(RotationOutcome.Unavailable, null, null);

        // The presented jti has to be the one the session currently holds. Anything else is a replay
        // of a token that has already been rotated away — a stale client or a stolen token, and this
        // daemon cannot tell which, so it refuses and lets the real holder sign in again.
        bool rotated = await registry.RotateAsync(
            claims.SessionId, claims.Jti, refresh.Jti, refresh.ExpiresAt, ctx.RequestAborted);

        if (!rotated)
        {
            validator.Evict(claims.SessionId);
            return new Rotation(RotationOutcome.Invalid, null, null);
        }

        return new Rotation(RotationOutcome.Rotated, access, refresh);
    }

    // ── Accounts ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Every person's account. Never carries a secret in any form. Read by whoever administers any part
    /// of access, since approving, disabling and assigning all start from it.
    /// </summary>
    internal static async Task Accounts(HttpContext ctx)
    {
        if (!await RequireAuthorityAsync(ctx))
            return;

        if (await RequireAdministratorAsync(ctx) is null)
            return;

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();

        IReadOnlyList<KgsmUser> users = await store.ListAsync(ctx.RequestAborted);
        var records = new List<AccountEntry>(users.Count);

        foreach (KgsmUser user in users)
        {
            IReadOnlyList<UserCredential> credentials =
                await store.ListCredentialsAsync(user.UserId, ctx.RequestAborted);

            records.Add(ToRecord(user, credentials));
        }

        await WriteJson(ctx, StatusCodes.Status200OK, new AccountsPage(records),
            AnchorJsonContext.Default.AccountsPage);
    }

    /// <summary>
    /// Change an account's standing: approve it, switch it off, switch it back on, or return it to
    /// awaiting approval.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each transition is its own action: approving (or returning an account to awaiting approval) is
    /// <c>auth:accounts.approve</c>, switching one off or on is <c>auth:accounts.disable</c>. Switching one
    /// off goes through the administration rules, which are what keep the cluster's last active Owner
    /// and let only an Owner switch off another.
    /// </para>
    /// <para>
    /// Every change advances the authority version every member orders by, and it is returned: a caller
    /// that has it knows its change is the newest statement about the account.
    /// </para>
    /// </remarks>
    internal static async Task PatchAccount(HttpContext ctx)
    {
        if (!await RequireAuthorityAsync(ctx))
            return;

        // Signed in before anything about the account is looked up, so a stranger learns nothing from
        // which accounts exist; which action the change needs is known only once the account is read.
        if (await RequireAccessCallerAsync(ctx) is null)
            return;

        string? userId = ctx.Request.RouteValues["userId"] as string;
        if (string.IsNullOrWhiteSpace(userId))
        {
            await Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_user", "A user id is required.");
            return;
        }

        AccountPatchRequest? body = await ReadBodyAsync(ctx, AnchorJsonContext.Default.AccountPatchRequest);
        if (body is null)
        {
            await Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request", "The request body is not readable.");
            return;
        }

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();
        KgsmUser? user = await store.FindByIdAsync(userId, ctx.RequestAborted);
        if (user is null)
        {
            await Refuse(ctx, StatusCodes.Status404NotFound, "no_such_account", "No account has that id.");
            return;
        }

        if (body.Status is not { Length: > 0 } wantedStatus || !TryReadStatus(wantedStatus, out UserStatus status))
        {
            await Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_status",
                $"'{body.Status}' is not a status. Use active, pending or disabled.");
            return;
        }

        // Which action the change is, from the route's own entries: approving a pending account is the
        // `active` entry; switching one off — and back on, which undoes that — is the `disabled` entry.
        string action = AuthAction.Of(ctx,
            status == UserStatus.Disabled || user.Status == UserStatus.Disabled ? "disabled" : "active");

        if (await RequireCaller(ctx, action) is not { } caller)
            return;

        SqliteAuthorityStore authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>().Store!;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        KgsmUser updated;

        if (status == UserStatus.Disabled && user.Status != UserStatus.Disabled)
        {
            try
            {
                AuthorityWrite write = await authority.ApplyAsync(
                    caller.User!.UserId, new DisableAccount(user.UserId), await authority.VersionAsync(ctx.RequestAborted), now,
                    ctx.RequestAborted);
                await AuthorityJournaling.JournalAsync(ctx.RequestServices.GetRequiredService<AnchorJournal>(), write,
                    ActorOf(caller), AnchorJournal.OriginUi, member: null, ctx.RequestAborted);
            }
            catch (AuthorityRefusedException e)
            {
                await AuthorityEndpoints.RefuseAsync(ctx, e.Refusal);
                return;
            }
            catch (StaleAuthorityException)
            {
                await Refuse(ctx, StatusCodes.Status409Conflict, "stale_authority", "Access changed meanwhile; try again.");
                return;
            }

            updated = (await store.FindByIdAsync(user.UserId, ctx.RequestAborted))!;
        }
        else
        {
            // Approving somebody admits them: an account somebody approved is never expired as an
            // arrival nobody looked at.
            updated = user with
            {
                Origin = status == UserStatus.Active && user.Status == UserStatus.Pending ? AccountOrigin.Admitted : user.Origin,
                Status = status,
                Updated = now,
            };

            await store.UpdateAsync(updated, ctx.RequestAborted);
            await RecordAccountChangesAsync(ctx, user, updated, caller, ctx.RequestAborted);
        }

        await AnnounceAsync(ctx);

        IReadOnlyList<UserCredential> credentials =
            await store.ListCredentialsAsync(updated.UserId, ctx.RequestAborted);

        await WriteJson(ctx, StatusCodes.Status200OK,
            new AccountChanged(ToRecord(updated, credentials), await authority.VersionAsync(ctx.RequestAborted)),
            AnchorJsonContext.Default.AccountChanged);
    }

    /// <summary>
    /// Settle what this anchor's writes owe, now rather than on a timer: in a KGSM cluster, sent to every
    /// member.
    /// </summary>
    /// <remarks>
    /// Every write already owes its change in the store's outbox, in the same transaction; this only
    /// drains it. A failure to send is logged by the broadcast and fails nothing: the change is real, and
    /// the timer sends it.
    /// </remarks>
    internal static Task AnnounceAsync(HttpContext ctx) =>
        ctx.RequestServices.GetRequiredService<IAuthorityAnnouncer>().DrainAsync(ctx.RequestAborted);

    /// <summary>The person who acted, as an audit trail names one.</summary>
    internal static string ActorOf(Caller caller) =>
        caller.Identity?.ActorString
        ?? (caller.User is { } self ? self.AsIdentity().ActorString : string.Empty);

    /// <summary>
    /// Record one line per fact that changed, rather than one "updated" line.
    /// </summary>
    /// <remarks>
    /// An access review reads for an approval, or for a disable. A combined line would make both
    /// queries a text search over a sentence.
    /// </remarks>
    private static async Task RecordAccountChangesAsync(
        HttpContext ctx, KgsmUser before, KgsmUser after, Caller caller, CancellationToken ct)
    {
        var journal = ctx.RequestServices.GetRequiredService<AnchorJournal>();

        // The person who acted is the actor; the account acted UPON rides in the payload. It is the
        // split every action on an account uses, so "who did this" and "to whom" never have to be
        // told apart by reading a sentence.
        string actor = ActorOf(caller);

        if (before.Status != after.Status)
        {
            // Which event this is comes from where the account LANDED, not from a verb chosen here:
            // the from/to pair travels on the line, so a reader tells "switched off" from "returned
            // to awaiting approval" without either being spelled into the record.
            string type = after.Status == UserStatus.Active
                ? AuthEvents.UserApproved
                : AuthEvents.UserDisabled;

            await journal.AccountAsync(
                type, after.UserId, after.Username,
                fromStatus: UserStatuses.ToWire(before.Status),
                toStatus: UserStatuses.ToWire(after.Status),
                actor: actor, origin: AnchorJournal.OriginUi, ct: ct);
        }
    }

    /// <summary>
    /// Remove the bootstrap password file once the account it names has signed in.
    /// </summary>
    /// <remarks>
    /// Never fails the sign-in. It worked; a file that could not be tidied away afterwards is a thing
    /// to say in a log, not a reason to refuse somebody who has just proved who they are.
    /// </remarks>
    private static void ConsumeBootstrapFile(HttpContext ctx, string username, ILogger logger)
    {
        string path = ctx.RequestServices.GetRequiredService<AnchorOptions>().InitialAdminPasswordPath;

        if (FirstAdmin.TryConsumePasswordFile(path, username, out Exception? error))
        {
            logger.LogInformation(
                "'{Username}' has signed in, so the initial password at {Path} is gone.",
                username, path);
        }
        else if (error is not null)
        {
            logger.LogWarning(error,
                "the initial password at {Path} could not be removed.", path);
        }
    }

    /// <summary>A status a caller asked for, refusing anything that is not one.</summary>
    internal static bool TryReadStatus(string wire, out UserStatus status)
    {
        status = UserStatuses.Parse(wire);
        return status != UserStatus.Disabled
            || string.Equals(wire.Trim(), UserStatuses.Disabled, StringComparison.OrdinalIgnoreCase);
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The caller, or null with the refusal already written.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The refusals are distinguishable because a client acts differently on each: an unauthenticated
    /// caller signs in, an ended session signs in again, a disabled account is told so, a person who may
    /// not do this is told <c>not_permitted</c>, and one who may but has not proved a credential recently
    /// is told <c>reauth_required</c> and sent to.
    /// </para>
    /// <para>
    /// With no <paramref name="action"/> any signed-in person passes: their own records. Every
    /// <c>auth:*</c> action is decided by the evaluator and then held to a recent sign-in.
    /// </para>
    /// </remarks>
    internal static async Task<Caller?> RequireCaller(HttpContext ctx, string? action)
    {
        if (await RequireAccessCallerAsync(ctx) is not { } access)
            return null;

        if (action is not null)
        {
            AnchorAccessResult result = await ctx.RequestServices.GetRequiredService<AnchorAccess>()
                .AllowsAsync(access.AccountId!, access.SessionId!, action, Access.AccessScope.Cluster, ctx.RequestAborted);

            if (!result.Decision.Allowed)
            {
                await Refuse(ctx, StatusCodes.Status403Forbidden, "not_permitted",
                    $"You do not hold '{action}'.");
                return null;
            }

            if (result.ReauthRequired)
            {
                await Refuse(ctx, StatusCodes.Status403Forbidden, "reauth_required",
                    "Prove it is you again to do that.");
                return null;
            }
        }

        return await CallerOfAsync(ctx, access);
    }

    /// <summary>
    /// The caller, admitted when they hold any <c>auth:*</c> action anywhere — what reading the lists that
    /// administering starts from takes.
    /// </summary>
    internal static async Task<Caller?> RequireAdministratorAsync(HttpContext ctx)
    {
        if (await RequireAccessCallerAsync(ctx) is not { } access)
            return null;

        AnchorAuthority authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>();
        Access.AccessEvaluator evaluator = new(await authority.Source!.CurrentAsync(ctx.RequestAborted));
        if (!AuthorityEndpoints.Administers(evaluator, access.AccountId!))
        {
            await Refuse(ctx, StatusCodes.Status403Forbidden, "not_permitted",
                "You hold no action that administers access.");
            return null;
        }

        return await CallerOfAsync(ctx, access);
    }

    /// <summary>
    /// The person behind the request's session, resolved against the authority store, or null with the
    /// refusal already written.
    /// </summary>
    internal static async Task<AccessCaller?> RequireAccessCallerAsync(HttpContext ctx)
    {
        AnchorAuthority authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>();
        if (authority.Store is null)
        {
            await Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
                authority.UnavailableReason ?? "The account store holds no authority.");
            return null;
        }

        AccessCaller caller;
        try
        {
            caller = await ctx.RequestServices.GetRequiredService<AuthorityCaller>().ResolveAsync(ctx.Request, ctx.RequestAborted);
        }
        catch (Exception e) when (e is InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            await Unavailable(ctx);
            return null;
        }

        switch (caller.Refusal)
        {
            case CallerRefusal.Unauthenticated:
                await Refuse(ctx, StatusCodes.Status401Unauthorized, "unauthenticated", "Sign in to continue.");
                return null;
            case CallerRefusal.SessionEnded:
                await Refuse(ctx, StatusCodes.Status401Unauthorized, "session_ended", "That session has ended. Sign in again.");
                return null;
            case CallerRefusal.AccountDisabled:
                await Refuse(ctx, StatusCodes.Status403Forbidden, "account_disabled", "This account has been switched off.");
                return null;
        }

        return caller;
    }

    private static async Task<Caller?> CallerOfAsync(HttpContext ctx, AccessCaller access)
    {
        KgsmUser? user = await ctx.RequestServices.GetRequiredService<IUserStore>()
            .FindByIdAsync(access.AccountId!, ctx.RequestAborted);
        if (user is null)
        {
            await Refuse(ctx, StatusCodes.Status401Unauthorized, "unauthenticated", "Sign in to continue.");
            return null;
        }

        return new Caller(CallerRefusal.None, user, access.SessionId, access.Identity);
    }

    /// <summary>
    /// The account store could not be read.
    /// </summary>
    /// <remarks>
    /// 503, never 403. "We could not find out what this person may do" is a different fact from "they
    /// may do nothing", and reporting the first as the second locks out the Owner mid-incident.
    /// </remarks>
    internal static Task Unavailable(HttpContext ctx) =>
        Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
            "The account store could not be read.");

    /// <summary>An account as this surface renders one. Never carries a secret in any form.</summary>
    internal static AccountEntry ToRecord(KgsmUser user, IReadOnlyList<UserCredential> credentials) =>
        new(
            Id: user.UserId,
            Username: user.Username,
            DisplayName: user.DisplayName,
            Origin: AccountWire.ToWire(user.Origin),
            Status: UserStatuses.ToWire(user.Status),
            HasPassword: credentials.Any(c => c.Kind == CredentialKind.Password),
            Identities: [.. credentials.Where(c => c.Kind == CredentialKind.Identity).Select(c => c.Handle)],
            Created: user.Created,
            Updated: user.Updated);

    internal static Task Refuse(HttpContext ctx, int status, string code, string message) =>
        WriteJson(ctx, status, new ErrorEnvelope(new ErrorBody(code, message)),
            ApiContractsJson.Default.ErrorEnvelope);

    internal static Task WriteJson<T>(HttpContext ctx, int status, T value, JsonTypeInfo<T> type)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(ctx.Response.Body, value, type, ctx.RequestAborted);
    }

    /// <summary>
    /// The request body, or null when it is absent, oversized or not readable as
    /// <typeparamref name="T"/>.
    /// </summary>
    internal static async Task<T?> ReadBodyAsync<T>(HttpContext ctx, JsonTypeInfo<T> type) where T : class
    {
        if (ctx.Request.ContentLength > MaxBodyBytes)
            return null;

        try
        {
            ctx.Request.EnableBuffering(bufferThreshold: MaxBodyBytes, bufferLimit: MaxBodyBytes);
            return await JsonSerializer.DeserializeAsync(ctx.Request.Body, type, ctx.RequestAborted);
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// The device, for a person reading their own session list. Truncated, because it is arbitrary
    /// text from a caller that ends up on a page somebody reads.
    /// </summary>
    internal static string? UserAgentOf(HttpContext ctx)
    {
        string agent = ctx.Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(agent))
            return null;
        return agent.Length > 256 ? agent[..256] : agent;
    }

    /// <summary>
    /// A fresh session id: 128 bits from the cryptographic RNG, matching the <c>usr_</c>/<c>crd_</c>
    /// convention the account store already uses.
    /// </summary>
    internal static string NewSessionId() =>
        "sid_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}
