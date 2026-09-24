using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The doors that change an account rather than open one.
/// </summary>
/// <remarks>
/// <para>
/// <b>They are here because the accounts are here.</b> A cluster's accounts have one writer, so a
/// member cannot answer any of these: a password set on a member lands in that member's replica, is
/// not versioned by the anchor, and is overwritten by the next thing the anchor publishes about the
/// account — appearing to work and then quietly not having happened.
/// </para>
/// <para>
/// <b>Every one of them announces.</b> A change made here and not told is a change that exists on one
/// machine, so each write is followed by a version and a broadcast, in that order and after the local
/// write has committed. A failure to announce is logged and does not fail the request: the change is
/// real, and reporting it as failed invites somebody to repeat it.
/// </para>
/// </remarks>
internal static class AccountEndpoints
{
    // ── An account arriving ───────────────────────────────────────────────────

    /// <summary>
    /// Create an account, as an administrator.
    /// </summary>
    /// <remarks>
    /// The counterpart to registration and the door an admin needs: somebody who will never register
    /// themselves, or who arrives through a provider and should already hold a tier when they do.
    /// </remarks>
    internal static async Task CreateAccount(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.Admin);
        if (maybe is not { } caller)
            return;

        CreateAccountRequest? body =
            await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.CreateAccountRequest);

        if (body is null || !Usernames.IsValid(body.Username))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_username",
                $"A username is {Usernames.MinLength}-{Usernames.MaxLength} characters of letters, "
                + "digits, '.', '_' or '-', beginning with a letter or a digit.");
            return;
        }

        // Parsed strictly, not fail-closed. Everywhere else an unreadable tier means "grants
        // nothing", which is the safe reading of a value somebody else wrote; here it is what the
        // caller is asking for, and silently creating at none instead of refusing a typo would make
        // an admin think they had granted something.
        if (!Endpoints.TryReadTier(body.Tier ?? KgsmTiers.None, out KgsmTier tier))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_tier",
                $"'{body.Tier}' is not a tier. Use admin, operator, viewer or none.");
            return;
        }

        // Only the two states an admin can mean. Creating one already disabled is a shape with no
        // use — an admin wanting that creates it and disables it, and the trail then says both
        // things happened.
        if (!Endpoints.TryReadStatus(body.Status ?? UserStatuses.Active, out UserStatus status)
            || status == UserStatus.Disabled)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_status",
                $"A new account is '{UserStatuses.Active}' or '{UserStatuses.Pending}'.");
            return;
        }

        // Optional: an account can be made for somebody who will only ever arrive through a
        // provider. One that IS set answers to the same floor as every other, or the door with the
        // least scrutiny becomes the one that admits the weakest password on the cluster.
        if (!string.IsNullOrEmpty(body.Password) && !Passwords.IsAcceptable(body.Password))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "password_too_short",
                $"A password must be at least {Passwords.MinLength} characters.");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        string username = body.Username!.Trim();
        var account = new KgsmUser(
            UserIds.NewUserId(),
            username,
            string.IsNullOrWhiteSpace(body.DisplayName) ? username : body.DisplayName.Trim(),
            tier,
            // An admin choosing a tier IS the deliberate grant this records, which is what expiry
            // reads to tell an approved account from one that arrived on its own.
            TierSource.Granted,
            status,
            now,
            now);

        try
        {
            await ctx.RequestServices.GetRequiredService<IUserStore>()
                .CreateAsync(account, ctx.RequestAborted);
        }
        catch (DuplicateUsernameException)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "username_taken",
                $"'{username}' is already taken on this cluster.");
            return;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ctx.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.AccountEndpoints")
                .LogError(ex, "could not create the account '{Username}'", username);
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
                "The account store could not be written.");
            return;
        }

        if (!string.IsNullOrEmpty(body.Password))
        {
            await ctx.RequestServices.GetRequiredService<LocalSignInService>()
                .SetPasswordAsync(account.UserId, body.Password, now, ctx.RequestAborted);
        }

        await AnnounceAsync(ctx, account, now);

        // No "from": the account did not exist a moment ago, and a from/to pair would invent a
        // previous state to have moved out of.
        await ctx.RequestServices.GetRequiredService<AnchorJournal>().AccountAsync(
            AuthEvents.UserProvisioned, account.UserId, account.Username,
            toTier: KgsmTiers.ToWire(tier),
            toStatus: UserStatuses.ToWire(status),
            actor: ActorOf(caller),
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

        IReadOnlyList<UserCredential> credentials = await ctx.RequestServices
            .GetRequiredService<IUserStore>()
            .ListCredentialsAsync(account.UserId, ctx.RequestAborted);

        await Endpoints.WriteJson(ctx, StatusCodes.Status201Created,
            Endpoints.ToRecord(account, credentials), AnchorJsonContext.Default.AccountRecord);
    }

    // ── Somebody else's password ──────────────────────────────────────────────

    /// <summary>
    /// Set somebody's password as an administrator.
    /// </summary>
    /// <remarks>
    /// Knows no current password, because the case it exists for is somebody who has lost theirs. It
    /// clears the lockout with it — an admin resetting a password for a person locked out of their own
    /// account has plainly resolved what the lockout existed for.
    /// </remarks>
    internal static async Task SetPassword(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.Admin);
        if (maybe is not { } caller)
            return;

        if (await SubjectAsync(ctx) is not { } user)
            return;

        PasswordSetRequest? body =
            await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.PasswordSetRequest);
        if (body is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request",
                "The request body is not readable.");
            return;
        }

        if (!Passwords.IsAcceptable(body.Password))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "password_too_short",
                $"A password must be at least {Passwords.MinLength} characters.");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        await ctx.RequestServices.GetRequiredService<LocalSignInService>()
            .SetPasswordAsync(user.UserId, body.Password!, now, ctx.RequestAborted);

        await AnnounceAsync(ctx, user, now);

        await ctx.RequestServices.GetRequiredService<AnchorJournal>().AccountAsync(
            AuthEvents.UserPasswordChanged, user.UserId, user.Username,
            byHolder: false,
            actor: ActorOf(caller),
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    // ── An account ending ─────────────────────────────────────────────────────

    /// <summary>
    /// Delete an account from the cluster.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The removal travels as a versioned tombstone rather than as an absence, because a member that
    /// was down would otherwise learn nothing and go on holding the account — and would hand it back
    /// the next time it took a snapshot from anywhere. A member that never saw the account records
    /// the version anyway, so a late arrival cannot resurrect it.
    /// </para>
    /// <para>
    /// The last administrator is refused, for the same reason a self-demotion is: an account store
    /// with nobody able to administer it cannot be repaired through any surface.
    /// </para>
    /// </remarks>
    internal static async Task DeleteAccount(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.Admin);
        if (maybe is not { } caller)
            return;

        if (await SubjectAsync(ctx) is not { } user)
            return;

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();

        if (user.EffectiveTier == KgsmTier.Admin
            && !await Endpoints.AnotherAdminExistsAsync(store, user.UserId, ctx.RequestAborted))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "last_admin",
                "This is the only administrator the cluster has. Promote somebody else first.");
            return;
        }

        if (!await store.DeleteAsync(user.UserId, ctx.RequestAborted))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_account",
                "No account has that id.");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        long version = await ctx.RequestServices.GetRequiredService<IAccountVersions>()
            .NextAsync(user.UserId, now, AccountAnnouncementKind.Removed, ctx.RequestAborted);

        await ctx.RequestServices.GetRequiredService<AccountBroadcast>()
            .DrainAsync(ctx.RequestAborted);

        // Nothing announces the sessions. A member resolves authority against its replica on every
        // request, and an account that is not there answers "no account" — so the removal above ends
        // every session this person holds, everywhere, as soon as it lands. A second announcement
        // would be a second mechanism for one fact, free to disagree with it.

        // Written after the deletion, naming an account that no longer exists. That is the point of a
        // trail: the row outlives its subject, and an account removed with no record of who removed
        // it is the removal nobody can review.
        await ctx.RequestServices.GetRequiredService<AnchorJournal>().AccountAsync(
            AuthEvents.UserDeleted, user.UserId, user.Username,
            fromTier: KgsmTiers.ToWire(user.Tier),
            fromStatus: UserStatuses.ToWire(user.Status),
            actor: ActorOf(caller),
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    // ── Ways into an account ──────────────────────────────────────────────────

    /// <summary>
    /// Detach one of <paramref name="user"/>'s credentials and answer, the caller's gates already passed.
    /// </summary>
    /// <remarks>
    /// Scoped to <paramref name="user"/>, because the credential id is the whole of what a caller
    /// supplies: an id copied from somewhere else would otherwise detach a stranger's identity. The
    /// account page is the door that calls it, having established that the person asking is the
    /// account's holder and has proved it lately.
    /// </remarks>
    internal static async Task UnlinkAsync(HttpContext ctx, KgsmUser user, string credentialId, string actor)
    {
        if (credentialId.Length == 0)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_credential",
                "A credential id is required.");
            return;
        }

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();

        // Read before it is detached: afterwards there is nothing left to say which identity this was,
        // and a line naming only an opaque id records that something was removed without saying what.
        UserCredential? detaching = (await store.ListCredentialsAsync(user.UserId, ctx.RequestAborted))
            .FirstOrDefault(c => c.CredentialId == credentialId);

        UnlinkOutcome outcome = await ctx.RequestServices
            .GetRequiredService<IdentityLinkService>()
            .UnlinkAsync(user.UserId, credentialId, ctx.RequestAborted);

        switch (outcome)
        {
            case UnlinkOutcome.NotFound:
                await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_credential",
                    "This account has no such way in.");
                return;

            case UnlinkOutcome.LastCredential:
                await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "last_credential",
                    "This is the only way into this account. Add another before removing it.");
                return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        await AnnounceAsync(ctx, user, now);

        if (detaching is { } gone)
        {
            await ctx.RequestServices.GetRequiredService<AnchorJournal>().IdentityAsync(
                AuthEvents.IdentityUnlinked, user.UserId, user.Username,
                IdentityEndpoints.ProviderOf(gone.Handle), gone.Handle,
                actor: actor,
                origin: AnchorJournal.OriginUi,
                ct: ctx.RequestAborted);
        }

        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    /// <summary>The account the route names, or null with the refusal already written.</summary>
    private static async Task<KgsmUser?> SubjectAsync(HttpContext ctx)
    {
        if (ctx.Request.RouteValues["userId"] as string is not { Length: > 0 } userId)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_user",
                "A user id is required.");
            return null;
        }

        KgsmUser? user = await ctx.RequestServices.GetRequiredService<IUserStore>()
            .FindByIdAsync(userId, ctx.RequestAborted);

        if (user is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_account",
                "No account has that id.");
        }

        return user;
    }

    /// <summary>
    /// Tell every member the account's current state, at a new version.
    /// </summary>
    /// <remarks>
    /// A credential change moves what replicates — a member holds the handles an account can be proved
    /// by, so one that is not told goes on resolving a session against a way in that no longer exists.
    /// </remarks>
    internal static async Task AnnounceAsync(HttpContext ctx, KgsmUser user, DateTimeOffset now)
    {
        await ctx.RequestServices.GetRequiredService<IAccountVersions>()
            .NextAsync(user.UserId, now, AccountAnnouncementKind.Changed, ctx.RequestAborted);

        await ctx.RequestServices.GetRequiredService<AccountBroadcast>()
            .DrainAsync(ctx.RequestAborted);
    }

    /// <summary>The administrator who acted, as an audit trail names one.</summary>
    private static string ActorOf(Caller caller) =>
        caller.Identity?.ActorString
        ?? (caller.User is { } self ? self.AsIdentity().ActorString : string.Empty);
}
