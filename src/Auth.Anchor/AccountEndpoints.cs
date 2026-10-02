using TheKrystalShip.KGSM.Auth.Access;
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
    /// The counterpart to registration: somebody who will never register themselves, or who arrives
    /// through a provider and should already be approved when they do. <c>auth:accounts.create</c>. The
    /// account holds only <c>everyone</c>; assigning it roles is the next, separate act.
    /// </remarks>
    internal static async Task CreateAccount(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, AuthAction.Of(ctx));
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
            // Made by somebody, which is what expiry reads to tell an admitted account from one that
            // arrived on its own.
            AccountOrigin.Admitted,
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

        await Endpoints.AnnounceAsync(ctx);

        // No "from": the account did not exist a moment ago, and a from/to pair would invent a
        // previous state to have moved out of.
        await ctx.RequestServices.GetRequiredService<AnchorJournal>().AccountAsync(
            AuthEvents.UserProvisioned, account.UserId, account.Username,
            toStatus: UserStatuses.ToWire(status),
            actor: ActorOf(caller),
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

        IReadOnlyList<UserCredential> credentials = await ctx.RequestServices
            .GetRequiredService<IUserStore>()
            .ListCredentialsAsync(account.UserId, ctx.RequestAborted);

        await Endpoints.WriteJson(ctx, StatusCodes.Status201Created,
            Endpoints.ToRecord(account, credentials), AnchorJsonContext.Default.AccountEntry);
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

        // Setting somebody's credential by hand is making their account by hand.
        Caller? maybe = await Endpoints.RequireCaller(ctx, AuthAction.Of(ctx));
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

        await Endpoints.AnnounceAsync(ctx);

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
    /// <c>auth:accounts.delete</c>, decided by the administration rules: the last active Owner is
    /// refused, only an Owner deletes an Owner, and a service account is never deleted by hand. Every
    /// assignment the account held goes with it, each journaled on its own.
    /// </para>
    /// <para>
    /// The removal travels as a versioned tombstone rather than as an absence, because a member that
    /// was down would otherwise learn nothing and go on holding the account — and would hand it back
    /// the next time it took a snapshot. Nothing announces the sessions: a member resolves every request
    /// against its replica, and an account that is not there is nobody, everywhere, as soon as the
    /// removal lands.
    /// </para>
    /// </remarks>
    internal static async Task DeleteAccount(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, AuthAction.Of(ctx));
        if (maybe is not { } caller)
            return;

        if (await SubjectAsync(ctx) is not { } user)
            return;

        SqliteAuthorityStore authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>().Store!;
        AuthorityWrite write;
        try
        {
            write = await authority.ApplyAsync(caller.User!.UserId, new Access.DeleteAccount(user.UserId),
                await authority.VersionAsync(ctx.RequestAborted), DateTimeOffset.UtcNow, ctx.RequestAborted);
        }
        catch (AuthorityRefusedException e)
        {
            await AuthorityEndpoints.RefuseAsync(ctx, e.Refusal);
            return;
        }
        catch (StaleAuthorityException)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "stale_authority", "Access changed meanwhile; try again.");
            return;
        }

        await Endpoints.AnnounceAsync(ctx);

        // Written after the deletion, naming an account that no longer exists. That is the point of a
        // trail: the row outlives its subject, and an account removed with no record of who removed
        // it is the removal nobody can review.
        await AuthorityJournaling.JournalAsync(ctx.RequestServices.GetRequiredService<AnchorJournal>(), write,
            ActorOf(caller), AnchorJournal.OriginUi, member: null, ctx.RequestAborted);

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
        await Endpoints.AnnounceAsync(ctx);

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

    private static string ActorOf(Caller caller) => Endpoints.ActorOf(caller);
}
