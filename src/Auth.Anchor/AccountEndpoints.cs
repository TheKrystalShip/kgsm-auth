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

    // ── A person's own password ───────────────────────────────────────────────

    /// <summary>
    /// Change the calling account's own password.
    /// </summary>
    /// <remarks>
    /// The password held now is required. A bearer left open on a shared machine is otherwise enough
    /// to lock somebody out of their own account for good, and this is the one door where the caller
    /// being signed in is not the whole of the proof.
    /// </remarks>
    internal static async Task ChangePassword(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.None);
        if (maybe is not { } caller || caller.User is not { } user)
            return;

        PasswordChangeRequest? body =
            await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.PasswordChangeRequest);
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

        var signIn = ctx.RequestServices.GetRequiredService<LocalSignInService>();
        DateTimeOffset now = DateTimeOffset.UtcNow;

        // Verified through the sign-in path rather than by comparing hashes here, so the door that
        // checks a password and the door that changes one cannot come to different conclusions about
        // the same one — and so a wrong current password costs a lockout the same way.
        LocalSignInResult proof;
        try
        {
            proof = await signIn.SignInAsync(user.Username, body.Current, now, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await Endpoints.Unavailable(ctx);
            return;
        }

        if (proof.Outcome != LocalSignInOutcome.Success)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "invalid_credentials",
                "That is not the password this account currently holds.");
            return;
        }

        await signIn.SetPasswordAsync(user.UserId, body.Password!, now, ctx.RequestAborted);
        await AnnounceAsync(ctx, user, now);

        await ctx.RequestServices.GetRequiredService<AnchorJournal>().AccountAsync(
            AuthEvents.UserPasswordChanged, user.UserId, user.Username,
            // The whole point of recording it: somebody else setting your password reads completely
            // differently from you setting it, and a line that could not tell them apart would report
            // a takeover and a routine rotation identically.
            byHolder: true,
            actor: (caller.Identity ?? user.AsIdentity()).ActorString,
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

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

    /// <summary>Every external identity attached to the calling account.</summary>
    internal static async Task Identities(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.None);
        if (maybe is not { } caller || caller.User is not { } user)
            return;

        IReadOnlyList<UserCredential> credentials = await ctx.RequestServices
            .GetRequiredService<IUserStore>()
            .ListCredentialsAsync(user.UserId, ctx.RequestAborted);

        IdentityRecord[] identities =
            [.. credentials
                .Where(c => c.Kind == CredentialKind.Identity)
                .Select(c => new IdentityRecord(
                    c.CredentialId, IdentityEndpoints.ProviderOf(c.Handle), c.Handle, c.Label,
                    c.Created, c.LastUsed))];

        var catalog = ctx.RequestServices.GetRequiredService<ProviderCatalog>();
        var gate = ctx.RequestServices.GetRequiredService<ReauthGate>();
        DateTimeOffset? fresh = gate.FreshUntil(caller.SessionId);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new IdentitiesResult(
            UserId: user.UserId,
            Username: user.Username,

            // Said separately from the list, because the password is not a way in that can be
            // detached — there is nothing about it to remove — and it is what decides whether
            // removing the last identity would leave a way in at all.
            HasPassword: credentials.Any(c => c.Kind == CredentialKind.Password),
            Identities: identities,

            // Every provider this build speaks, wired up or not. A surface needs both facts: it must
            // be able to say a provider is not set up here rather than silently omitting it, and it
            // must not offer a button that bounces to nothing.
            Providers:
                [.. catalog.Known.Select(p => new LinkableProvider(
                    p,
                    catalog.IsConfigured(p),
                    identities.Any(i => string.Equals(
                        i.Provider, p, StringComparison.OrdinalIgnoreCase))))],

            Reauth: new ReauthState(
                fresh is not null, fresh, (int)gate.Window.TotalMinutes)),
            AnchorJsonContext.Default.IdentitiesResult);
    }

    /// <summary>
    /// Detach an external identity from the calling account.
    /// </summary>
    /// <remarks>
    /// Scoped to the caller's own account, because the credential id is the whole of what a caller
    /// supplies: an id copied from somewhere else would otherwise detach a stranger's identity. One
    /// belonging to another account answers the same as one that does not exist, since telling those
    /// apart says whether an id is real.
    /// </remarks>
    internal static async Task Unlink(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.None);
        if (maybe is not { } caller || caller.User is not { } user)
            return;

        if (ctx.Request.RouteValues["credentialId"] as string is not { Length: > 0 } credentialId)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_credential",
                "A credential id is required.");
            return;
        }

        // The same gate attaching one passes. Detaching is the half that locks somebody out rather
        // than the half that lets somebody in, and a session somebody else is holding is exactly what
        // would be used for it.
        if (!ctx.RequestServices.GetRequiredService<ReauthGate>().IsFresh(caller.SessionId))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "reauth_required",
                "Prove your password before changing how you sign in.");
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
                actor: (caller.Identity ?? user.AsIdentity()).ActorString,
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
    private static async Task AnnounceAsync(HttpContext ctx, KgsmUser user, DateTimeOffset now)
    {
        long version = await ctx.RequestServices.GetRequiredService<IAccountVersions>()
            .NextAsync(user.UserId, now, AccountAnnouncementKind.Removed, ctx.RequestAborted);

        await ctx.RequestServices.GetRequiredService<AccountBroadcast>()
            .DrainAsync(ctx.RequestAborted);
    }

    /// <summary>The administrator who acted, as an audit trail names one.</summary>
    private static string ActorOf(Caller caller) =>
        caller.Identity?.ActorString
        ?? (caller.User is { } self ? self.AsIdentity().ActorString : string.Empty);
}
