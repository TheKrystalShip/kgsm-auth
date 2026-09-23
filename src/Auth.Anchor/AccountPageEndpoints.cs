using System.Collections.Concurrent;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Round trips to an external provider started to prove the person on the account page again, keyed by
/// the <c>state</c> each began with.
/// </summary>
/// <remarks>
/// In memory: a restart drops the ones in flight, which costs a click and grants nothing. A returning
/// <c>state</c> found here is a re-proof and nothing else — never a sign-in, never a new account.
/// </remarks>
internal sealed class ReauthRoundTrips
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<string, (string ProviderSession, string UserId, DateTimeOffset Expires)> _pending =
        new(StringComparer.Ordinal);

    public void Begin(string state, string providerSession, string userId)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach (var entry in _pending)
        {
            if (entry.Value.Expires <= now)
                _pending.TryRemove(entry.Key, out _);
        }
        _pending[state] = (providerSession, userId, now + Ttl);
    }

    public (string ProviderSession, string UserId)? Take(string? state) =>
        state is not null && _pending.TryRemove(state, out var entry) && entry.Expires > DateTimeOffset.UtcNow
            ? (entry.ProviderSession, entry.UserId)
            : null;
}

/// <summary>
/// The account page: somebody's own password, the identities that prove them, and where they are signed in.
/// </summary>
/// <remarks>
/// <para>
/// <b>Authenticated by the provider's own cookie, and same-origin only.</b> Nothing a surface holds can
/// change how somebody signs in; only this origin's pages can, and every write here needs the
/// same-origin gate a credential post needs.
/// </para>
/// <para>
/// <b>A change to how somebody signs in needs a recent proof.</b> The provider session records when a
/// credential was last typed or a provider last completed for it; older than the re-authentication
/// window, the page asks for the password again — or a round trip to a provider, for an account with
/// none. A cookie proves a browser signed in within the refresh lifetime, not that the person at it is
/// the one who did.
/// </para>
/// </remarks>
internal static class AccountPageEndpoints
{
    /// <summary>
    /// The request-in-flight client a sign-in for the account page itself runs under. Never registered
    /// and never issued a code: completing it returns the browser to <c>/account</c> with its provider
    /// session proved, which is all this page needs.
    /// </summary>
    internal const string AccountClientId = "kgsm-account";

    /// <summary>What a person is told they are signing in to, on the account page's own sign-in.</summary>
    internal const string AccountClientName = "your account";

    // ── The page ──────────────────────────────────────────────────────────────

    /// <summary><c>GET /account</c>: the page, or its sign-in when this browser holds none.</summary>
    internal static async Task Page(HttpContext ctx)
    {
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        if (options.IssuerUrl is null)
        {
            await ProviderPages.ProblemAsync(ctx, StatusCodes.Status503ServiceUnavailable, "Sign-in is not set up",
                "This anchor has no issuer address, so it signs nobody in.");
            return;
        }

        if (await ctx.RequestServices.GetRequiredService<ProviderSessions>().CurrentAsync(ctx) is null)
        {
            ctx.Response.Redirect("/account/sign-in");
            return;
        }

        if (await ctx.RequestServices.GetRequiredService<ProviderBundle>()
                .TryServeAsync(ctx, ProviderBundle.Page.Account, clientOrigin: null, []))
            return;

        await ProviderPages.ProblemAsync(ctx, StatusCodes.Status503ServiceUnavailable, "Account page not installed",
            "The account page comes with kgsm-web-auth, which is not installed here.");
    }

    /// <summary><c>GET /account/sign-in</c>: sign in at the anchor to reach the account page.</summary>
    internal static async Task SignIn(HttpContext ctx)
    {
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        if (options.IssuerUrl is null || !ctx.RequestServices.GetRequiredService<AnchorRole>().IsAuthority)
        {
            await ProviderPages.ProblemAsync(ctx, StatusCodes.Status503ServiceUnavailable, "Not signing in here",
                "This member does not sign anybody in.");
            return;
        }

        AuthorizeRequest request = await OidcEndpoints.BeginRequestAsync(
            ctx, AccountClientId, options.Issuer + "/account", state: null, challenge: "", nonce: null, prompt: null);
        await OidcEndpoints.SignInPageAsync(ctx, request, message: null);
    }

    // ── Reading ───────────────────────────────────────────────────────────────

    /// <summary><c>GET /account/me</c>: everything the account page draws.</summary>
    internal static async Task Me(HttpContext ctx)
    {
        if (await CallerAsync(ctx, write: false) is not var (session, user))
            return;

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();
        var catalog = ctx.RequestServices.GetRequiredService<ProviderCatalog>();
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();

        IReadOnlyList<UserCredential> credentials = await store.ListCredentialsAsync(user.UserId, ctx.RequestAborted);
        IReadOnlyList<string> handles = [.. credentials.Select(c => c.Handle).Distinct(StringComparer.Ordinal)];
        IReadOnlyList<SqliteSessionRegistry.LiveSession> live = await ctx.RequestServices
            .GetRequiredService<SqliteSessionRegistry>().ListAsync(handles, ctx.RequestAborted);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new AccountView(
            UserId: user.UserId,
            Username: user.Username,
            DisplayName: user.DisplayName,
            Tier: KgsmTiers.ToWire(user.EffectiveTier),
            Status: UserStatuses.ToWire(user.Status),
            HasPassword: credentials.Any(c => c.Kind == CredentialKind.Password),
            Identities: [.. credentials.Where(c => c.Kind == CredentialKind.Identity).Select(c => new AccountIdentity(
                c.CredentialId, IdentityEndpoints.ProviderOf(c.Handle), c.Handle, c.Label, c.Created, c.LastUsed))],
            Providers: catalog.Configured,
            KnownProviders: catalog.Known,
            ProvedAt: session.CredentialAt,
            FreshUntil: FreshUntil(session, options),
            ReauthWindowSeconds: (int)options.ReauthWindow.TotalSeconds,
            Sessions: [.. live.Select(s => new SessionRecord(
                s.SessionId, s.UserId, s.Created, s.Expires, s.UserAgent, s.LastSeen,
                Current: s.SessionId == session.SessionId,
                Kind: s.Provider ? SqliteSessionRegistry.ProviderKind : null))]),
            AnchorJsonContext.Default.AccountView);
    }

    // ── Proving it again ──────────────────────────────────────────────────────

    /// <summary><c>POST /account/reauth</c>: the password again, which opens the window.</summary>
    internal static async Task Reauth(HttpContext ctx)
    {
        if (await CallerAsync(ctx, write: true) is not var (session, user))
            return;

        ReauthRequest? body = await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.ReauthRequest);
        if (body?.Password is not { Length: > 0 } password)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request", "A password is required.");
            return;
        }

        IReadOnlyList<UserCredential> credentials = await ctx.RequestServices.GetRequiredService<IUserStore>()
            .ListCredentialsAsync(user.UserId, ctx.RequestAborted);
        if (!credentials.Any(c => c.Kind == CredentialKind.Password))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "no_password",
                "This account has no password. Confirm it with a connected account instead.");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (await Endpoints.CheckPasswordAsync(ctx, user.Username, password, now) is not { } result)
        {
            await Endpoints.Unavailable(ctx);
            return;
        }

        switch (result.Outcome)
        {
            case LocalSignInOutcome.Success:
                break;

            case LocalSignInOutcome.LockedOut:
                if (result.RetryAfter is { } until)
                    ctx.Response.Headers.RetryAfter = Endpoints.RetryAfterSeconds(until, now).ToString();
                await Endpoints.Refuse(ctx, StatusCodes.Status429TooManyRequests, "account_locked",
                    "Too many failed attempts. Try again shortly.");
                return;

            default:
                await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "invalid_credentials",
                    "That password is not correct.");
                return;
        }

        await ReproveAsync(ctx, session, session.Identity, now);
        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new ReauthResult(now + ctx.RequestServices.GetRequiredService<AnchorOptions>().ReauthWindow),
            AnchorJsonContext.Default.ReauthResult);
    }

    /// <summary>
    /// <c>GET /account/reauth/{provider}</c>: prove it with a connected account, for an account with no
    /// password.
    /// </summary>
    /// <remarks>
    /// The round trip returns through the provider door's registered callback, which recognises its
    /// <c>state</c> and accepts only an identity already attached to this same account. The provider is
    /// asked to show its consent screen, because a silent round trip proves only that the browser is
    /// still signed in over there.
    /// </remarks>
    internal static async Task ReauthWithProvider(HttpContext ctx)
    {
        if (await CallerAsync(ctx, write: false) is not var (session, user))
            return;

        string provider = (string?)ctx.Request.RouteValues["provider"] ?? "";
        if (ctx.RequestServices.GetRequiredService<ProviderCatalog>().Identity(provider) is not { } directory)
        {
            ctx.Response.Redirect("/account#reauth_error=auth_unconfigured");
            return;
        }

        OAuthHandshake handshake = OAuthHandshake.Create();
        ctx.RequestServices.GetRequiredService<ReauthRoundTrips>().Begin(handshake.State, session.SessionId, user.UserId);
        ProviderEndpoints.BeginHandshake(ctx, handshake);
        ctx.Response.Redirect(directory.BuildAuthorizeUrl(handshake.State, handshake.CodeChallenge, "consent"));
    }

    /// <summary>
    /// A provider round trip began from the account page has returned with <paramref name="verified"/>.
    /// </summary>
    /// <returns>Where the browser goes: the account page, saying whether it worked.</returns>
    internal static async Task<string> CompleteReauthAsync(
        HttpContext ctx, (string ProviderSession, string UserId) pending, KgsmIdentity verified)
    {
        // Resolved, never provisioned: an identity nobody has attached is a stranger, and a re-proof is
        // not a way to make an account.
        KgsmUser? holder = await ctx.RequestServices.GetRequiredService<IUserStore>()
            .FindByCredentialAsync(verified.Handle, ctx.RequestAborted);
        if (holder is null || !string.Equals(holder.UserId, pending.UserId, StringComparison.Ordinal))
            return "/account#reauth_error=other_account";

        if (await ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>()
                .FindProviderSessionAsync(pending.ProviderSession, ctx.RequestAborted) is not { } session)
            return "/account/sign-in";

        await ReproveAsync(ctx, session, StoredIdentity.From(verified), DateTimeOffset.UtcNow);
        return "/account#proved";
    }

    private static Task ReproveAsync(HttpContext ctx, ProviderSessionRow session, StoredIdentity identity, DateTimeOffset now) =>
        ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>().ReproveProviderSessionAsync(
            session.SessionId, identity.Handle, identity.ToJson(), now,
            now.Add(ctx.RequestServices.GetRequiredService<AnchorOptions>().RefreshLifetime), ctx.RequestAborted);

    // ── Changing how somebody signs in ────────────────────────────────────────

    /// <summary><c>POST /account/password</c>: set this account's own password, with a recent proof.</summary>
    /// <remarks>
    /// No current password is asked for here: the recent proof is that question, answered within the
    /// window. It is also how an account that has only ever signed in with a provider gains a password.
    /// </remarks>
    internal static async Task SetPassword(HttpContext ctx)
    {
        if (await FreshCallerAsync(ctx) is not var (session, user))
            return;

        PasswordSetRequest? body = await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.PasswordSetRequest);
        if (!Passwords.IsAcceptable(body?.Password))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "password_too_short",
                $"A password must be at least {Passwords.MinLength} characters.");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        await ctx.RequestServices.GetRequiredService<LocalSignInService>()
            .SetPasswordAsync(user.UserId, body!.Password!, now, ctx.RequestAborted);
        await AccountEndpoints.AnnounceAsync(ctx, user, now);

        await ctx.RequestServices.GetRequiredService<AnchorJournal>().AccountAsync(
            AuthEvents.UserPasswordChanged, user.UserId, user.Username,
            byHolder: true,
            actor: session.Identity.ToIdentity().ActorString,
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    /// <summary>
    /// <c>POST /account/identities/{provider}/start</c>: begin attaching an account at a provider.
    /// </summary>
    /// <remarks>
    /// Same-origin, so the link ticket's cookie is first-party. It returns through the link callback
    /// registered with the provider, which sends the browser back to this page because the ticket names a
    /// provider session.
    /// </remarks>
    internal static async Task StartLink(HttpContext ctx)
    {
        if (await FreshCallerAsync(ctx) is not var (session, user))
            return;

        string provider = (string?)ctx.Request.RouteValues["provider"] ?? "";
        if (ctx.RequestServices.GetRequiredService<ProviderCatalog>().Link(provider) is not { } directory)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "auth_unconfigured",
                $"Connecting a {provider} account is not configured on this cluster.");
            return;
        }

        IReadOnlyList<UserCredential> credentials = await ctx.RequestServices.GetRequiredService<IUserStore>()
            .ListCredentialsAsync(user.UserId, ctx.RequestAborted);
        if (credentials.Any(c => c.Kind == CredentialKind.Identity
            && string.Equals(IdentityEndpoints.ProviderOf(c.Handle), directory.Provider, StringComparison.OrdinalIgnoreCase)))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "already_linked",
                $"A {directory.Provider} account is already connected. Disconnect it first.");
            return;
        }

        OAuthHandshake handshake = OAuthHandshake.Create();
        string ticket = ctx.RequestServices.GetRequiredService<LinkTicketStore>()
            .Issue(user.UserId, session.SessionId, handshake);
        IdentityEndpoints.SetTicketCookie(ctx, ticket);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new LinkStartResponse(directory.BuildAuthorizeUrl(handshake.State, handshake.CodeChallenge, "consent")),
            AnchorJsonContext.Default.LinkStartResponse);
    }

    /// <summary><c>DELETE /account/identities/{credentialId}</c>: detach an identity, with a recent proof.</summary>
    internal static async Task Unlink(HttpContext ctx)
    {
        if (await FreshCallerAsync(ctx) is not var (session, user))
            return;

        string credentialId = (string?)ctx.Request.RouteValues["credentialId"] ?? "";
        await AccountEndpoints.UnlinkAsync(ctx, user, credentialId, session.Identity.ToIdentity().ActorString);
    }

    // ── Where somebody is signed in ───────────────────────────────────────────

    /// <summary>
    /// <c>POST /account/sessions/revoke</c>: end one of this account's sessions, or every one of them.
    /// </summary>
    /// <remarks>
    /// Not gated on a recent proof: ending sessions takes access away. Ending this browser's own sign-in
    /// here is signing out, and "every one" includes it.
    /// </remarks>
    internal static async Task Revoke(HttpContext ctx)
    {
        if (await CallerAsync(ctx, write: true) is not var (session, user))
            return;

        RevokeRequest? body = await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.RevokeRequest);
        var registry = ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>();
        var sessions = ctx.RequestServices.GetRequiredService<ProviderSessions>();
        var journal = ctx.RequestServices.GetRequiredService<AnchorJournal>();
        string actor = session.Identity.ToIdentity().ActorString;

        IReadOnlyList<string> handles = [.. (await ctx.RequestServices.GetRequiredService<IUserStore>()
            .ListCredentialsAsync(user.UserId, ctx.RequestAborted)).Select(c => c.Handle).Distinct(StringComparer.Ordinal)];

        if (body?.All == true)
        {
            IReadOnlyList<string> ended = await registry.RevokeAllAsync(handles, ctx.RequestAborted);
            var validator = ctx.RequestServices.GetRequiredService<ISessionValidator>();
            var broadcast = ctx.RequestServices.GetRequiredService<SessionBroadcast>();
            foreach (string sid in ended)
            {
                validator.Evict(sid);
                ctx.RequestServices.GetRequiredService<ReauthGate>().Forget(sid);
                await broadcast.RevokedAsync(sid, ctx.RequestAborted);
            }

            if (ended.Count > 0)
            {
                await journal.SessionRevokedAsync(SessionRevokeScopes.All, user.UserId, user.Username, sid: null,
                    ended.Count, actor, AnchorJournal.OriginUi, ctx.RequestAborted);
            }

            sessions.ClearCookie(ctx);
            await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new RevokeResult(ended.Count),
                AnchorJsonContext.Default.RevokeResult);
            return;
        }

        if (body?.Sid is not { Length: > 0 } target
            || await registry.OwnerAsync(target, ctx.RequestAborted) is not { } owner
            || !handles.Contains(owner, StringComparer.Ordinal))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_session", "This account has no such session.");
            return;
        }

        if (await registry.IsProviderSessionAsync(target, ctx.RequestAborted))
        {
            await sessions.EndAsync(ctx, target);
            if (target == session.SessionId)
                sessions.ClearCookie(ctx);
        }
        else
        {
            await registry.RevokeAsync(target, ctx.RequestAborted);
            ctx.RequestServices.GetRequiredService<ISessionValidator>().Evict(target);
            ctx.RequestServices.GetRequiredService<ReauthGate>().Forget(target);
            await ctx.RequestServices.GetRequiredService<SessionBroadcast>().RevokedAsync(target, ctx.RequestAborted);
            await journal.SessionRevokedAsync(SessionRevokeScopes.Self, user.UserId, user.Username, target,
                count: null, actor, AnchorJournal.OriginUi, ctx.RequestAborted);
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new RevokeResult(1), AnchorJsonContext.Default.RevokeResult);
    }

    /// <summary><c>POST /account/sign-out</c>: end this browser's sign-in and every session under it.</summary>
    internal static async Task SignOut(HttpContext ctx)
    {
        if (await CallerAsync(ctx, write: true) is not var (session, _))
            return;

        var sessions = ctx.RequestServices.GetRequiredService<ProviderSessions>();
        await sessions.EndAsync(ctx, session.SessionId);
        sessions.ClearCookie(ctx);
        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The browser's provider session and the account it proves, or null with the refusal written.
    /// </summary>
    /// <remarks>
    /// The account is re-read, never taken from the session: a disabled account is refused here as it is
    /// at every other door. A write needs the same-origin gate every post on this origin needs.
    /// </remarks>
    private static async Task<(ProviderSessionRow Session, KgsmUser User)?> CallerAsync(HttpContext ctx, bool write)
    {
        if (ctx.RequestServices.GetRequiredService<AnchorOptions>().IssuerUrl is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "no_issuer",
                "This anchor has no issuer address, so it signs nobody in.");
            return null;
        }

        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return null;

        if (write && !OidcEndpoints.IsSameOrigin(ctx))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "cross_site",
                "An account change can only be sent from the account page.");
            return null;
        }

        if (await ctx.RequestServices.GetRequiredService<ProviderSessions>().CurrentAsync(ctx) is not { } session)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status401Unauthorized, "unauthenticated", "Sign in to continue.");
            return null;
        }

        KgsmUser? user;
        try
        {
            user = await ctx.RequestServices.GetRequiredService<IUserStore>()
                .FindByCredentialAsync(session.Handle, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await Endpoints.Unavailable(ctx);
            return null;
        }

        if (user is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status401Unauthorized, "unauthenticated", "Sign in to continue.");
            return null;
        }

        if (user.Status == UserStatus.Disabled)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "account_disabled",
                "This account has been switched off.");
            return null;
        }

        return (session, user);
    }

    /// <summary>As <see cref="CallerAsync"/> for a write, and refused unless the last proof is recent.</summary>
    private static async Task<(ProviderSessionRow Session, KgsmUser User)?> FreshCallerAsync(HttpContext ctx)
    {
        if (await CallerAsync(ctx, write: true) is not { } caller)
            return null;

        if (FreshUntil(caller.Session, ctx.RequestServices.GetRequiredService<AnchorOptions>()) is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "reauth_required",
                "Confirm it is you before changing how you sign in.");
            return null;
        }

        return caller;
    }

    private static DateTimeOffset? FreshUntil(ProviderSessionRow session, AnchorOptions options)
    {
        DateTimeOffset until = session.CredentialAt + options.ReauthWindow;
        return until > DateTimeOffset.UtcNow ? until : null;
    }
}
