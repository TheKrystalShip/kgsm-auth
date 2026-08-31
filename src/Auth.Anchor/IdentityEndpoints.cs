using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Changing what proves an account.
/// </summary>
/// <remarks>
/// <para>
/// <b>These ask for a credential again, and the rest of the anchor does not.</b> Holding a session is
/// not the same as having proved you own it, and the two come apart exactly where it matters — an
/// unlocked laptop, a browser left signed in, a token lifted from storage. Most of what a session does
/// is bounded by that session's own life, so the distinction costs nothing. Attaching an identity is
/// not: afterwards whoever holds that provider account can sign in as this one, for as long as the
/// account exists.
/// </para>
/// <para>
/// <b>Signing in counts as proving it.</b> Every door that mints a session stamps it, so somebody who
/// has just arrived attaches an account without being asked for anything, and somebody returning to a
/// week-old tab is asked once.
/// </para>
/// </remarks>
internal static class IdentityEndpoints
{
    /// <summary>The cookie carrying the opaque ticket for a link in flight.</summary>
    /// <remarks>
    /// The ticket and nothing else. The account being changed stays on this machine — a browser
    /// carrying its own account id would be the authority on whose account is being attached to.
    /// </remarks>
    private const string TicketCookie = "kgsm_link_ticket";

    /// <summary>Prove the caller's password again, opening the window in which they may change it.</summary>
    internal static async Task Reauth(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.None);
        if (maybe is not { } caller || caller.User is not { } user)
            return;

        ReauthRequest? body = await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.ReauthRequest);
        if (body?.Password is not { Length: > 0 })
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request",
                "A password is required.");
            return;
        }

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();
        IReadOnlyList<UserCredential> credentials =
            await store.ListCredentialsAsync(user.UserId, ctx.RequestAborted);

        // A distinct answer from a wrong password, because the way through is different: there is
        // nothing here to prove, and signing in again stamps the session it mints.
        if (!credentials.Any(c => c.Kind == CredentialKind.Password && c.Secret is not null))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "no_password",
                "This account has no password. Sign in again to change your connected accounts.");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        LocalSignInResult result;
        try
        {
            result = await ctx.RequestServices.GetRequiredService<LocalSignInService>()
                .SignInAsync(user.Username, body.Password, now, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await Endpoints.Unavailable(ctx);
            return;
        }

        // The same lockout a sign-in gets, because this is the same check — an unbounded one here
        // would be the way around it.
        if (result.Outcome == LocalSignInOutcome.LockedOut)
        {
            int seconds = (int)Math.Max(1, Math.Ceiling(((result.RetryAfter ?? now) - now).TotalSeconds));
            ctx.Response.Headers.RetryAfter = seconds.ToString();
            await Endpoints.Refuse(ctx, StatusCodes.Status429TooManyRequests, "account_locked",
                "Too many failed attempts. Try again shortly.");
            return;
        }

        if (result.Outcome != LocalSignInOutcome.Success)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "invalid_credentials",
                "That password is not correct.");
            return;
        }

        var gate = ctx.RequestServices.GetRequiredService<ReauthGate>();
        gate.Stamp(caller.SessionId);

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new ReauthResult(gate.FreshUntil(caller.SessionId) ?? now + gate.Window),
            AnchorJsonContext.Default.ReauthResult);
    }

    /// <summary>Begin attaching an account at a provider.</summary>
    internal static async Task StartLink(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        string provider = (string?)ctx.Request.RouteValues["provider"] ?? "";

        if (ctx.RequestServices.GetRequiredService<ProviderCatalog>().Link(provider) is not { } directory)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "auth_unconfigured",
                $"Connecting a {provider} account is not configured on this cluster.");
            return;
        }

        Caller? maybe = await Endpoints.RequireCaller(ctx, KgsmTier.None);
        if (maybe is not { } caller || caller.User is not { } user)
            return;

        if (!ctx.RequestServices.GetRequiredService<ReauthGate>().IsFresh(caller.SessionId))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "reauth_required",
                "Prove your password before changing how you sign in.");
            return;
        }

        // One account per provider, per KGSM account. The store's own constraint is stricter in a
        // different direction — an identity belongs to exactly one account, table-wide — so it would
        // let somebody attach a second account at the same provider and never say which one signs
        // them in.
        IReadOnlyList<UserCredential> credentials = await ctx.RequestServices
            .GetRequiredService<IUserStore>()
            .ListCredentialsAsync(user.UserId, ctx.RequestAborted);

        if (credentials.Any(c => c.Kind == CredentialKind.Identity
            && string.Equals(ProviderOf(c.Handle), directory.Provider, StringComparison.OrdinalIgnoreCase)))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "already_linked",
                $"A {directory.Provider} account is already connected. Disconnect it first.");
            return;
        }

        OAuthHandshake handshake = OAuthHandshake.Create();
        string ticket = ctx.RequestServices.GetRequiredService<LinkTicketStore>()
            .Issue(user.UserId, caller.SessionId ?? string.Empty, handshake);

        ctx.Response.Cookies.Append(TicketCookie, ticket, CookieOptions(ctx));

        // `consent` rather than the silent `none` a sign-in uses: somebody attaching an account is
        // choosing WHICH account, and a silent bounce attaches whichever one that browser happens to
        // be signed into without ever showing them which.
        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new LinkStartResponse(
                directory.BuildAuthorizeUrl(handshake.State, handshake.CodeChallenge, "consent")),
            AnchorJsonContext.Default.LinkStartResponse);
    }

    /// <summary>
    /// Take the provider's answer and attach the identity to the account that started the link.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unauthenticated by necessity: this is a top-level navigation from the provider and a bearer
    /// does not survive one. What authorizes it is the ticket — issued to a session that had proved a
    /// credential minutes ago, single-use, and holding the account id on this machine so the browser
    /// never carries it.
    /// </para>
    /// <para>
    /// Freshness is checked when the link is <em>started</em> and not again here. The bounce takes as
    /// long as it takes, and re-checking would fail a link somebody legitimately began while adding
    /// nothing: the ticket is already one-use, short-lived and unforgeable.
    /// </para>
    /// </remarks>
    internal static async Task CompleteLink(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        string provider = (string?)ctx.Request.RouteValues["provider"] ?? "";
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.IdentityEndpoints");

        // Cleared whatever the outcome, so a ticket cannot be replayed from history or a log.
        string? cookie = ctx.Request.Cookies[TicketCookie];
        if (cookie is not null)
            ctx.Response.Cookies.Delete(TicketCookie, CookieOptions(ctx));

        LinkTicket? ticket = ctx.RequestServices.GetRequiredService<LinkTicketStore>()
            .Redeem(cookie, ctx.Request.Query["state"]);

        if (ticket is null)
        {
            await Fail(ctx, options, StatusCodes.Status400BadRequest, "invalid_state",
                "That link could not be verified. Start again.");
            return;
        }

        if (ctx.RequestServices.GetRequiredService<ProviderCatalog>().Link(provider) is not { } directory)
        {
            await Fail(ctx, options, StatusCodes.Status503ServiceUnavailable, "auth_unconfigured",
                $"Connecting a {provider} account is not configured on this cluster.");
            return;
        }

        if (ctx.Request.Query["code"].ToString() is not { Length: > 0 } code)
        {
            await Fail(ctx, options, StatusCodes.Status400BadRequest, "bad_request",
                "The provider returned no authorization code.");
            return;
        }

        KgsmIdentity? verified;
        try
        {
            verified = await directory.VerifyAsync(code, ticket.Handshake.CodeVerifier, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException ex)
        {
            logger.LogWarning(ex, "{Provider} link exchange failed", provider);
            await Fail(ctx, options, StatusCodes.Status502BadGateway, "auth_provider_error",
                "Could not finish authenticating with the provider.");
            return;
        }

        if (verified is null)
        {
            await Fail(ctx, options, StatusCodes.Status401Unauthorized, "login_required",
                "That authorization code was invalid or expired.");
            return;
        }

        LinkResult link;
        try
        {
            link = await ctx.RequestServices.GetRequiredService<IdentityLinkService>()
                .LinkAsync(ticket.UserId, verified, DateTimeOffset.UtcNow, ctx.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "could not attach {Handle} to {UserId}", verified.Handle, ticket.UserId);
            await Fail(ctx, options, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
                "The account store could not be written.");
            return;
        }

        // Attached to somebody else. Refused rather than moved: re-pointing a credential hands one
        // person another's account, and the person on the other end would never learn it happened.
        if (link.Outcome == LinkOutcome.AlreadyLinked)
        {
            await Fail(ctx, options,
                link.User is null ? StatusCodes.Status404NotFound : StatusCodes.Status409Conflict,
                link.User is null ? "no_such_account" : "identity_taken",
                link.User is null
                    ? "That account no longer exists."
                    : $"That {provider} account is already connected to another account.");
            return;
        }

        KgsmUser account = link.User!;

        // Provisioned means the credential was ADDED. Existing means it was already on this same
        // account — a repeated click, and not something to write a privilege event about.
        if (link.Outcome == LinkOutcome.Provisioned)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            // Every member holds the handles an account can be proved by, so one that is not told
            // would refuse a session this identity establishes.
            long version = await ctx.RequestServices.GetRequiredService<IAccountVersions>()
                .NextAsync(account.UserId, now, ctx.RequestAborted);
            await ctx.RequestServices.GetRequiredService<AccountBroadcast>()
                .PublishAsync(account with { Updated = now }, version, ctx.RequestAborted);

            await ctx.RequestServices.GetRequiredService<AnchorJournal>().IdentityAsync(
                AuthEvents.IdentityLinked, account.UserId, account.Username,
                verified.Provider, verified.Handle,
                // The person who attached it, which is the account's own holder — this door cannot be
                // reached any other way.
                actor: account.AsIdentity().ActorString,
                origin: AnchorJournal.OriginUi,
                ct: ctx.RequestAborted);

            logger.LogInformation(
                "{Handle} attached to '{Username}'", verified.Handle, account.Username);
        }

        if (options.RedirectsToPanel)
        {
            ctx.Response.Redirect($"{options.FrontendUrl}#linked={Uri.EscapeDataString(verified.Provider)}");
            return;
        }

        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    /// <summary>
    /// Report a failed link the way the caller can act on.
    /// </summary>
    /// <remarks>
    /// A browser sent here by a redirect is sent back to the panel with the reason in the fragment,
    /// because leaving somebody on a JSON error page at an address they did not type is not an answer
    /// they can do anything with.
    /// </remarks>
    private static Task Fail(
        HttpContext ctx, AnchorOptions options, int status, string code, string message)
    {
        if (options.RedirectsToPanel)
        {
            ctx.Response.Redirect($"{options.FrontendUrl}#error={Uri.EscapeDataString(code)}");
            return Task.CompletedTask;
        }

        return Endpoints.Refuse(ctx, status, code, message);
    }

    /// <summary>
    /// The ticket cookie's attributes — shared by the set at start and the delete at callback, where
    /// Path has to match for the deletion to take.
    /// </summary>
    /// <remarks>
    /// <c>SameSite=Lax</c>, never Strict: Strict suppresses the cookie on the provider's top-level
    /// redirect back, which breaks every link. Secure tracks the scheme so it works on an http
    /// loopback yet is Secure on a real host.
    /// </remarks>
    private static CookieOptions CookieOptions(HttpContext ctx) => new()
    {
        HttpOnly = true,
        Secure = ctx.Request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Path = "/auth",
        IsEssential = true,
        MaxAge = LinkTicketStore.Ttl,
    };

    /// <summary>The provider half of a <c>provider:subject</c> handle.</summary>
    internal static string ProviderOf(string handle) =>
        handle.IndexOf(':', StringComparison.Ordinal) is > 0 and var at ? handle[..at] : handle;
}
