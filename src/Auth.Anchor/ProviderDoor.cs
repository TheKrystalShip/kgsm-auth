using Microsoft.Extensions.Configuration;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// How one identity provider is built for this anchor.
/// </summary>
/// <param name="Provider">The name a route carries and a credential handle is prefixed with.</param>
/// <param name="Create">
/// Builds it against one application and one redirect URI. A factory rather than an instance because
/// these wrap a typed <see cref="HttpClient"/>: holding one for the process lifetime pins its handler
/// and silently stops the factory rotating it, so DNS changes never land.
/// </param>
internal sealed record ProviderRegistration(
    string Provider,
    Func<IHttpClientFactory, KgsmOAuthApplication, string, IIdentityProvider> Create);

/// <summary>
/// The identity providers this anchor can sign somebody in through.
/// </summary>
/// <remarks>
/// <para>
/// A provider is a <b>route value resolved against this catalog</b>, and the registrations below are
/// the only place this daemon names one. Wiring up another is an entry here and nothing anywhere
/// else — no new route, no new setting shape, no branch in an endpoint.
/// </para>
/// <para>
/// <b>The application is the host's, not this daemon's.</b> It is read from the shared
/// <c>KgsmAuth</c> configuration that every KGSM surface on the machine binds, so a person signing in
/// at the anchor and at anything else beside it goes through one application rather than two. Read by
/// explicit key rather than bound, because a reflective binder is what an ahead-of-time compiled
/// daemon cannot do.
/// </para>
/// <para>
/// <b>A provider nobody wired up and a provider nobody has heard of are the same answer.</b> Both are
/// simply not offered, so the set of providers a build knows about cannot be probed by asking.
/// </para>
/// </remarks>
internal sealed class ProviderCatalog(
    IConfiguration configuration,
    IHttpClientFactory httpClientFactory,
    AnchorAddress address)
{
    private static readonly ProviderRegistration[] Registrations =
    [
        new(KgsmActorProvider.Discord, (factory, application, redirectUri) => new DiscordDirectory(
            factory.CreateClient(nameof(DiscordDirectory)),
            application,
            // "identify guilds" matches what every other KGSM surface asks for, so a person is not
            // re-prompted for a different set depending on which door they used. Neither scope
            // contributes to authority — nothing a provider grants does.
            new DiscordOAuthEndpoints(redirectUri, "identify guilds"))),
    ];

    /// <summary>The providers this anchor is wired to, in the order a sign-in page draws them.</summary>
    internal IReadOnlyList<string> Configured =>
        [.. Registrations.Select(r => r.Provider).Where(IsConfigured)];

    /// <summary>
    /// Whether <paramref name="provider"/> can be used here: an application is configured for it, and
    /// this anchor has an address for the provider to send the browser back to.
    /// </summary>
    internal bool IsConfigured(string provider) => Application(provider) is not null && address.Base is not null;

    /// <summary>
    /// Every provider this build knows how to speak, wired up or not.
    /// </summary>
    /// <remarks>
    /// A surface offering somebody a way to attach an account needs both lists: what exists, so it can
    /// say a provider is not set up here, and what is configured, so it does not offer a button that
    /// bounces to nothing.
    /// </remarks>
    internal IReadOnlyList<string> Known => [.. Registrations.Select(r => r.Provider)];

    /// <summary>
    /// The provider pointed at this anchor's <em>link</em> callback, or <see langword="null"/> when
    /// this anchor does not offer it.
    /// </summary>
    /// <remarks>
    /// The same provider as <see cref="Identity"/> with a different redirect, because attaching an
    /// account and signing in with one are different arrivals: one mints a session for whoever comes
    /// back, the other attaches whoever comes back to an account already signed in. Building them from
    /// one method with one address would let a link come back through the sign-in door and mint a
    /// session instead.
    /// </remarks>
    internal IIdentityProvider? Link(string provider)
    {
        if (Find(provider) is not { } registration || Application(registration.Provider) is not { } application
            || address.LinkRedirectUri(registration.Provider) is not { } redirect)
            return null;

        return registration.Create(httpClientFactory, application, redirect);
    }

    /// <summary>
    /// The provider, pointed at this anchor's callback — or <see langword="null"/> when this anchor
    /// does not offer it.
    /// </summary>
    internal IIdentityProvider? Identity(string provider)
    {
        if (Find(provider) is not { } registration || Application(registration.Provider) is not { } application
            || address.RedirectUri(registration.Provider) is not { } redirect)
            return null;

        return registration.Create(httpClientFactory, application, redirect);
    }

    /// <summary>
    /// The host's application for a provider, or <see langword="null"/> when it is not wired up.
    /// </summary>
    private KgsmOAuthApplication? Application(string provider)
    {
        string id = configuration[$"KgsmAuth:Providers:{provider}:ClientId"] ?? "";
        string secret = configuration[$"KgsmAuth:Providers:{provider}:ClientSecret"] ?? "";

        var application = new KgsmOAuthApplication { ClientId = id, ClientSecret = secret };
        return application.Configured ? application : null;
    }

    // Case-insensitive because the name arrives off a route, and a route value is whatever the
    // browser sent. The handle it ends up in carries the provider's own spelling, which the
    // registration states rather than the caller.
    private static ProviderRegistration? Find(string provider) =>
        Registrations.FirstOrDefault(
            r => string.Equals(r.Provider, provider, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Making an account nobody has yet.
/// </summary>
/// <remarks>
/// <para>
/// An unauthenticated write, and the reason it is defensible is that the capability already exists:
/// completing a sign-in at a configured provider provisions exactly the same unapproved account. This
/// adds a door to a room rather than a room. It is off unless a cluster says otherwise, bounded by
/// the same <see cref="PendingPolicy"/> that bounds the provider door, and the account it creates
/// holds <b>nothing</b> until an administrator grants something.
/// </para>
/// <para>
/// A caller names a username, a password and optionally a display name, and nothing else. A tier or a
/// status on the wire is a field somebody will try to set, so neither is on it: both are decided here
/// and the tier is always <see cref="KgsmTier.None"/>.
/// </para>
/// <para>
/// The provider's registration page is the door (<see cref="OidcEndpoints.Register"/>); it answers with
/// the wait, and the browser returns to its client once an administrator approves the account.
/// </para>
/// </remarks>
internal static class Registration
{
    /// <summary>
    /// Make the account <paramref name="body"/> asks for, or refuse with the reason already written.
    /// </summary>
    /// <returns>The account, unapproved and holding nothing, or null.</returns>
    internal static async Task<KgsmUser?> CreateAsync(HttpContext ctx, RegisterRequest body)
    {
        var options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.Registration");

        if (!options.AllowSelfRegistration)
        {
            logger.LogWarning("registration refused: this cluster does not take accounts people create themselves");
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "registration_closed",
                "This cluster does not take accounts people create for themselves. Ask an administrator for one.");
            return null;
        }

        // The accounts are the cluster's, so only the member holding them may add one. A member
        // standing by that wrote here would create an account the holder has never heard of and will
        // overwrite at the next snapshot.
        var role = ctx.RequestServices.GetRequiredService<AnchorRole>();
        if (!role.IsAuthority)
        {
            if (role.Holder is { Length: > 0 } holder)
                ctx.Response.Headers["X-Kgsm-Auth-Holder"] = holder;
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "not_the_anchor",
                "This member does not hold the cluster's accounts.");
            return null;
        }

        if (!Usernames.IsValid(body.Username))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "bad_request",
                $"A username is {Usernames.MinLength}–{Usernames.MaxLength} characters of letters, digits, "
                + "'.', '_' or '-', beginning with a letter or a digit.");
            return null;
        }

        if (!Passwords.IsAcceptable(body.Password))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "bad_request",
                $"A password is at least {Passwords.MinLength} characters.");
            return null;
        }

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();
        var linking = ctx.RequestServices.GetRequiredService<IdentityLinkService>();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string username = body.Username!.Trim();

        // The cap, and the expiry that stops the cap becoming a permanent lockout. Read through the
        // same service the provider door uses, so one policy bounds both doors rather than two counts
        // that can disagree about how full the queue is.
        int pending;
        try
        {
            await linking.ExpirePendingAsync(options.Pending, now, ctx.RequestAborted);
            pending = await linking.CountPendingAsync(ctx.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "registration failed: the account store could not be read");
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
                "The account store could not be read.");
            return null;
        }

        if (pending >= options.Pending.Cap)
        {
            logger.LogWarning(
                "'{Username}' tried to register and this cluster already holds {Cap} accounts awaiting approval",
                username, options.Pending.Cap);
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "not_accepting_accounts",
                "This cluster is not accepting new accounts right now. Ask an administrator.");
            return null;
        }

        var account = new KgsmUser(
            UserIds.NewUserId(),
            username,
            string.IsNullOrWhiteSpace(body.DisplayName) ? username : body.DisplayName.Trim(),
            KgsmTier.None,
            // Nobody chose this tier — it is where an unapproved account starts. Granted is what an
            // admin's deliberate pick records, and the difference is what expiry reads.
            TierSource.Derived,
            UserStatus.Pending,
            now,
            now);

        try
        {
            await store.CreateAsync(account, ctx.RequestAborted);
        }
        catch (DuplicateUsernameException)
        {
            logger.LogInformation("registration refused: '{Username}' is already taken", username);
            await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "username_taken",
                $"'{username}' is already taken on this cluster.");
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "registration failed: the account could not be written");
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
                "The account store could not be written.");
            return null;
        }

        await ctx.RequestServices.GetRequiredService<LocalSignInService>()
            .SetPasswordAsync(account.UserId, body.Password!, now, ctx.RequestAborted);

        // Every member is told, at a version, the way any other account change is. Without this the
        // account exists on the anchor alone until something else makes a member take a snapshot —
        // so a person could sign in and be a stranger everywhere they went.
        var versions = ctx.RequestServices.GetRequiredService<IAccountVersions>();
        long version = await versions.NextAsync(account.UserId, now, AccountAnnouncementKind.Changed, ctx.RequestAborted);
        await ctx.RequestServices.GetRequiredService<AccountBroadcast>()
            .DrainAsync(ctx.RequestAborted);

        logger.LogInformation("'{Username}' registered and is awaiting approval", username);

        // The account exists and every member has been told. Recording it here is what puts the
        // person in front of an administrator: the row is what a Control Panel renders and what a
        // push notification asking for approval is raised from, so an account created and unrecorded
        // is one nobody is asked about.
        //
        // No "from" side: the account did not exist a moment ago, and a from/to pair here would
        // invent a previous state to have moved out of.
        await ctx.RequestServices.GetRequiredService<AnchorJournal>().AccountAsync(
            AuthEvents.UserProvisioned,
            account.UserId,
            account.Username,
            toTier: KgsmTiers.ToWire(account.Tier),
            toStatus: UserStatuses.ToWire(account.Status),
            actor: account.AsIdentity().ActorString,
            origin: AnchorJournal.OriginUi,
            ct: ctx.RequestAborted);

        return account;
    }
}

/// <summary>
/// Signing in with an account somebody already has somewhere else: the round trip to a provider and
/// its way back.
/// </summary>
/// <remarks>
/// <para>
/// The provider establishes <b>who</b>, and contributes nothing else. What the person may do is on
/// their KGSM account and on nothing else — no group, no guild, no role is consulted, which is what
/// lets a provider be added with no authority story of its own.
/// </para>
/// <para>
/// A round trip begins on this anchor's own pages — the sign-in page for a request in flight
/// (<see cref="OidcEndpoints.ProviderStart"/>) and the account page to prove the person again — and
/// ends here. It never mints a session itself: the request it completes is answered with a code for
/// its client.
/// </para>
/// </remarks>
internal static class ProviderEndpoints
{
    /// <summary>
    /// The one-time cookie carrying <c>state</c> and the PKCE verifier.
    /// </summary>
    /// <remarks>
    /// <c>state</c> stops login CSRF and only works because the cookie binds it to the browser that
    /// started the login; a server-side set of issued states would admit an attacker's own. PKCE
    /// stops code interception. Neither is optional and the verifier never travels in a URL.
    /// </remarks>
    private const string StateCookie = "kgsm_oauth_state";

    /// <summary>Bind a round trip to this browser: <c>state</c> and the PKCE verifier, in the one-time cookie.</summary>
    internal static void BeginHandshake(HttpContext ctx, OAuthHandshake handshake) =>
        ctx.Response.Cookies.Append(StateCookie, handshake.ToCookieValue(), CookieOptions(ctx));

    /// <summary>
    /// Take the provider's answer: prove the person again for the account page, or complete the
    /// authorization request the round trip was started for.
    /// </summary>
    /// <remarks>
    /// One callback for both, because it is the one address registered with the provider's application.
    /// Which it is comes from the <c>state</c> that returns: a re-proof recorded its own, and a round
    /// trip started from the sign-in page recorded its <c>state</c> on the request in flight. A state
    /// that matches neither — a request that expired while the person was at the provider — completes
    /// nothing and says so on this anchor's own page.
    /// </remarks>
    internal static async Task Callback(HttpContext ctx)
    {
        string provider = (string?)ctx.Request.RouteValues["provider"] ?? "";
        var options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.ProviderEndpoints");

        var role = ctx.RequestServices.GetRequiredService<AnchorRole>();
        if (!role.IsAuthority)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "not_the_anchor",
                "This member does not hold the cluster's accounts.");
            return;
        }

        if (ctx.RequestServices.GetRequiredService<ProviderCatalog>().Identity(provider) is not { } directory)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "auth_unconfigured",
                $"Signing in with {provider} is not configured on this anchor.");
            return;
        }

        // The CSRF gate, before any exchange. The cookie is one-time and is cleared whatever the
        // outcome, so a state cannot be replayed. A missing cookie, a malformed one, or one that does
        // not match what came back is a forged or stale login — never a grant.
        string? cookie = ctx.Request.Cookies[StateCookie];
        if (cookie is not null)
            ctx.Response.Cookies.Delete(StateCookie, CookieOptions(ctx));

        string? state = ctx.Request.Query["state"];
        if (!OAuthHandshake.TryParse(cookie, out OAuthHandshake handshake) || !handshake.MatchesState(state))
        {
            await Fail(ctx, options, StatusCodes.Status400BadRequest, "invalid_state",
                "That sign-in could not be verified. Start again.");
            return;
        }

        // A round trip begun on the account page to prove the person again. It proves an account that
        // already holds this identity, or nothing — it never signs anybody in and never makes an account.
        if (ctx.RequestServices.GetRequiredService<ReauthRoundTrips>().Take(state) is { } reauth)
        {
            string? reauthCode = ctx.Request.Query["code"];
            KgsmIdentity? proved = null;
            if (!string.IsNullOrWhiteSpace(reauthCode))
            {
                try
                {
                    proved = await directory.VerifyAsync(reauthCode, handshake.CodeVerifier, ctx.RequestAborted);
                }
                catch (KgsmAuthProviderException ex)
                {
                    logger.LogWarning(ex, "{Provider} re-authentication exchange failed", provider);
                    ctx.Response.Redirect("/account#reauth_error=auth_provider_error");
                    return;
                }
            }

            ctx.Response.Redirect(proved is null
                ? "/account#reauth_error=login_required"
                : await AccountPageEndpoints.CompleteReauthAsync(ctx, reauth, proved));
            return;
        }

        AuthorizeRequest? inFlight = await OidcEndpoints.InFlightAsync(ctx);
        if (inFlight is null || !string.Equals(inFlight.UpstreamState, state, StringComparison.Ordinal))
        {
            await Fail(ctx, options, StatusCodes.Status400BadRequest, "no_request",
                "That sign-in is no longer waiting here. Go back to where you started and sign in again.");
            return;
        }

        string? code = ctx.Request.Query["code"];
        if (string.IsNullOrWhiteSpace(code))
        {
            await Fail(ctx, options, inFlight, StatusCodes.Status400BadRequest, "bad_request",
                "The provider returned no authorization code.");
            return;
        }

        KgsmIdentity? verified;
        try
        {
            verified = await directory.VerifyAsync(code, handshake.CodeVerifier, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException ex)
        {
            // Could not reach or parse the provider. An honest upstream failure, never a grant, and
            // never reported as the person's credentials being wrong.
            logger.LogWarning(ex, "{Provider} sign-in exchange failed", provider);
            await Fail(ctx, options, inFlight, StatusCodes.Status502BadGateway, "auth_provider_error",
                "Could not finish signing in with that provider.");
            return;
        }

        if (verified is null)
        {
            await Fail(ctx, options, inFlight, StatusCodes.Status401Unauthorized, "login_required",
                "That sign-in expired or was already used. Start again.");
            return;
        }

        // A verified identity is not yet an account. It matches one here, or an unapproved one is
        // created for it — holding no tier, so the session it gets says who they are and reaches
        // nothing. It is never matched on a username or an email: providers disagree about what
        // "verified" means, and matching on one is the documented route to handing somebody another
        // person's account.
        var linking = ctx.RequestServices.GetRequiredService<IdentityLinkService>();
        LinkResult link;
        try
        {
            link = await linking.ResolveOrProvisionAsync(
                verified, DateTimeOffset.UtcNow, options.Pending, ctx.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "could not resolve {Handle} against the account store", verified.Handle);
            await Fail(ctx, options, inFlight, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
                "The account store could not be read.");
            return;
        }

        if (link.Outcome == LinkOutcome.PendingCapReached)
        {
            // Not a refusal of this person: a refusal to hold more unapproved accounts. Logged,
            // because from the outside it is indistinguishable from being turned away.
            logger.LogWarning(
                "{Handle} signed in and this cluster already holds {Cap} accounts awaiting approval",
                verified.Handle, options.Pending.Cap);
            await Fail(ctx, options, inFlight, StatusCodes.Status503ServiceUnavailable, "not_accepting_accounts",
                "This cluster is not accepting new accounts right now. Ask an administrator.");
            return;
        }

        KgsmUser account = link.User!;
        if (account.Status == UserStatus.Disabled)
        {
            await Fail(ctx, options, inFlight, StatusCodes.Status403Forbidden, "account_disabled",
                "This account has been switched off.");
            return;
        }

        KgsmTier tier = account.EffectiveTier;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var journal = ctx.RequestServices.GetRequiredService<AnchorJournal>();

        // An account that did not exist until this login, and the identity that now proves it. Two
        // facts rather than one: the account is a person to approve, and the link is what lets
        // whoever controls that provider account sign in as this one. Recorded before the session, so
        // the order on the record is the order they happened.
        if (link.Outcome == LinkOutcome.Provisioned)
        {
            await journal.AccountAsync(
                AuthEvents.UserProvisioned,
                account.UserId,
                account.Username,
                toTier: KgsmTiers.ToWire(account.Tier),
                toStatus: UserStatuses.ToWire(account.Status),
                actor: verified.ActorString,
                origin: AnchorJournal.OriginUi,
                ct: ctx.RequestAborted);

            await journal.IdentityAsync(
                AuthEvents.IdentityLinked,
                account.UserId,
                account.Username,
                provider,
                verified.Handle,
                actor: verified.ActorString,
                origin: AnchorJournal.OriginUi,
                ct: ctx.RequestAborted);
        }

        logger.LogInformation(
            "{Handle} signed in with {Provider} at {Tier}", verified.Handle, provider, KgsmTiers.ToWire(tier));

        // The sign-in proves this browser's provider session, and the request it was started for is
        // answered from there — a code for the client, never a session.
        ProviderSessionRow session = await ctx.RequestServices.GetRequiredService<ProviderSessions>()
            .EstablishAsync(ctx, verified, account);
        await OidcEndpoints.ProceedAsync(ctx, inFlight, session, OidcEndpoints.Answer.Navigation, silent: false);
    }

    /// <summary>
    /// Report a failed round trip on this anchor's own page, before there is a request to report it on.
    /// </summary>
    private static Task Fail(
        HttpContext ctx, AnchorOptions options, int status, string code, string message) =>
        Fail(ctx, options, inFlight: null, status, code, message);

    /// <summary>
    /// Report a failed sign-in: on the sign-in page of the request it was started for, or as a page of
    /// its own when there is none.
    /// </summary>
    private static Task Fail(
        HttpContext ctx, AnchorOptions options, AuthorizeRequest? inFlight, int status, string code, string message)
    {
        // Said out loud, because a browser is the only other witness to a failed sign-in and it cannot
        // be asked afterwards.
        ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.ProviderEndpoints")
            .LogWarning("provider sign-in refused: {Code} — {Message}", code, message);

        return inFlight is not null
            ? OidcEndpoints.SignInPageAsync(ctx, inFlight, message, status)
            : ProviderPages.ProblemAsync(ctx, status, "Sign-in didn't complete", message);
    }

    /// <summary>
    /// How the handshake cookie is written.
    /// </summary>
    /// <remarks>
    /// <c>SameSite=Lax</c> rather than <c>Strict</c>, and that is load-bearing: Strict suppresses the
    /// cookie on the top-level redirect back from the provider, which breaks every sign-in. Secure
    /// follows the scheme the request arrived on, so it is set wherever TLS is terminated in front and
    /// absent on a plain loopback where it would stop the cookie being stored at all.
    /// </remarks>
    private static CookieOptions CookieOptions(HttpContext ctx) => new()
    {
        HttpOnly = true,
        Secure = ctx.Request.IsHttps
                 || string.Equals(ctx.Request.Headers["X-Forwarded-Proto"], "https", StringComparison.Ordinal),
        SameSite = SameSiteMode.Lax,
        Path = "/auth",
        MaxAge = TimeSpan.FromMinutes(10),
    };
}
