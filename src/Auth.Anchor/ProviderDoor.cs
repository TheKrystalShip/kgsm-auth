using Microsoft.Extensions.Configuration;

using TheKrystalShip.KGSM.Auth.Discord;
using TheKrystalShip.KGSM.Auth.Sessions;
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
    AnchorOptions options)
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

    /// <summary>Whether an application is configured for <paramref name="provider"/>.</summary>
    internal bool IsConfigured(string provider) => Application(provider) is not null;

    /// <summary>
    /// The provider, pointed at this anchor's callback — or <see langword="null"/> when this anchor
    /// does not offer it.
    /// </summary>
    internal IIdentityProvider? Identity(string provider)
    {
        if (Find(provider) is not { } registration || Application(registration.Provider) is not { } application)
            return null;

        return registration.Create(
            httpClientFactory, application, options.RedirectUri(registration.Provider));
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
/// </remarks>
internal static class RegisterEndpoint
{
    internal static async Task Register(HttpContext ctx)
    {
        var options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.RegisterEndpoint");

        if (!options.AllowSelfRegistration)
        {
            logger.LogWarning("registration refused: this cluster does not take accounts people create themselves");
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "registration_closed",
                "This cluster does not take accounts people create for themselves. Ask an administrator for one.");
            return;
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
            return;
        }

        RegisterRequest? body = await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.RegisterRequest);
        if (body is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request",
                "The request body is not readable.");
            return;
        }

        if (!Usernames.IsValid(body.Username))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "bad_request",
                $"A username is {Usernames.MinLength}–{Usernames.MaxLength} characters of letters, digits, "
                + "'.', '_' or '-', beginning with a letter or a digit.");
            return;
        }

        if (!Passwords.IsAcceptable(body.Password))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "bad_request",
                $"A password is at least {Passwords.MinLength} characters.");
            return;
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
            return;
        }

        if (pending >= options.Pending.Cap)
        {
            logger.LogWarning(
                "'{Username}' tried to register and this cluster already holds {Cap} accounts awaiting approval",
                username, options.Pending.Cap);
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "not_accepting_accounts",
                "This cluster is not accepting new accounts right now. Ask an administrator.");
            return;
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
            return;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "registration failed: the account could not be written");
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
                "The account store could not be written.");
            return;
        }

        await ctx.RequestServices.GetRequiredService<LocalSignInService>()
            .SetPasswordAsync(account.UserId, body.Password!, now, ctx.RequestAborted);

        // Every member is told, at a version, the way any other account change is. Without this the
        // account exists on the anchor alone until something else makes a member take a snapshot —
        // so a person could sign in and be a stranger everywhere they went.
        var versions = ctx.RequestServices.GetRequiredService<IAccountVersions>();
        long version = await versions.NextAsync(account.UserId, now, ctx.RequestAborted);
        await ctx.RequestServices.GetRequiredService<AccountBroadcast>()
            .PublishAsync(account, version, ctx.RequestAborted);

        logger.LogInformation("'{Username}' registered and is awaiting approval", username);

        // A real session at `none`, deliberately. A bare refusal tells somebody who has just made an
        // account nothing about what happens next; a session lets a surface say they are waiting on
        // an administrator, and lets that administrator see them.
        await Endpoints.MintSessionFor(ctx, account.AsIdentity(), account.EffectiveTier, account, now,
            StatusCodes.Status201Created);
    }
}

/// <summary>
/// Signing in with an account somebody already has somewhere else.
/// </summary>
/// <remarks>
/// <para>
/// The provider establishes <b>who</b>, and contributes nothing else. What the person may do is on
/// their KGSM account and on nothing else — no group, no guild, no role is consulted, which is what
/// lets a provider be added with no authority story of its own.
/// </para>
/// <para>
/// What this door mints is what the password door mints: a session audienced to the <b>cluster</b>,
/// signed with this anchor's private key, that every member verifies offline and none can produce.
/// The two doors differ in what proves a person and in nothing after that.
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

    /// <summary>What a person's browser is offered to sign in with.</summary>
    internal static async Task Providers(HttpContext ctx)
    {
        var catalog = ctx.RequestServices.GetRequiredService<ProviderCatalog>();
        var options = ctx.RequestServices.GetRequiredService<AnchorOptions>();

        // Unauthenticated on purpose: a sign-in page has to draw its buttons before anybody has
        // signed in, and what it learns is which doors exist rather than anything behind them.
        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new ProvidersResult(catalog.Configured, options.RedirectsToPanel, options.AllowSelfRegistration),
            AnchorJsonContext.Default.ProvidersResult);
    }

    /// <summary>Send the browser to the provider.</summary>
    internal static Task Start(HttpContext ctx)
    {
        string provider = (string?)ctx.Request.RouteValues["provider"] ?? "";

        var role = ctx.RequestServices.GetRequiredService<AnchorRole>();
        if (!role.IsAuthority)
        {
            // A member standing by mints nothing, and starting a bounce it could not finish would
            // send somebody to a provider and back to a refusal.
            return Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "not_the_anchor",
                "This member does not hold the cluster's accounts.");
        }

        if (ctx.RequestServices.GetRequiredService<ProviderCatalog>().Identity(provider) is not { } identity)
        {
            return Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "auth_unconfigured",
                $"Signing in with {provider} is not configured on this anchor.");
        }

        OAuthHandshake handshake = OAuthHandshake.Create();
        ctx.Response.Cookies.Append(StateCookie, handshake.ToCookieValue(), CookieOptions(ctx));

        // Honoured from the query, because a caller asking for a screen and silently not getting one
        // is a door that lies about what it did. The default matches the one every other KGSM sign-in
        // uses, so a person meets the same provider screen wherever they arrive.
        string prompt = ctx.Request.Query["prompt"].ToString();
        if (string.IsNullOrWhiteSpace(prompt))
            prompt = "none";

        // Only the challenge travels — the verifier stays in the cookie, never in a URL.
        ctx.Response.Redirect(identity.BuildAuthorizeUrl(handshake.State, handshake.CodeChallenge, prompt));
        return Task.CompletedTask;
    }

    /// <summary>Take the provider's answer, and mint a session for the whole cluster.</summary>
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

        string? code = ctx.Request.Query["code"];
        if (string.IsNullOrWhiteSpace(code))
        {
            await Fail(ctx, options, StatusCodes.Status400BadRequest, "bad_request",
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
            await Fail(ctx, options, StatusCodes.Status502BadGateway, "auth_provider_error",
                "Could not finish signing in with that provider.");
            return;
        }

        if (verified is null)
        {
            await Fail(ctx, options, StatusCodes.Status401Unauthorized, "login_required",
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
            await Fail(ctx, options, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
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
            await Fail(ctx, options, StatusCodes.Status503ServiceUnavailable, "not_accepting_accounts",
                "This cluster is not accepting new accounts right now. Ask an administrator.");
            return;
        }

        KgsmUser account = link.User!;
        if (account.Status == UserStatus.Disabled)
        {
            await Fail(ctx, options, StatusCodes.Status403Forbidden, "account_disabled",
                "This account has been switched off.");
            return;
        }

        var tokens = ctx.RequestServices.GetRequiredService<ISessionTokenService>();
        var registry = ctx.RequestServices.GetRequiredService<ISessionRegistry>();

        KgsmTier tier = account.EffectiveTier;
        string sessionId = "sid_" + Guid.NewGuid().ToString("N");
        MintedToken access = tokens.MintAccess(verified, tier, sessionId);
        MintedToken refresh = tokens.MintRefresh(verified, tier, sessionId);

        await registry.CreateAsync(
            new SessionRegistration(
                sessionId, verified.Handle, options.ClusterId,
                DateTimeOffset.UtcNow, refresh.ExpiresAt,
                ctx.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua : null,
                refresh.Jti),
            ctx.RequestAborted);

        logger.LogInformation(
            "{Handle} signed in with {Provider} at {Tier}", verified.Handle, provider, KgsmTiers.ToWire(tier));

        if (options.RedirectsToPanel)
        {
            // The tokens ride the URL FRAGMENT, never the query: a fragment is not sent to the server,
            // so it stays out of access logs and out of the Referer header. The panel reads them,
            // adopts the session and strips the fragment.
            ctx.Response.Redirect(
                $"{options.FrontendUrl}#access={Uri.EscapeDataString(access.Token)}"
                + $"&refresh={Uri.EscapeDataString(refresh.Token)}");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new SignInResult(
            Token: access.Token,
            Refresh: refresh.Token,
            Tier: KgsmTiers.ToWire(tier),
            UserId: account.UserId,
            Status: UserStatuses.ToWire(account.Status),
            Cluster: options.ClusterId,
            AccessTokenExpiresAt: access.ExpiresAt,
            RefreshExpiresAt: refresh.ExpiresAt),
            AnchorJsonContext.Default.SignInResult);
    }

    /// <summary>
    /// Report a failed sign-in the way the caller can act on.
    /// </summary>
    /// <remarks>
    /// A browser that was sent here by a redirect is sent back to the panel with the reason in the
    /// fragment, because leaving somebody on a JSON error page at an address they did not type is not
    /// an answer they can do anything with. Everything else gets the frozen error envelope.
    /// </remarks>
    private static Task Fail(
        HttpContext ctx, AnchorOptions options, int status, string code, string message)
    {
        // Said out loud, because the alternative is a person staring at a panel that says something
        // went wrong while this daemon knows exactly what and tells nobody. A browser is the only
        // other witness to a failed sign-in and it cannot be asked afterwards.
        ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.ProviderEndpoints")
            .LogWarning("provider sign-in refused: {Code} — {Message}", code, message);

        if (!options.RedirectsToPanel)
            return Endpoints.Refuse(ctx, status, code, message);

        ctx.Response.Redirect($"{options.FrontendUrl}#error={Uri.EscapeDataString(code)}");
        return Task.CompletedTask;
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
