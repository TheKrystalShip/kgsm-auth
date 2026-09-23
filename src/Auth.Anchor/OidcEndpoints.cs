using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The anchor as an OpenID Connect provider: every browser surface in the cluster sends a person here and
/// gets back a code it exchanges for a session.
/// </summary>
/// <remarks>
/// <para>
/// <b>Authorization code with PKCE (S256), public clients.</b> No client secret exists to leak from a
/// browser. A code is single use, lives sixty seconds, and is bound to its client and its exact redirect.
/// </para>
/// <para>
/// <b>The request in flight is held here</b>, keyed by the hash of a secret the browser carries in
/// <c>kgsm_authz</c>. The page, its form and its provider links carry no request field, so nothing about
/// where a code goes can be edited on the way through.
/// </para>
/// <para>
/// <b>A credential answer is a code, never a session.</b> Nothing the provider's own pages hold can call
/// a member; the session is minted at <c>/token</c>, for the client, under the provider session the
/// browser proved.
/// </para>
/// <para>
/// Every handler is a plain <see cref="RequestDelegate"/>, for the reason the rest of this daemon's are:
/// binding a delegate's parameters is reflection, which a Native AOT build cannot do.
/// </para>
/// </remarks>
internal static class OidcEndpoints
{
    /// <summary>How long a code may wait to be exchanged.</summary>
    internal static readonly TimeSpan CodeLifetime = TimeSpan.FromSeconds(60);

    /// <summary>The largest form <c>/token</c> reads. A code exchange is a few hundred bytes.</summary>
    private const int MaxFormBytes = 8 * 1024;

    // ── Discovery ─────────────────────────────────────────────────────────────

    /// <summary><c>GET /.well-known/openid-configuration</c>.</summary>
    internal static Task Discovery(HttpContext ctx)
    {
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        if (options.IssuerUrl is null)
            return NoIssuerAsync(ctx);

        string issuer = options.Issuer;
        return Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new OidcDiscovery(
            Issuer: issuer,
            AuthorizationEndpoint: issuer + "/authorize",
            TokenEndpoint: issuer + "/token",
            UserinfoEndpoint: issuer + "/userinfo",
            JwksUri: issuer + "/.well-known/jwks.json",
            EndSessionEndpoint: issuer + "/sign-out",
            ResponseTypesSupported: ["code"],
            ResponseModesSupported: ["query"],
            GrantTypesSupported: ["authorization_code", "refresh_token"],
            SubjectTypesSupported: ["public"],
            IdTokenSigningAlgValuesSupported: ["ES256"],
            ScopesSupported: ["openid"],
            ClaimsSupported: ["sub", "sid", "auth_time", "nonce", "preferred_username", "name", "picture"],
            CodeChallengeMethodsSupported: ["S256"],
            TokenEndpointAuthMethodsSupported: ["none"],
            PromptValuesSupported: ["none", "login"],
            AuthorizationResponseIssParameterSupported: true),
            AnchorJsonContext.Default.OidcDiscovery);
    }

    /// <summary><c>GET /.well-known/jwks.json</c>: the key every session and <c>id_token</c> is signed with.</summary>
    internal static Task Jwks(HttpContext ctx) =>
        Results.Text(ctx.RequestServices.GetRequiredService<EcdsaSessionSigner>().PublicKeysJson, "application/json")
            .ExecuteAsync(ctx);

    // ── Authorize ─────────────────────────────────────────────────────────────

    /// <summary>
    /// <c>GET /authorize</c>: validate the request, hold it, then answer a recognised browser at once,
    /// or show the sign-in page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Until the client and its redirect are known to be registered, a refusal is rendered here, on the
    /// provider's own origin. Redirecting to an unregistered address with an error would be the open
    /// redirect this endpoint exists to refuse. After that, a refusal goes back to the client.
    /// </para>
    /// <para>
    /// <c>prompt=login</c> forces the credential. <c>prompt=none</c> never renders a page: wherever one
    /// would be shown it returns <c>login_required</c>. Absent, a live provider session whose account still
    /// stands is honoured.
    /// </para>
    /// </remarks>
    internal static async Task Authorize(HttpContext ctx)
    {
        if (!await RequireProviderPageAsync(ctx))
            return;

        IQueryCollection q = ctx.Request.Query;
        var clients = ctx.RequestServices.GetRequiredService<ClientRegistry>();

        if (clients.Find(Single(q, "client_id")) is not { } client)
        {
            await ProviderPages.ProblemAsync(ctx, StatusCodes.Status400BadRequest, "Unknown application",
                "The application that sent you here is not registered with this cluster.");
            return;
        }

        string? redirectUri = Single(q, "redirect_uri");
        if (!ClientRegistry.Redirects(client, redirectUri))
        {
            await ProviderPages.ProblemAsync(ctx, StatusCodes.Status400BadRequest, "Unknown return address",
                $"{client.Name} asked to be answered at an address it is not registered with.");
            return;
        }

        string? state = Single(q, "state");

        if (Single(q, "response_type") != "code")
        {
            RedirectError(ctx, redirectUri!, state, "unsupported_response_type", "Only the authorization code flow is served.");
            return;
        }

        if (!Tokens(Single(q, "scope")).Contains("openid"))
        {
            RedirectError(ctx, redirectUri!, state, "invalid_scope", "The openid scope is required.");
            return;
        }

        string? challenge = Single(q, "code_challenge");
        if (Single(q, "code_challenge_method") != "S256" || challenge is not { Length: >= 43 and <= 128 })
        {
            RedirectError(ctx, redirectUri!, state, "invalid_request", "PKCE with S256 is required.");
            return;
        }

        HashSet<string> prompt = Tokens(Single(q, "prompt"));
        bool silentOnly = prompt.Contains("none");
        bool forceCredential = prompt.Contains("login");
        if (silentOnly && prompt.Count > 1)
        {
            RedirectError(ctx, redirectUri!, state, "invalid_request", "prompt=none cannot be combined.");
            return;
        }

        AuthorizeRequest request = await BeginRequestAsync(ctx, client.ClientId, redirectUri!, state, challenge,
            Single(q, "nonce"), silentOnly ? "none" : forceCredential ? "login" : null);

        if (!forceCredential
            && await ctx.RequestServices.GetRequiredService<ProviderSessions>().CurrentAsync(ctx) is { } session)
        {
            await ProceedAsync(ctx, request, session, Answer.Navigation, silent: silentOnly);
            return;
        }

        if (silentOnly)
        {
            await RedirectErrorAsync(ctx, request, "login_required", "Nobody is signed in on this browser.");
            return;
        }

        await SignInPageAsync(ctx, request, message: null);
    }

    /// <summary>
    /// <c>POST /authorize/credentials</c>: a username and a password against the request in flight.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Login CSRF is refused before a credential is read.</b> The post needs this browser's request
    /// cookie and a same-origin <c>Sec-Fetch-Site</c>, or an <c>Origin</c> equal to the provider's where no
    /// fetch metadata is sent. Without it an attacker's page posts the attacker's own credentials, and
    /// every later bounce signs the victim in as the attacker.
    /// </para>
    /// <para>
    /// One endpoint for the plain form and for the pages' own fetch, so the cookie is set and the code
    /// minted in one place. A form gets a redirect; the fetch gets the same destination as JSON, so it can
    /// render a refusal inline.
    /// </para>
    /// </remarks>
    internal static async Task Credentials(HttpContext ctx)
    {
        bool json = ctx.Request.HasJsonContentType();
        if (!await RequireProviderPageAsync(ctx, json))
            return;

        if (!IsSameOrigin(ctx))
        {
            await RefuseAsync(ctx, json, StatusCodes.Status403Forbidden, "cross_site",
                "Sign-in refused", "A sign-in can only be sent from this page.");
            return;
        }

        if (await InFlightAsync(ctx) is not { } request)
        {
            await ExpiredAsync(ctx, json);
            return;
        }

        string? username;
        string? password;
        if (json)
        {
            SignInRequest? body = await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.SignInRequest);
            (username, password) = (body?.Username, body?.Password);
        }
        else if (ctx.Request.HasFormContentType && ctx.Request.ContentLength is null or <= MaxFormBytes)
        {
            IFormCollection form = await ctx.Request.ReadFormAsync(ctx.RequestAborted);
            (username, password) = (form["username"].ToString(), form["password"].ToString());
        }
        else
        {
            (username, password) = (null, null);
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (await Endpoints.CheckPasswordAsync(ctx, username, password, now) is not { } result)
        {
            await RefuseInFlightAsync(ctx, request, json, StatusCodes.Status503ServiceUnavailable,
                "authority_unavailable", "The account store could not be read. Try again shortly.");
            return;
        }

        switch (result.Outcome)
        {
            case LocalSignInOutcome.Success when result.Principal is { } principal && result.User is { } user:
                ProviderSessionRow session = await ctx.RequestServices.GetRequiredService<ProviderSessions>()
                    .EstablishAsync(ctx, principal.Identity, user);
                await ProceedAsync(ctx, request, session, json ? Answer.Json : Answer.Navigation, silent: false);
                return;

            case LocalSignInOutcome.LockedOut:
                if (result.RetryAfter is { } until)
                    ctx.Response.Headers.RetryAfter = Endpoints.RetryAfterSeconds(until, now).ToString();
                await RefuseInFlightAsync(ctx, request, json, StatusCodes.Status429TooManyRequests,
                    "account_locked", "Too many failed attempts. Try again shortly.");
                return;

            case LocalSignInOutcome.Disabled:
                await RefuseInFlightAsync(ctx, request, json, StatusCodes.Status403Forbidden,
                    "account_disabled", "This account has been switched off.");
                return;

            default:
                await RefuseInFlightAsync(ctx, request, json, StatusCodes.Status401Unauthorized,
                    "invalid_credentials", "That username and password do not match an account.");
                return;
        }
    }

    /// <summary>
    /// <c>GET /authorize/wait</c>: an account an administrator has not approved yet, polled until they do.
    /// </summary>
    /// <remarks>
    /// The request in flight is kept alive while the page polls, because a wait for approval is minutes
    /// or hours and the client is still owed its answer when it ends.
    /// </remarks>
    internal static async Task Wait(HttpContext ctx)
    {
        bool json = AcceptsJson(ctx);
        if (!await RequireProviderPageAsync(ctx, json))
            return;

        if (await InFlightAsync(ctx) is not { } request)
        {
            await ExpiredAsync(ctx, json);
            return;
        }

        if (await ctx.RequestServices.GetRequiredService<ProviderSessions>().CurrentAsync(ctx) is not { } session)
        {
            if (json)
                await Endpoints.Refuse(ctx, StatusCodes.Status401Unauthorized, "unauthenticated", "Sign in to continue.");
            else
                await SignInPageAsync(ctx, request, message: null);
            return;
        }

        await ProceedAsync(ctx, request, session, json ? Answer.WaitJson : Answer.WaitPage, silent: false);
    }

    /// <summary>
    /// <c>GET /authorize/context</c>: what the provider's own pages need to draw the request in flight.
    /// </summary>
    /// <remarks>
    /// The documents are static, so everything particular to this request — whose sign-in it is, which
    /// providers and whether registration is open, and who this browser is already signed in as — is
    /// read here, same-origin, by the application that replaces the floor. Nothing about where the code
    /// goes is in it.
    /// </remarks>
    internal static async Task Context(HttpContext ctx)
    {
        if (!await RequireProviderPageAsync(ctx, json: true))
            return;

        if (await InFlightAsync(ctx) is not { } request)
        {
            await ExpiredAsync(ctx, json: true);
            return;
        }

        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();

        AuthorizeContextAccount? account = null;
        if (await ctx.RequestServices.GetRequiredService<ProviderSessions>().CurrentAsync(ctx) is { } session
            && await ctx.RequestServices.GetRequiredService<IUserStore>()
                .FindByCredentialAsync(session.Handle, ctx.RequestAborted) is { } user)
        {
            account = new AuthorizeContextAccount(user.Username, user.DisplayName, UserStatuses.ToWire(user.Status));
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new AuthorizeContext(
            new AuthorizeContextClient(request.ClientId, ClientName(ctx, request)),
            ctx.RequestServices.GetRequiredService<ProviderCatalog>().Configured,
            options.AllowSelfRegistration,
            account),
            AnchorJsonContext.Default.AuthorizeContext);
    }

    /// <summary>
    /// <c>POST /authorize/register</c>: make an account against the request in flight.
    /// </summary>
    /// <remarks>
    /// The same rules as every registration — closed unless the cluster opens it, capped, the account
    /// unapproved and holding nothing — and the same-origin gate every credential post here passes. The
    /// new account's password proves this browser's provider session, so the wait that follows is theirs,
    /// and it returns them to the client that asked once an administrator approves.
    /// </remarks>
    internal static async Task Register(HttpContext ctx)
    {
        if (!await RequireProviderPageAsync(ctx, json: true))
            return;

        if (!IsSameOrigin(ctx))
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status403Forbidden, "cross_site",
                "A registration can only be sent from this page.");
            return;
        }

        if (await InFlightAsync(ctx) is not { } request)
        {
            await ExpiredAsync(ctx, json: true);
            return;
        }

        if (await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.RegisterRequest) is not { } body)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request",
                "The request body is not readable.");
            return;
        }

        if (await RegisterEndpoint.CreateAsync(ctx, body) is not { } account)
            return;

        ProviderSessionRow session = await ctx.RequestServices.GetRequiredService<ProviderSessions>()
            .EstablishAsync(ctx, account.AsIdentity(), account);
        await ProceedAsync(ctx, request, session, Answer.Json, silent: false);
    }

    private static bool AcceptsJson(HttpContext ctx) =>
        ctx.Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// <c>GET /authorize/{provider}</c>: sign in with an external provider, for the request in flight.
    /// </summary>
    /// <remarks>
    /// The round trip returns through the provider door's own callback, the one address registered with the
    /// provider's application. What makes that callback complete this request rather than answer as the
    /// provider door does is the <c>state</c> recorded on the request here, matched when it comes back.
    /// </remarks>
    internal static async Task ProviderStart(HttpContext ctx)
    {
        if (!await RequireProviderPageAsync(ctx))
            return;

        if (await InFlightAsync(ctx) is not { } request)
        {
            await ExpiredAsync(ctx, json: false);
            return;
        }

        string provider = (string?)ctx.Request.RouteValues["provider"] ?? "";
        if (ctx.RequestServices.GetRequiredService<ProviderCatalog>().Identity(provider) is not { } identity)
        {
            await SignInPageAsync(ctx, request, $"Signing in with {provider} is not set up here.",
                StatusCodes.Status503ServiceUnavailable);
            return;
        }

        OAuthHandshake handshake = OAuthHandshake.Create();
        await ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>()
            .SetUpstreamStateAsync(request.SecretHash, handshake.State, ctx.RequestAborted);
        ProviderEndpoints.BeginHandshake(ctx, handshake);

        ctx.Response.Redirect(identity.BuildAuthorizeUrl(handshake.State, handshake.CodeChallenge, "none"));
    }

    /// <summary>How the end of an authorization is delivered.</summary>
    internal enum Answer
    {
        /// <summary>The browser navigated here: redirect it.</summary>
        Navigation,

        /// <summary>The provider's pages fetched this: answer with where to go, as JSON.</summary>
        Json,

        /// <summary>The wait page is polling: render it again while the account still waits.</summary>
        WaitPage,

        /// <summary>The wait page's application is polling: say whether it is still waiting, as JSON.</summary>
        WaitJson,
    }

    /// <summary>
    /// The browser holds a provider session: re-read the account behind it, then answer the request.
    /// </summary>
    /// <remarks>
    /// The account is re-read on every pass, cookie or no cookie. A disabled or deleted account ends the
    /// provider session and is refused; a pending one gets the wait and no code; only an active account
    /// gets a code.
    /// </remarks>
    /// <param name="ctx">The request being answered.</param>
    /// <param name="request">The request in flight.</param>
    /// <param name="session">The provider session this browser holds.</param>
    /// <param name="answer">How the browser is to be told.</param>
    /// <param name="silent">Whether the client asked for no page to be shown.</param>
    internal static async Task ProceedAsync(
        HttpContext ctx, AuthorizeRequest request, ProviderSessionRow session, Answer answer, bool silent)
    {
        var sessions = ctx.RequestServices.GetRequiredService<ProviderSessions>();
        var authority = ctx.RequestServices.GetRequiredService<UserStoreAuthority>();
        bool json = answer is Answer.Json or Answer.WaitJson;

        AuthorityAnswer standing;
        try
        {
            standing = await authority.ResolveAsync(session.Identity.ToIdentity(), ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await RefuseInFlightAsync(ctx, request, json, StatusCodes.Status503ServiceUnavailable,
                "authority_unavailable", "The account store could not be read. Try again shortly.");
            return;
        }

        if (standing.Outcome != AuthorityOutcome.Ok || standing.User is not { } user
            || user.Status == UserStatus.Disabled)
        {
            // The sign-in this browser holds is for an account that can no longer be signed in to, so it
            // ends here rather than being offered again on the next bounce.
            await sessions.EndAsync(ctx, session.SessionId);
            sessions.ClearCookie(ctx);

            if (silent)
            {
                await RedirectErrorAsync(ctx, request, "login_required", "Nobody is signed in on this browser.");
                return;
            }

            bool disabled = standing.Outcome == AuthorityOutcome.Disabled || standing.User?.Status == UserStatus.Disabled;
            await RefuseInFlightAsync(ctx, request, json,
                disabled ? StatusCodes.Status403Forbidden : StatusCodes.Status401Unauthorized,
                disabled ? "account_disabled" : "no_account",
                disabled ? "This account has been switched off." : "That account no longer exists. Sign in again.");
            return;
        }

        if (user.Status != UserStatus.Active)
        {
            if (silent)
            {
                await RedirectErrorAsync(ctx, request, "login_required", "This account is waiting for approval.");
                return;
            }

            switch (answer)
            {
                case Answer.Json:
                    await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new CredentialAnswer(null, "/authorize/wait"),
                        AnchorJsonContext.Default.CredentialAnswer);
                    return;

                case Answer.WaitPage:
                case Answer.WaitJson:
                    DateTimeOffset expires = DateTimeOffset.UtcNow.Add(ProviderCookies.RequestLifetime);
                    await ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>()
                        .ExtendRequestAsync(request.SecretHash, expires, ctx.RequestAborted);
                    ctx.Response.Cookies.Append(ProviderCookies.Request, ctx.Request.Cookies[ProviderCookies.Request]!,
                        ProviderCookies.Options(ctx, ProviderCookies.RequestLifetime));

                    if (answer == Answer.WaitJson)
                    {
                        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
                            new CredentialAnswer(null, "/authorize/wait"), AnchorJsonContext.Default.CredentialAnswer);
                        return;
                    }

                    if (!await ctx.RequestServices.GetRequiredService<ProviderBundle>()
                            .TryServeAsync(ctx, ProviderBundle.Page.Wait, ClientOrigin(request), []))
                        await ProviderPages.WaitAsync(ctx, user.Username, ClientOrigin(request));
                    return;

                default:
                    ctx.Response.StatusCode = StatusCodes.Status303SeeOther;
                    ctx.Response.Headers.Location = "/authorize/wait";
                    return;
            }
        }

        string destination = await IssueCodeAsync(ctx, request, user, session);
        if (json)
        {
            await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new CredentialAnswer(destination, null),
                AnchorJsonContext.Default.CredentialAnswer);
            return;
        }

        // 303 after a post, so the browser arrives at the client with a GET whatever the method was.
        ctx.Response.StatusCode = HttpMethods.IsPost(ctx.Request.Method)
            ? StatusCodes.Status303SeeOther
            : StatusCodes.Status302Found;
        ctx.Response.Headers.Location = destination;
    }

    // ── Token ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// <c>POST /token</c>: exchange a code for a session, or rotate one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The code is taken out of the store before anything about the exchange is checked, so a code
    /// presented wrongly is spent: the only party that presents one wrongly is one that should not have it.
    /// A replay, a mismatched verifier, a different client or redirect, and a code past its sixty seconds
    /// are all <c>invalid_grant</c>.
    /// </para>
    /// <para>
    /// The session is minted through the one mint site every door uses, recording the provider session it
    /// came from. Its access token's audience is the cluster; the <c>id_token</c> beside it is the client's.
    /// </para>
    /// </remarks>
    internal static async Task Token(HttpContext ctx)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Pragma = "no-cache";

        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        if (options.IssuerUrl is null)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable",
                "This anchor has no issuer address, so it mints nothing.");
            return;
        }

        if (!ctx.RequestServices.GetRequiredService<AnchorRole>().IsAuthority)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable",
                "This member does not hold the cluster's accounts.");
            return;
        }

        if (!ctx.Request.HasFormContentType || ctx.Request.ContentLength > MaxFormBytes)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "invalid_request",
                "The request is a form of at most 8 KiB.");
            return;
        }

        IFormCollection form = await ctx.Request.ReadFormAsync(ctx.RequestAborted);
        switch (Single(form, "grant_type"))
        {
            case "authorization_code":
                await ExchangeCodeAsync(ctx, form);
                return;

            case "refresh_token":
                await RefreshAsync(ctx, form);
                return;

            default:
                await OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "unsupported_grant_type",
                    "The grants served are authorization_code and refresh_token.");
                return;
        }
    }

    private static async Task ExchangeCodeAsync(HttpContext ctx, IFormCollection form)
    {
        string? code = Single(form, "code");
        string? redirectUri = Single(form, "redirect_uri");
        string? clientId = Single(form, "client_id");
        string? verifier = Single(form, "code_verifier");

        if (code is null || redirectUri is null || clientId is null || verifier is null)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "invalid_request",
                "code, redirect_uri, client_id and code_verifier are all required.");
            return;
        }

        var registry = ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>();
        AuthorizationCode? issued = await registry.ConsumeCodeAsync(ProviderCookies.Hash(code), ctx.RequestAborted);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (issued is null || issued.Expires <= now
            || !string.Equals(issued.ClientId, clientId, StringComparison.Ordinal)
            || !string.Equals(issued.RedirectUri, redirectUri, StringComparison.Ordinal)
            || !VerifierMatches(verifier, issued.CodeChallenge)
            || ctx.RequestServices.GetRequiredService<ClientRegistry>().Find(clientId) is null)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "invalid_grant",
                "That code is not valid for this exchange.");
            return;
        }

        // The provider session may have been signed out in the seconds since the code was issued, and a
        // code minted under a sign-in that has ended mints nothing.
        if (await registry.FindProviderSessionAsync(issued.ProviderSession, ctx.RequestAborted) is not { } session)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "invalid_grant",
                "The sign-in that code was issued under has ended.");
            return;
        }

        KgsmIdentity identity = session.Identity.ToIdentity();
        AuthorityAnswer standing;
        try
        {
            standing = await ctx.RequestServices.GetRequiredService<UserStoreAuthority>()
                .ResolveAsync(identity, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable",
                "The account store could not be read.");
            return;
        }

        if (standing is not { Outcome: AuthorityOutcome.Ok, User: { Status: UserStatus.Active } user }
            || !string.Equals(user.UserId, issued.UserId, StringComparison.Ordinal))
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "invalid_grant",
                "The account that code was issued for cannot be signed in to.");
            return;
        }

        var idTokens = ctx.RequestServices.GetRequiredService<IdTokens>();
        await Endpoints.MintSessionFor(ctx, identity, standing.Tier, user, now, (access, refresh) =>
            Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new TokenResponse(
                AccessToken: access.Token,
                TokenType: "Bearer",
                ExpiresIn: SecondsUntil(access.ExpiresAt, now),
                RefreshToken: refresh.Token,
                IdToken: idTokens.Mint(user, clientId, session.SessionId, issued.AuthTime, issued.Nonce, identity.AvatarUrl),
                Scope: "openid"),
                AnchorJsonContext.Default.TokenResponse),
            providerSession: session.SessionId);
    }

    private static async Task RefreshAsync(HttpContext ctx, IFormCollection form)
    {
        if (Single(form, "refresh_token") is not { } presented)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "invalid_request", "refresh_token is required.");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        Endpoints.Rotation rotation = await Endpoints.RotateAsync(ctx, presented);
        switch (rotation.Outcome)
        {
            case Endpoints.RotationOutcome.Rotated:
                await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new TokenResponse(
                    AccessToken: rotation.Access!.Token,
                    TokenType: "Bearer",
                    ExpiresIn: SecondsUntil(rotation.Access.ExpiresAt, now),
                    RefreshToken: rotation.Refresh!.Token,
                    IdToken: null,
                    Scope: "openid"),
                    AnchorJsonContext.Default.TokenResponse);
                return;

            case Endpoints.RotationOutcome.Unavailable:
                await OAuthErrorAsync(ctx, StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable",
                    "The account store could not be read.");
                return;

            default:
                await OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "invalid_grant",
                    "That session cannot be continued. Sign in again.");
                return;
        }
    }

    // ── Userinfo ──────────────────────────────────────────────────────────────

    /// <summary><c>GET /userinfo</c>: the account, as the bearer's session sees it.</summary>
    internal static async Task UserInfo(HttpContext ctx)
    {
        Caller caller;
        try
        {
            caller = await ctx.RequestServices.GetRequiredService<AnchorAuth>().ResolveAsync(ctx.Request, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await OAuthErrorAsync(ctx, StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable",
                "The account store could not be read.");
            return;
        }

        if (!caller.IsAuthenticated || caller.User is not { } user)
        {
            ctx.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
            await OAuthErrorAsync(ctx, StatusCodes.Status401Unauthorized, "invalid_token",
                "That bearer is not a live session.");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new UserInfoResponse(user.UserId, user.Username, user.DisplayName, caller.Identity?.AvatarUrl),
            AnchorJsonContext.Default.UserInfoResponse);
    }

    // ── Sign out ──────────────────────────────────────────────────────────────

    /// <summary>
    /// <c>GET /sign-out</c>: the OpenID Connect end-session endpoint.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The hint's <c>sid</c> names the provider session, so it is found whether or not the browser still
    /// carries the cookie; it and every session minted under it end, on every member. The browser goes
    /// back to <c>post_logout_redirect_uri</c> only when that is registered, exactly, for the client the
    /// hint was issued to.
    /// </para>
    /// <para>
    /// Without a valid hint the person is asked to confirm, so a page elsewhere cannot sign somebody out
    /// by linking here. Not gated on holding the capability: ending a sign-in takes authority away.
    /// </para>
    /// </remarks>
    internal static async Task SignOut(HttpContext ctx)
    {
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        if (options.IssuerUrl is null)
        {
            await NoIssuerPageAsync(ctx);
            return;
        }

        IQueryCollection q = ctx.Request.Query;
        string? clientId = Single(q, "client_id");
        string? returnTo = Single(q, "post_logout_redirect_uri");
        string? state = Single(q, "state");

        IdTokenHint? hint = await ctx.RequestServices.GetRequiredService<IdTokens>().ReadHintAsync(Single(q, "id_token_hint"));
        if (hint is null || (clientId is not null && !string.Equals(clientId, hint.ClientId, StringComparison.Ordinal)))
        {
            RegisteredClient? asking = ctx.RequestServices.GetRequiredService<ClientRegistry>().Find(clientId);
            string? origin = asking is not null && ClientRegistry.ReturnsAfterSignOut(asking, returnTo)
                ? ClientRegistry.OriginOf(returnTo!)
                : null;
            await ProviderPages.ConfirmSignOutAsync(ctx, clientId, returnTo, state, origin);
            return;
        }

        var sessions = ctx.RequestServices.GetRequiredService<ProviderSessions>();
        ProviderSessionRow? current = await sessions.CurrentAsync(ctx);
        await sessions.EndAsync(ctx, hint.ProviderSession);

        // The cookie goes when it names the sign-in just ended, or names nothing live. One naming a
        // different, live sign-in is somebody else's on this browser and is left alone.
        if (current is null || current.SessionId == hint.ProviderSession)
            sessions.ClearCookie(ctx);

        await ReturnAfterSignOutAsync(ctx, hint.ClientId, returnTo, state);
    }

    /// <summary><c>POST /sign-out</c>: the person confirmed; end the sign-in this browser holds.</summary>
    internal static async Task ConfirmSignOut(HttpContext ctx)
    {
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        if (options.IssuerUrl is null)
        {
            await NoIssuerPageAsync(ctx);
            return;
        }

        if (!IsSameOrigin(ctx))
        {
            await ProviderPages.ProblemAsync(ctx, StatusCodes.Status403Forbidden, "Sign-out refused",
                "A sign-out can only be confirmed from this page.");
            return;
        }

        IFormCollection form = ctx.Request.HasFormContentType && ctx.Request.ContentLength is null or <= MaxFormBytes
            ? await ctx.Request.ReadFormAsync(ctx.RequestAborted)
            : FormCollection.Empty;

        var sessions = ctx.RequestServices.GetRequiredService<ProviderSessions>();
        if (await sessions.CurrentAsync(ctx) is { } current)
            await sessions.EndAsync(ctx, current.SessionId);
        sessions.ClearCookie(ctx);

        await ReturnAfterSignOutAsync(ctx, Single(form, "client_id"), Single(form, "post_logout_redirect_uri"),
            Single(form, "state"));
    }

    private static Task ReturnAfterSignOutAsync(HttpContext ctx, string? clientId, string? returnTo, string? state)
    {
        RegisteredClient? client = ctx.RequestServices.GetRequiredService<ClientRegistry>().Find(clientId);
        if (client is null || !ClientRegistry.ReturnsAfterSignOut(client, returnTo))
            return ProviderPages.SignedOutAsync(ctx);

        string destination = state is { Length: > 0 }
            ? QueryHelpers.AddQueryString(returnTo!, "state", state)
            : returnTo!;
        ctx.Response.StatusCode = HttpMethods.IsPost(ctx.Request.Method)
            ? StatusCodes.Status303SeeOther
            : StatusCodes.Status302Found;
        ctx.Response.Headers.Location = destination;
        return Task.CompletedTask;
    }

    // ── Clients ───────────────────────────────────────────────────────────────

    /// <summary><c>GET /auth/cluster/clients</c>: every client, announced or registered.</summary>
    internal static async Task ListClients(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx) || await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new ClientsPage([.. ctx.RequestServices.GetRequiredService<ClientRegistry>().All.Select(ToRecord)]),
            AnchorJsonContext.Default.ClientsPage);
    }

    /// <summary><c>POST /auth/cluster/clients</c>: register a client by hand.</summary>
    /// <remarks>For whatever no member announces: a panel served from a bucket, a third-party
    /// application. Registering it is the consent every person signing in to it gives.</remarks>
    internal static async Task RegisterClient(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;
        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is not { } caller)
            return;

        if (await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.ClientRegistration) is not { } body)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request", "The request body is not readable.");
            return;
        }

        var (outcome, client, problem) = await ctx.RequestServices.GetRequiredService<ClientRegistry>()
            .RegisterAsync(body, DateTimeOffset.UtcNow, ctx.RequestAborted);

        switch (outcome)
        {
            case ClientRegistry.RegisterOutcome.Invalid:
                await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_client", problem!);
                return;

            case ClientRegistry.RegisterOutcome.Taken:
                await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "client_taken", problem!);
                return;
        }

        ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.Clients")
            .LogInformation("{Actor} registered client {ClientId} ({Name}) returning to {Redirects}",
                caller.Identity?.ActorString ?? caller.User?.Username, client!.ClientId, client.Name,
                string.Join(", ", client.RedirectUris));

        await Endpoints.WriteJson(ctx, StatusCodes.Status201Created, ToRecord(client),
            AnchorJsonContext.Default.ClientRecord);
    }

    /// <summary><c>DELETE /auth/cluster/clients/{clientId}</c>: remove a client registered by hand.</summary>
    internal static async Task RemoveClient(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;
        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is not { } caller)
            return;

        string clientId = (string?)ctx.Request.RouteValues["clientId"] ?? "";
        switch (await ctx.RequestServices.GetRequiredService<ClientRegistry>().RemoveAsync(clientId, ctx.RequestAborted))
        {
            case ClientRegistry.RemoveOutcome.NotFound:
                await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_client", "No client has that id.");
                return;

            case ClientRegistry.RemoveOutcome.Announced:
                await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "client_announced",
                    "A member announces that client, and it leaves when the member stops announcing it.");
                return;
        }

        ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.Clients")
            .LogInformation("{Actor} removed client {ClientId}",
                caller.Identity?.ActorString ?? caller.User?.Username, clientId);

        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    private static ClientRecord ToRecord(RegisteredClient c) =>
        new(c.ClientId, c.Name, c.RedirectUris, c.PostLogoutRedirectUris, c.Source, c.MemberId, c.Created);

    // ── The request in flight ─────────────────────────────────────────────────

    /// <summary>The request this browser has in flight, or null.</summary>
    internal static async Task<AuthorizeRequest?> InFlightAsync(HttpContext ctx)
    {
        string? secret = ctx.Request.Cookies[ProviderCookies.Request];
        if (string.IsNullOrEmpty(secret))
            return null;

        return await ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>()
            .FindRequestAsync(ProviderCookies.Hash(secret), ctx.RequestAborted);
    }

    internal static async Task<AuthorizeRequest> BeginRequestAsync(
        HttpContext ctx, string clientId, string redirectUri, string? state, string challenge, string? nonce,
        string? prompt)
    {
        var registry = ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>();

        // One request per browser. The previous one is abandoned the moment another begins, so a stale
        // request can never be the one a later credential completes.
        if (ctx.Request.Cookies[ProviderCookies.Request] is { Length: > 0 } previous)
            await registry.DeleteRequestAsync(ProviderCookies.Hash(previous), ctx.RequestAborted);

        string secret = ProviderCookies.NewSecret();
        var request = new AuthorizeRequest(
            ProviderCookies.Hash(secret), clientId, redirectUri, state, challenge, nonce, prompt,
            UpstreamState: null, DateTimeOffset.UtcNow.Add(ProviderCookies.RequestLifetime));

        await registry.StoreRequestAsync(request, ctx.RequestAborted);
        ctx.Response.Cookies.Append(ProviderCookies.Request, secret,
            ProviderCookies.Options(ctx, ProviderCookies.RequestLifetime));
        return request;
    }

    private static async Task EndRequestAsync(HttpContext ctx, AuthorizeRequest request)
    {
        await ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>()
            .DeleteRequestAsync(request.SecretHash, ctx.RequestAborted);
        ctx.Response.Cookies.Delete(ProviderCookies.Request, ProviderCookies.Options(ctx, TimeSpan.Zero));
    }

    /// <summary>Mint a code for the request, end it, and say where the browser goes with it.</summary>
    /// <remarks>
    /// The account page's own sign-in is the one request that gets no code: what it needed was the
    /// provider session, which is proved by now, and a code nobody exchanges is a bearer left lying about.
    /// </remarks>
    private static async Task<string> IssueCodeAsync(
        HttpContext ctx, AuthorizeRequest request, KgsmUser user, ProviderSessionRow session)
    {
        if (request.ClientId == AccountPageEndpoints.AccountClientId)
        {
            await EndRequestAsync(ctx, request);
            return request.RedirectUri;
        }

        string code = ProviderCookies.NewSecret();
        await ctx.RequestServices.GetRequiredService<SqliteSessionRegistry>().IssueCodeAsync(
            ProviderCookies.Hash(code),
            new AuthorizationCode(
                request.ClientId, request.RedirectUri, request.CodeChallenge, request.Nonce, user.UserId,
                session.SessionId, session.CredentialAt, DateTimeOffset.UtcNow.Add(CodeLifetime)),
            ctx.RequestAborted);

        await EndRequestAsync(ctx, request);

        var answer = new Dictionary<string, string?> { ["code"] = code };
        if (request.State is { } state)
            answer["state"] = state;
        answer["iss"] = ctx.RequestServices.GetRequiredService<AnchorOptions>().Issuer;
        return QueryHelpers.AddQueryString(request.RedirectUri, answer);
    }

    // ── Answers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Whether this provider can serve a page at all: it has an issuer, and it holds the accounts.
    /// </summary>
    /// <remarks>A member standing by refuses, naming the holder: a promotion candidate is not a second door.</remarks>
    private static async Task<bool> RequireProviderPageAsync(HttpContext ctx, bool json = false)
    {
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        if (options.IssuerUrl is null)
        {
            if (json)
                await NoIssuerAsync(ctx);
            else
                await NoIssuerPageAsync(ctx);
            return false;
        }

        var role = ctx.RequestServices.GetRequiredService<AnchorRole>();
        if (role.IsAuthority)
            return true;

        if (json)
            return await Endpoints.RequireAuthorityAsync(ctx);

        await ProviderPages.ProblemAsync(ctx, StatusCodes.Status503ServiceUnavailable, "Not signing in here",
            role.Holder is { Length: > 0 } holder
                ? $"This member does not hold the cluster's accounts. {holder} does."
                : "No member holds the cluster's accounts yet.");
        return false;
    }

    private static Task NoIssuerAsync(HttpContext ctx) =>
        Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "no_issuer",
            "This anchor has no issuer address, so it signs nobody in. Set Anchor__Issuer to the URL people reach it at.");

    private static Task NoIssuerPageAsync(HttpContext ctx) =>
        ProviderPages.ProblemAsync(ctx, StatusCodes.Status503ServiceUnavailable, "Sign-in is not set up",
            "This anchor has no issuer address, so it signs nobody in.");

    private static Task ExpiredAsync(HttpContext ctx, bool json) =>
        json
            ? Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "request_expired",
                "This sign-in has expired. Go back to the application and start again.")
            : ProviderPages.ProblemAsync(ctx, StatusCodes.Status400BadRequest, "This sign-in has expired",
                "Go back to the application and start again.");

    private static Task RefuseAsync(HttpContext ctx, bool json, int status, string code, string title, string message) =>
        json
            ? Endpoints.Refuse(ctx, status, code, message)
            : ProviderPages.ProblemAsync(ctx, status, title, message);

    /// <summary>A refusal while a request is in flight: inline for the pages, on the sign-in form otherwise.</summary>
    private static Task RefuseInFlightAsync(
        HttpContext ctx, AuthorizeRequest request, bool json, int status, string code, string message) =>
        json
            ? Endpoints.Refuse(ctx, status, code, message)
            : SignInPageAsync(ctx, request, message, status);

    /// <summary>The sign-in page for the request in flight.</summary>
    /// <remarks>
    /// The bundle's page on a first visit, where it is installed. A refusal of a plain form post is
    /// answered with the built-in page and the reason on it: a browser that posted the form rather than
    /// fetching is one where the application did not run, and the static document has nowhere to say why.
    /// </remarks>
    internal static async Task SignInPageAsync(HttpContext ctx, AuthorizeRequest request, string? message,
        int status = StatusCodes.Status200OK)
    {
        IReadOnlyList<string> providers = ctx.RequestServices.GetRequiredService<ProviderCatalog>().Configured;
        if (message is null
            && await ctx.RequestServices.GetRequiredService<ProviderBundle>()
                .TryServeAsync(ctx, ProviderBundle.Page.SignIn, ClientOrigin(request), providers))
            return;

        await ProviderPages.SignInAsync(ctx, ClientName(ctx, request), ClientOrigin(request),
            providers, message, status);
    }

    private static string ClientOrigin(AuthorizeRequest request) => ClientRegistry.OriginOf(request.RedirectUri);

    /// <summary>Whose sign-in a request is, as a person reads it.</summary>
    private static string ClientName(HttpContext ctx, AuthorizeRequest request) =>
        request.ClientId == AccountPageEndpoints.AccountClientId
            ? AccountPageEndpoints.AccountClientName
            : ctx.RequestServices.GetRequiredService<ClientRegistry>().Find(request.ClientId)?.Name ?? request.ClientId;

    private static void RedirectError(HttpContext ctx, string redirectUri, string? state, string error, string description)
    {
        var answer = new Dictionary<string, string?> { ["error"] = error, ["error_description"] = description };
        if (state is not null)
            answer["state"] = state;
        answer["iss"] = ctx.RequestServices.GetRequiredService<AnchorOptions>().Issuer;
        ctx.Response.Redirect(QueryHelpers.AddQueryString(redirectUri, answer));
    }

    private static async Task RedirectErrorAsync(HttpContext ctx, AuthorizeRequest request, string error, string description)
    {
        await EndRequestAsync(ctx, request);
        RedirectError(ctx, request.RedirectUri, request.State, error, description);
    }

    private static Task OAuthErrorAsync(HttpContext ctx, int status, string error, string description) =>
        Endpoints.WriteJson(ctx, status, new OAuthError(error, description), AnchorJsonContext.Default.OAuthError);

    // ── Checks ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Whether a post came from the provider's own pages.
    /// </summary>
    /// <remarks>
    /// Fetch metadata where the browser sends it, and the <c>Origin</c> where it does not. A request with
    /// neither is refused: every browser that can run these pages sends one or the other on a post.
    /// </remarks>
    internal static bool IsSameOrigin(HttpContext ctx)
    {
        string site = ctx.Request.Headers["Sec-Fetch-Site"].ToString();
        if (site.Length > 0)
            return site == "same-origin";

        string origin = ctx.Request.Headers.Origin.ToString();
        string? mine = ctx.RequestServices.GetRequiredService<AnchorOptions>().IssuerOrigin;
        return origin.Length > 0 && mine is not null && string.Equals(origin, mine, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Whether a PKCE verifier is well formed and hashes to the challenge.</summary>
    private static bool VerifierMatches(string verifier, string challenge)
    {
        if (verifier.Length is < 43 or > 128)
            return false;

        byte[] hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        string computed = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(computed), Encoding.ASCII.GetBytes(challenge));
    }

    private static long SecondsUntil(DateTimeOffset expires, DateTimeOffset now) =>
        Math.Max(0, (long)(expires - now).TotalSeconds);

    /// <summary>A parameter's one value, or null when it is absent, blank or repeated.</summary>
    /// <remarks>A repeated parameter is ambiguous, and an authorization request read two ways by two
    /// readers is how one of them is fooled.</remarks>
    private static string? Single(IQueryCollection q, string name) => One(q[name]);

    private static string? Single(IFormCollection f, string name) => One(f[name]);

    private static string? One(StringValues values) =>
        values.Count == 1 && !string.IsNullOrEmpty(values[0]) ? values[0] : null;

    private static HashSet<string> Tokens(string? value) =>
        [.. (value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)];
}
