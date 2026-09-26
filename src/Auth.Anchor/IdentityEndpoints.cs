using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Attaching an identity to an account: the provider's answer to a link the account page started.
/// </summary>
/// <remarks>
/// A link outlives the session that makes it — afterwards whoever holds that provider account signs in
/// as this one — so it starts only from the account page, behind a recent proof
/// (<see cref="AccountPageEndpoints.StartLink"/>). This is where the provider sends the browser back.
/// </remarks>
internal static class IdentityEndpoints
{
    /// <summary>The cookie carrying the opaque ticket for a link in flight.</summary>
    /// <remarks>
    /// The ticket and nothing else. The account being changed stays on this machine — a browser
    /// carrying its own account id would be the authority on whose account is being attached to.
    /// </remarks>
    private const string TicketCookie = "kgsm_link_ticket";

    /// <summary>Where the browser goes when the link has been decided either way.</summary>
    private const string AccountPage = "/account";

    /// <summary>
    /// Take the provider's answer and attach the identity to the account that started the link.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unauthenticated by necessity: this is a top-level navigation from the provider. What authorizes
    /// it is the ticket — issued to a provider session that had proved a credential minutes ago,
    /// single-use, and holding the account id on this machine so the browser never carries it.
    /// </para>
    /// <para>
    /// Freshness is checked when the link is <em>started</em> and not again here. The bounce takes as
    /// long as it takes, and re-checking would fail a link somebody legitimately began while adding
    /// nothing: the ticket is already one-use, short-lived and unforgeable.
    /// </para>
    /// <para>
    /// The outcome goes back to the account page in the fragment, as <c>linked</c> or
    /// <c>link_error</c>, which the page reads once and reports.
    /// </para>
    /// </remarks>
    internal static async Task CompleteLink(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        string provider = (string?)ctx.Request.RouteValues["provider"] ?? "";
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
            Fail(ctx, logger, "invalid_state", "that link could not be verified");
            return;
        }

        if (ctx.RequestServices.GetRequiredService<ProviderCatalog>().Link(provider) is not { } directory)
        {
            Fail(ctx, logger, "auth_unconfigured", $"connecting a {provider} account is not configured here");
            return;
        }

        if (ctx.Request.Query["code"].ToString() is not { Length: > 0 } code)
        {
            Fail(ctx, logger, "bad_request", "the provider returned no authorization code");
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
            Fail(ctx, logger, "auth_provider_error", "could not finish authenticating with the provider");
            return;
        }

        if (verified is null)
        {
            Fail(ctx, logger, "login_required", "the authorization code was invalid or expired");
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
            Fail(ctx, logger, "authority_unavailable", "the account store could not be written");
            return;
        }

        // Attached to somebody else. Refused rather than moved: re-pointing a credential hands one
        // person another's account, and the person on the other end would never learn it happened.
        if (link.Outcome == LinkOutcome.AlreadyLinked)
        {
            Fail(ctx, logger,
                link.User is null ? "no_such_account" : "identity_taken",
                link.User is null
                    ? "the account no longer exists"
                    : $"that {provider} account is already connected to another account");
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
            await Endpoints.AnnounceAsync(ctx);

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

        ctx.Response.Redirect($"{AccountPage}#linked={Uri.EscapeDataString(verified.Provider)}");
    }

    /// <summary>
    /// Send the browser back to the account page with the reason, and say it here too.
    /// </summary>
    /// <remarks>
    /// <c>link_error</c> rather than <c>error</c>: the page reads its fragment once, and a failed attach
    /// must never read as a failed sign-in. Logged, because a browser is the only other witness and it
    /// cannot be asked afterwards.
    /// </remarks>
    private static void Fail(HttpContext ctx, ILogger logger, string code, string why)
    {
        logger.LogWarning("identity link refused: {Code} — {Why}", code, why);
        ctx.Response.Redirect($"{AccountPage}#link_error={Uri.EscapeDataString(code)}");
    }

    /// <summary>Hand the browser a link ticket, for the callback to redeem.</summary>
    internal static void SetTicketCookie(HttpContext ctx, string ticket) =>
        ctx.Response.Cookies.Append(TicketCookie, ticket, CookieOptions(ctx));

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
