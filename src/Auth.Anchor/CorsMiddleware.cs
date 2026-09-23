namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The cross-origin answer for the browsers that sign in here.
/// </summary>
/// <remarks>
/// <para>
/// A person signs in against the anchor directly, from a Control Panel served by a different member
/// on a different origin. Without a matching allowance the browser discards the answer before any of
/// it is read, so the sign-in fails with nothing in this daemon's log to explain it.
/// </para>
/// <para>
/// <b>Only a known origin is echoed, and the wildcard is never sent.</b> Two kinds are known: a
/// configured origin, answered on every path and with credentials, and a registered client's origin,
/// answered only on what a client of the provider reads across origins and never with credentials.
/// A wildcard on a surface that mints credentials invites every page on the internet to drive
/// somebody's sign-in from their own browser. Any other origin gets no allowance header and the browser
/// applies its own rule, which is to refuse.
/// </para>
/// <para>
/// Written rather than taken from the CORS middleware because the policy is one comparison against a
/// configured list, and the framework's own answer is a policy engine, a service registration and a
/// set of conventions for a decision this size.
/// </para>
/// </remarks>
internal sealed class CorsMiddleware(RequestDelegate next, AnchorOptions options, ClientRegistry clients)
{
    public async Task InvokeAsync(HttpContext ctx)
    {
        string? origin = ctx.Request.Headers.Origin.ToString();

        if (!string.IsNullOrEmpty(origin) && !Allowed(origin) && ClientReadable(ctx.Request.Path)
            && clients.IsClientOrigin(origin))
        {
            // A registered client's origin, on what a client of this provider reads across origins: the
            // published documents, the token exchange, the account behind a bearer, and the
            // administration a panel drives with the bearer it holds. Never with credentials, and never on
            // anything that reads the provider's cookie — those are same-origin by construction.
            IHeaderDictionary headers = ctx.Response.Headers;
            headers.AccessControlAllowOrigin = origin;
            headers.Append("Vary", "Origin");
            string requested = ctx.Request.Headers.AccessControlRequestHeaders.ToString();
            headers.AccessControlAllowHeaders = string.IsNullOrWhiteSpace(requested)
                ? "Authorization, Content-Type"
                : requested;
            headers.Append("Vary", "Access-Control-Request-Headers");
            headers.AccessControlAllowMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
            headers.AccessControlMaxAge = "600";
        }
        else if (!string.IsNullOrEmpty(origin) && Allowed(origin))
        {
            IHeaderDictionary headers = ctx.Response.Headers;
            headers.AccessControlAllowOrigin = origin;
            // The answer varies by origin, so a cache that keyed on the URL alone would serve one
            // origin's allowance to another.
            headers.Append("Vary", "Origin");
            // Reflected, not a fixed list. A browser states exactly which headers it intends to send
            // and refuses the request when the answer omits one — in the browser, before anything
            // reaches this daemon, so a caller sees a failed fetch with no status and nothing here
            // logs it. A list held here would have to be extended every time any client grows a
            // header, and each omission would present itself as a broken endpoint rather than as a
            // policy that did not permit it.
            //
            // Safe because the origin above is already one this cluster configured: a page that is
            // allowed to call at all is allowed to say what it is sending, and the request itself is
            // still authorized on its own merits.
            string requested = ctx.Request.Headers.AccessControlRequestHeaders.ToString();
            headers.AccessControlAllowHeaders = string.IsNullOrWhiteSpace(requested)
                ? "Authorization, Content-Type"
                : requested;

            // The answer now varies by the requested headers as well as by the origin.
            headers.Append("Vary", "Access-Control-Request-Headers");
            // Every method a door here answers. A method missing from this list is refused by the
            // browser at the preflight, which the daemon never sees and no log here records — so a
            // door added without its method appearing here reads as an unreachable endpoint rather
            // than as a policy that does not permit it.
            headers.AccessControlAllowMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
            headers.AccessControlMaxAge = "600";

            // Attaching an identity sets a one-time ticket cookie on an XHR response, and a browser
            // discards both the cookie and the whole answer without this — so the callback can only
            // ever report that the link did not verify. Safe only because the allowance above is a
            // configured origin and never the wildcard: the two together are what the specification
            // refuses to combine, and what this daemon therefore never sends.
            headers.AccessControlAllowCredentials = "true";
        }

        // A preflight asks whether the real request is permitted and carries nothing to act on.
        // Answered here for every path, including ones that do not exist, because a browser reads a
        // 404 on a preflight as "not permitted" rather than "no such route".
        if (HttpMethods.IsOptions(ctx.Request.Method))
        {
            ctx.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }

        await next(ctx);
    }

    /// <summary>The paths a registered client's origin may read across origins.</summary>
    private static bool ClientReadable(PathString path) =>
        path.StartsWithSegments("/.well-known")
        || path.Equals("/token")
        || path.Equals("/userinfo")
        || path.StartsWithSegments("/auth/cluster");

    private bool Allowed(string origin)
    {
        foreach (string configured in options.AllowedOrigins)
        {
            if (string.Equals(configured, origin, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
