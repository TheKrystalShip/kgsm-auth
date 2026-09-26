namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The cross-origin answer for the surfaces this provider signs people in to.
/// </summary>
/// <remarks>
/// <para>
/// A registered client's origin may read what a client of this provider reads across origins: the
/// published documents, the token exchange, the account behind a bearer, the administration a Control
/// Panel drives with the bearer it holds, and this anchor's own configuration and journal. Without a
/// matching allowance the browser discards the answer before any of it is read, so the call fails with
/// nothing in this daemon's log to explain it.
/// </para>
/// <para>
/// <b>Never with credentials, never the wildcard, and never on anything that reads the provider's
/// cookie.</b> A session travels as a bearer, and the pages that read the cookie — sign-in, the wait,
/// the account page — are same-origin by construction. A wildcard on a surface that mints credentials
/// invites every page on the internet to drive somebody's sign-in from their own browser. Any other
/// origin gets no allowance header and the browser applies its own rule, which is to refuse.
/// </para>
/// <para>
/// Written rather than taken from the CORS middleware because the policy is one comparison against the
/// registry, and the framework's own answer is a policy engine, a service registration and a set of
/// conventions for a decision this size.
/// </para>
/// </remarks>
internal sealed class CorsMiddleware(RequestDelegate next, ClientRegistry clients)
{
    public async Task InvokeAsync(HttpContext ctx)
    {
        string? origin = ctx.Request.Headers.Origin.ToString();

        if (!string.IsNullOrEmpty(origin) && ClientReadable(ctx.Request.Path) && clients.IsClientOrigin(origin))
        {
            IHeaderDictionary headers = ctx.Response.Headers;
            headers.AccessControlAllowOrigin = origin;
            // The answer varies by origin, so a cache that keyed on the URL alone would serve one
            // origin's allowance to another.
            headers.Append("Vary", "Origin");

            // Reflected, not a fixed list. A browser states exactly which headers it intends to send and
            // refuses the request when the answer omits one — in the browser, before anything reaches
            // this daemon — so a list held here would present every omission as a broken endpoint. Safe
            // because the origin is already a registered client's, and the request itself is still
            // authorized on its own merits.
            string requested = ctx.Request.Headers.AccessControlRequestHeaders.ToString();
            headers.AccessControlAllowHeaders = string.IsNullOrWhiteSpace(requested)
                ? "Authorization, Content-Type"
                : requested;
            headers.Append("Vary", "Access-Control-Request-Headers");

            // Every method a door here answers. A method missing from this list is refused by the
            // browser at the preflight, which the daemon never sees and no log here records.
            headers.AccessControlAllowMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
            headers.AccessControlMaxAge = "600";
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
        || path.StartsWithSegments("/auth/cluster")
        || path.Equals("/me/access")
        || path.Equals("/auth/identity")
        || path.StartsWithSegments("/auth/config")
        || path.StartsWithSegments("/auth/system")
        || path.StartsWithSegments("/auth/logs")
        || path.StartsWithSegments("/auth/commands");
}
