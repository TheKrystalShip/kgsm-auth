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
/// <b>Only a configured origin is echoed, and the wildcard is never sent.</b> A session rides in the
/// response body rather than a cookie, but a wildcard on a surface that mints credentials invites
/// every page on the internet to drive somebody's sign-in from their own browser. An origin that is
/// not configured gets no allowance header and the browser applies its own rule, which is to refuse.
/// </para>
/// <para>
/// Written rather than taken from the CORS middleware because the policy is one comparison against a
/// configured list, and the framework's own answer is a policy engine, a service registration and a
/// set of conventions for a decision this size.
/// </para>
/// </remarks>
internal sealed class CorsMiddleware(RequestDelegate next, AnchorOptions options)
{
    public async Task InvokeAsync(HttpContext context)
    {
        string? origin = context.Request.Headers.Origin.ToString();

        if (!string.IsNullOrEmpty(origin) && Allowed(origin))
        {
            IHeaderDictionary headers = context.Response.Headers;
            headers.AccessControlAllowOrigin = origin;
            // The answer varies by origin, so a cache that keyed on the URL alone would serve one
            // origin's allowance to another.
            headers.Append("Vary", "Origin");
            headers.AccessControlAllowHeaders = "Authorization, Content-Type";
            headers.AccessControlAllowMethods = "GET, POST, PATCH, OPTIONS";
            headers.AccessControlMaxAge = "600";
        }

        // A preflight asks whether the real request is permitted and carries nothing to act on.
        // Answered here for every path, including ones that do not exist, because a browser reads a
        // 404 on a preflight as "not permitted" rather than "no such route".
        if (HttpMethods.IsOptions(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }

        await next(context);
    }

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
