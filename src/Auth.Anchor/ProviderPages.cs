using System.Net;
using System.Text;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The provider's pages as plain documents: signing in, the wait for approval, sign-out, and refusals.
/// </summary>
/// <remarks>
/// <para>
/// <b>The floor.</b> Signing in never needs script. The document carries a working form and the provider
/// links, so a bundle that fails to load, or scripting that is off, still leaves a way in — the provider
/// is the one origin whose failure locks a cluster out of everything. Where <c>kgsm-web-auth</c> is
/// installed its documents are served instead (<see cref="ProviderBundle"/>), each carrying a floor of
/// its own; these answer a refusal, a form post that failed with no script to show why, and every page
/// while that package is absent — the sign-in page then names it.
/// </para>
/// <para>
/// Every document is sent under a content security policy with no inline script and no inline style,
/// and <c>form-action</c> naming this origin and the one client the request in flight returns to — a
/// browser checks the redirect that follows a form post against it. No page may be framed.
/// </para>
/// <para>
/// Every value written into a document is encoded. Most come from this provider, but a client's name is
/// an administrator's text and a username is whatever somebody registered.
/// </para>
/// </remarks>
internal static class ProviderPages
{
    /// <summary>Where the pages' stylesheet is served, on this origin because the policy admits no other.</summary>
    public const string StylesheetPath = "/authorize/floor.css";

    /// <summary>The sign-in page for the request in flight.</summary>
    /// <param name="ctx">The request being answered.</param>
    /// <param name="clientName">Whose sign-in the person is completing.</param>
    /// <param name="clientOrigin">Where the request in flight returns to, which the form may redirect to.</param>
    /// <param name="providers">The external providers wired here, as the route names them.</param>
    /// <param name="message">Why the last attempt failed, or null on a first visit.</param>
    /// <param name="status">The status to answer with.</param>
    public static Task SignInAsync(
        HttpContext ctx, string clientName, string clientOrigin, IReadOnlyList<string> providers,
        string? message, int status = StatusCodes.Status200OK)
    {
        var body = new StringBuilder();
        body.Append("<h1>Sign in</h1>");
        body.Append("<p class=\"lead\">to <strong>").Append(Encode(clientName)).Append("</strong></p>");
        if (message is { Length: > 0 })
            body.Append("<p class=\"error\" role=\"alert\">").Append(Encode(message)).Append("</p>");

        body.Append("<form method=\"post\" action=\"/authorize/credentials\">")
            .Append("<label>Username<input name=\"username\" autocomplete=\"username\" autocapitalize=\"none\" ")
            .Append("spellcheck=\"false\" required autofocus></label>")
            .Append("<label>Password<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>")
            .Append("<button type=\"submit\">Sign in</button>")
            .Append("</form>");

        if (providers.Count > 0)
        {
            body.Append("<div class=\"providers\">");
            foreach (string provider in providers)
            {
                body.Append("<a class=\"provider\" href=\"/authorize/").Append(Encode(provider)).Append("\">Continue with ")
                    .Append(Encode(DisplayName(provider))).Append("</a>");
            }
            body.Append("</div>");
        }

        body.Append("<p class=\"note\">Plain sign-in form: kgsm-web-auth is not installed.</p>");
        return WriteAsync(ctx, status, "Sign in", body.ToString(), clientOrigin);
    }

    /// <summary>An account waiting for an administrator, polled without script.</summary>
    public static Task WaitAsync(HttpContext ctx, string username, string clientOrigin)
    {
        string body =
            "<h1>Waiting for approval</h1>"
            + $"<p class=\"lead\"><strong>{Encode(username)}</strong> needs an administrator's approval before you can continue.</p>"
            + "<p><a href=\"/authorize/wait\">Check now</a></p>";

        // A refresh rather than a stream: the wait is minutes, and on a page with no script a refresh is
        // the only thing that polls at all.
        return WriteAsync(ctx, StatusCodes.Status200OK, "Waiting for approval", body, clientOrigin, refreshSeconds: 15);
    }

    /// <summary>A refusal that has nowhere to redirect to, answered on this origin.</summary>
    public static Task ProblemAsync(HttpContext ctx, int status, string title, string message) =>
        WriteAsync(ctx, status, title, $"<h1>{Encode(title)}</h1><p>{Encode(message)}</p>", clientOrigin: null);

    /// <summary>
    /// Asking the person to confirm a sign-out that arrived without proof of which sign-in it ends.
    /// </summary>
    /// <remarks>
    /// Without it, any page anywhere could sign somebody out by linking here. The values carried to the
    /// post are checked again there, against the client's registration.
    /// </remarks>
    public static Task ConfirmSignOutAsync(
        HttpContext ctx, string? clientId, string? postLogoutRedirectUri, string? state, string? returnOrigin)
    {
        var body = new StringBuilder();
        body.Append("<h1>Sign out</h1><p class=\"lead\">Sign out of every application signed in through this browser?</p>");
        body.Append("<form method=\"post\" action=\"/sign-out\">");
        Hidden(body, "client_id", clientId);
        Hidden(body, "post_logout_redirect_uri", postLogoutRedirectUri);
        Hidden(body, "state", state);
        body.Append("<button type=\"submit\">Sign out</button></form>");
        return WriteAsync(ctx, StatusCodes.Status200OK, "Sign out", body.ToString(), returnOrigin);
    }

    /// <summary>Signed out, with nowhere registered to return to.</summary>
    public static Task SignedOutAsync(HttpContext ctx) =>
        WriteAsync(ctx, StatusCodes.Status200OK, "Signed out",
            "<h1>Signed out</h1><p>You can close this page.</p>", clientOrigin: null);

    /// <summary>The pages' stylesheet.</summary>
    public static Task StylesheetAsync(HttpContext ctx)
    {
        ctx.Response.ContentType = "text/css; charset=utf-8";
        ctx.Response.Headers.CacheControl = "public, max-age=3600";
        return ctx.Response.WriteAsync(Stylesheet, ctx.RequestAborted);
    }

    private static void Hidden(StringBuilder body, string name, string? value)
    {
        if (value is { Length: > 0 })
            body.Append("<input type=\"hidden\" name=\"").Append(name).Append("\" value=\"").Append(Encode(value)).Append("\">");
    }

    private static Task WriteAsync(
        HttpContext ctx, int status, string title, string body, string? clientOrigin, int? refreshSeconds = null)
    {
        ApplyDocumentHeaders(ctx, status, clientOrigin);

        var document = new StringBuilder();
        document.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
            .Append("<meta name=\"referrer\" content=\"no-referrer\">")
            .Append("<meta name=\"color-scheme\" content=\"light dark\">");
        if (refreshSeconds is { } seconds)
            document.Append("<meta http-equiv=\"refresh\" content=\"").Append(seconds).Append("\">");
        document.Append("<title>").Append(Encode(title)).Append("</title>")
            .Append("<link rel=\"stylesheet\" href=\"").Append(StylesheetPath).Append("\">")
            .Append("</head><body><main class=\"card\">")
            .Append(body)
            .Append("</main></body></html>");

        return ctx.Response.WriteAsync(document.ToString(), ctx.RequestAborted);
    }

    /// <summary>
    /// The headers every document the provider serves carries, whoever built it.
    /// </summary>
    /// <param name="ctx">The request being answered.</param>
    /// <param name="status">The status to answer with.</param>
    /// <param name="clientOrigin">The one client a form on this page may redirect to, or null.</param>
    internal static void ApplyDocumentHeaders(HttpContext ctx, int status, string? clientOrigin)
    {
        string formAction = clientOrigin is { Length: > 0 } ? $"'self' {clientOrigin}" : "'self'";

        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "text/html; charset=utf-8";
        IHeaderDictionary headers = ctx.Response.Headers;
        headers.ContentSecurityPolicy =
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
            + $"connect-src 'self'; form-action {formAction}; frame-ancestors 'none'; base-uri 'none'";
        headers.CacheControl = "no-store";
        headers["Referrer-Policy"] = "no-referrer";
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
    }

    internal static string DisplayName(string provider) =>
        provider.Length == 0 ? provider : char.ToUpperInvariant(provider[0]) + provider[1..];

    internal static string Encode(string value) => WebUtility.HtmlEncode(value);

    // One appearance, following the reader's colour scheme. A theme carried in the bounce would be a
    // parameter a stranger sets.
    private const string Stylesheet =
        """
        :root { color-scheme: light dark; --bg: #f4f5f7; --card: #ffffff; --fg: #1b1d22; --muted: #5b6070;
                --line: #d7dae0; --accent: #3b5bdb; --accent-fg: #ffffff; --error: #b42318; }
        @media (prefers-color-scheme: dark) {
          :root { --bg: #111318; --card: #1a1d24; --fg: #e8eaef; --muted: #9aa0ad; --line: #2e323c;
                  --accent: #748ffc; --accent-fg: #0b0d12; --error: #f97066; }
        }
        * { box-sizing: border-box; }
        html, body { margin: 0; min-height: 100%; }
        body { background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
               display: flex; align-items: center; justify-content: center; padding: 16px; min-height: 100vh; }
        .card { width: 100%; max-width: 380px; background: var(--card); border: 1px solid var(--line);
                border-radius: 12px; padding: 28px 24px; }
        h1 { font-size: 1.4rem; margin: 0 0 4px; }
        .lead { color: var(--muted); margin: 0 0 20px; }
        .lead strong { color: var(--fg); }
        .error { color: var(--error); margin: 0 0 16px; }
        form { display: flex; flex-direction: column; gap: 14px; }
        label { display: flex; flex-direction: column; gap: 6px; font-size: .9rem; color: var(--muted); }
        input { font: inherit; color: var(--fg); background: var(--bg); border: 1px solid var(--line);
                border-radius: 8px; padding: 10px 12px; }
        input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
        button, .provider { font: inherit; font-weight: 600; border-radius: 8px; padding: 10px 12px; text-align: center;
                            cursor: pointer; text-decoration: none; }
        button { background: var(--accent); color: var(--accent-fg); border: 0; margin-top: 4px; }
        .providers { display: flex; flex-direction: column; gap: 10px; margin-top: 18px; padding-top: 18px;
                     border-top: 1px solid var(--line); }
        .provider { color: var(--fg); border: 1px solid var(--line); }
        .note { color: var(--muted); font-size: .8rem; margin: 20px 0 0; }
        a { color: var(--accent); }
        """;
}
