using System.Net;
using System.Text;

using Microsoft.AspNetCore.StaticFiles;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The provider's pages as <c>kgsm-web</c> builds them — the <c>kgsm-web-auth</c> package — served from
/// where it is installed.
/// </summary>
/// <remarks>
/// <para>
/// <b>Each page is a document of its own with its floor in it.</b> <c>auth-sign-in.html</c> carries a
/// working form, <c>auth-wait.html</c> a refresh that only applies with scripting off, and the
/// application replaces both on mount. The request in flight lives behind a cookie, so the documents are
/// static and served as built; the one thing filled in is the provider links, which only this daemon
/// knows, at the <c>&lt;!--kgsm-floor-providers--&gt;</c> marker.
/// </para>
/// <para>
/// Read from disk on every request, so installing or upgrading the package takes effect without a
/// restart, and an absent package is noticed the same way. Assets are served under <c>/ui/</c>, the base
/// the bundle is built with; their names carry their hash, so they are cached for good.
/// </para>
/// </remarks>
internal sealed class ProviderBundle(AnchorOptions options)
{
    /// <summary>The marker the provider links are written at.</summary>
    internal const string ProvidersMarker = "<!--kgsm-floor-providers-->";

    private static readonly FileExtensionContentTypeProvider ContentTypes = new();

    /// <summary>The pages the bundle carries.</summary>
    internal enum Page { SignIn, Wait, Account }

    /// <summary>Whether the bundle is installed at all.</summary>
    public bool Installed => File.Exists(PathOf(Page.SignIn));

    /// <summary>
    /// Serve one of the bundle's documents, or answer false when that document is not installed.
    /// </summary>
    /// <param name="ctx">The request being answered.</param>
    /// <param name="page">Which document.</param>
    /// <param name="clientOrigin">The one client a form on it may redirect to, or null.</param>
    /// <param name="providers">The external providers wired here, written at the marker.</param>
    public async Task<bool> TryServeAsync(
        HttpContext ctx, Page page, string? clientOrigin, IReadOnlyList<string> providers)
    {
        string document;
        try
        {
            document = await File.ReadAllTextAsync(PathOf(page), ctx.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or UnauthorizedAccessException)
        {
            return false;
        }

        if (document.Contains(ProvidersMarker, StringComparison.Ordinal))
            document = document.Replace(ProvidersMarker, ProviderLinks(providers), StringComparison.Ordinal);

        ProviderPages.ApplyDocumentHeaders(ctx, StatusCodes.Status200OK, clientOrigin);
        await ctx.Response.WriteAsync(document, ctx.RequestAborted).ConfigureAwait(false);
        return true;
    }

    /// <summary><c>GET /ui/{**path}</c>: one of the bundle's files.</summary>
    internal static async Task ServeAssetAsync(HttpContext ctx)
    {
        var bundle = ctx.RequestServices.GetRequiredService<ProviderBundle>();
        string relative = (string?)ctx.Request.RouteValues["path"] ?? "";

        if (bundle.Resolve(relative) is not { } full || !File.Exists(full))
        {
            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        ctx.Response.ContentType = ContentTypes.TryGetContentType(full, out string? type)
            ? type
            : "application/octet-stream";
        ctx.Response.Headers.XContentTypeOptions = "nosniff";
        ctx.Response.Headers.CacheControl = relative.StartsWith("assets/", StringComparison.Ordinal)
            ? "public, max-age=31536000, immutable"
            : "no-cache";

        await ctx.Response.SendFileAsync(full, ctx.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>
    /// The file a request path names, or null when it names something outside the bundle.
    /// </summary>
    /// <remarks>
    /// Resolved and then checked to still be under the root, so no spelling of <c>..</c>, an encoded
    /// separator or an absolute path reads anything else this daemon can open — which includes the
    /// signing key.
    /// </remarks>
    private string? Resolve(string relative)
    {
        if (relative.Length == 0 || relative.Contains('\0'))
            return null;

        string root = Path.GetFullPath(options.UiPath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string full = Path.GetFullPath(Path.Combine(root, relative));
        return full.StartsWith(root, StringComparison.Ordinal) ? full : null;
    }

    private string PathOf(Page page) => Path.Combine(options.UiPath, page switch
    {
        Page.SignIn => "auth-sign-in.html",
        Page.Wait => "auth-wait.html",
        _ => "auth-account.html",
    });

    private static string ProviderLinks(IReadOnlyList<string> providers)
    {
        var links = new StringBuilder();
        foreach (string provider in providers)
        {
            links.Append("<a class=\"floor-provider\" href=\"/authorize/").Append(WebUtility.HtmlEncode(provider))
                .Append("\">Continue with ").Append(WebUtility.HtmlEncode(ProviderPages.DisplayName(provider)))
                .Append("</a>");
        }
        return links.ToString();
    }
}
