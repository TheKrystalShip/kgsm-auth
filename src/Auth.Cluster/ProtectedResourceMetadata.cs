using System.Text;
using System.Text.Json;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// What a member says about who signs its sessions (RFC 9728): the document a browser surface reads
/// from the origin that served it to find its sign-in provider.
/// </summary>
/// <remarks>
/// <para>
/// <b>Public, and deliberately so.</b> The provider is reached by browsers, so its name is already in
/// public DNS and in certificate transparency logs; naming it to anybody who asks gives away nothing a
/// search does not, and in exchange a surface needs no build per cluster and no address to remember.
/// Nothing else is said — no account, no session, no roster.
/// </para>
/// <para>
/// <b>Only an issuer that is a URL is named.</b> A cluster whose anchor states anything else has no
/// provider a browser can be sent to, and the member says so rather than handing a surface a value it
/// would try to navigate to.
/// </para>
/// </remarks>
public static class ProtectedResourceMetadata
{
    /// <summary>Where the document is served on every member.</summary>
    public const string Path = "/.well-known/oauth-protected-resource";

    /// <summary>
    /// The document naming <paramref name="issuer"/> as the provider for <paramref name="resource"/>, or
    /// null when <paramref name="issuer"/> is not a provider a browser can be sent to.
    /// </summary>
    /// <param name="resource">The origin the document was asked for at.</param>
    /// <param name="issuer">The issuer this member verifies cluster sessions against.</param>
    public static string? Document(string resource, string? issuer)
    {
        if (!IsProvider(issuer))
            return null;

        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteString("resource", resource);
            json.WriteStartArray("authorization_servers");
            json.WriteStringValue(issuer);
            json.WriteEndArray();
            json.WriteStartArray("bearer_methods_supported");
            json.WriteStringValue("header");
            json.WriteEndArray();
            json.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>The answer when there is no provider to name.</summary>
    public static string NoProvider { get; } =
        """{"error":"no_issuer","error_description":"This member knows of no sign-in provider for its cluster yet."}""";

    /// <summary>Whether <paramref name="issuer"/> is an address a browser can be sent to sign in at.</summary>
    public static bool IsProvider(string? issuer) =>
        Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
        && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);
}
