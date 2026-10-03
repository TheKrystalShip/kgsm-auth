using System.Text.Json;
using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// A browser surface a member serves, announced so the cluster's sign-in provider will send people back
/// to it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Paths, never URLs.</b> The provider joins each one to a browser address the member's own roster
/// row carries, so a member can only ever announce somewhere on an address the cluster already hands out
/// for it. A member announcing full URLs could name any origin on the internet as a place codes are sent.
/// </para>
/// <para>
/// <b>Which of those addresses, the member says.</b> A roster row keeps every address a member was ever
/// reached at, including names since taken away, so a surface is registered at the addresses in
/// <see cref="Addresses"/> that the row also carries — the names it serves now — and, when it names none
/// of them, at the row's browser address alone.
/// </para>
/// <para>
/// The client id is <see cref="ClientIdFor"/> each such address. One member serves at most one surface,
/// reachable at each of its names; a second surface is a second member or a client registered at the
/// anchor.
/// </para>
/// </remarks>
/// <param name="Name">What a person is shown on the sign-in page: whose sign-in they are completing.</param>
/// <param name="RedirectPaths">Where on the member's address a code may be sent, each beginning with <c>/</c>.</param>
/// <param name="PostLogoutRedirectPaths">Where on it a signed-out browser may be returned.</param>
/// <param name="Addresses">
/// The browser addresses the surface is served at, as origins. Null or empty means the row's browser
/// address alone.
/// </param>
public sealed record ClusterClientAnnouncement(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("redirectPaths")] IReadOnlyList<string> RedirectPaths,
    [property: JsonPropertyName("postLogoutRedirectPaths")] IReadOnlyList<string> PostLogoutRedirectPaths,
    [property: JsonPropertyName("addresses"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<string>? Addresses = null)
{
    /// <summary>
    /// This announcement served at <paramref name="addresses"/>: each reduced to its origin, unusable ones
    /// dropped, de-duplicated and sorted so the same set always publishes the same fact.
    /// </summary>
    public ClusterClientAnnouncement At(IEnumerable<string> addresses)
    {
        string[] origins = [.. addresses
            .Select(ClusterClientOrigins.Normalize).OfType<string>()
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        return this with { Addresses = origins.Length == 0 ? null : origins };
    }

    /// <summary>
    /// The published fact a member states its surface under. Read by the sign-in provider off every
    /// member's row, which is the opposite direction from <see cref="ClusterAuthFacts"/>.
    /// </summary>
    public const string FactKey = "auth.client";

    /// <summary>
    /// The Control Panel, wherever it is served: a node announcing the one it serves, and the provider
    /// registering one it is told a static host serves. One statement of where the panel lands, so the
    /// two can never send a browser to different paths.
    /// </summary>
    public static ClusterClientAnnouncement ControlPanel { get; } = new("Control Panel", ["/signed-in"], ["/"]);

    /// <summary>
    /// The client id of the surface served at <paramref name="origin"/>: its host, lowercased, with
    /// <c>-&lt;port&gt;</c> when the origin names one — or null when the origin is not one a client can
    /// live at.
    /// </summary>
    /// <remarks>
    /// A surface derives its own id from where it was loaded, so it is told nothing before it signs in
    /// and a panel on a static host signs in through a member that never served it. The provider derives
    /// the same string from a member's browser address and from a declared panel's origin, which is the
    /// whole agreement: one rule, applied at both ends.
    /// </remarks>
    public static string? ClientIdFor(string? origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            || uri.HostNameType == UriHostNameType.IPv6)
            return null;

        string host = uri.Host.ToLowerInvariant();
        return uri.IsDefaultPort ? host : $"{host}-{uri.Port}";
    }

    /// <summary>The fact's value.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, ClusterClientJsonContext.Default.ClusterClientAnnouncement);

    /// <summary>An announcement read back out of a fact, or null when the value is not one.</summary>
    public static ClusterClientAnnouncement? Read(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;

        try
        {
            return JsonSerializer.Deserialize(json, ClusterClientJsonContext.Default.ClusterClientAnnouncement);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// The value of <see cref="ClusterAuthFacts.ClientOrigins"/>: every origin a registered client lives at.
/// </summary>
/// <remarks>
/// Written by the provider, read by every member through the holder. Sorted and de-duplicated on the
/// way out so an unchanged registry publishes an unchanged fact, and read back tolerantly — an entry
/// that is not an origin is dropped rather than failing the whole value, because a member must not stop
/// admitting every client over one it cannot read.
/// </remarks>
public static class ClusterClientOrigins
{
    /// <summary>The fact's value for <paramref name="origins"/>.</summary>
    public static string ToJson(IEnumerable<string> origins) =>
        JsonSerializer.Serialize(
            origins.Select(Normalize).OfType<string>().Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
            ClusterClientJsonContext.Default.StringArray);

    /// <summary>The origins a fact names; empty when it names none or is not one.</summary>
    public static IReadOnlyList<string> Read(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];

        try
        {
            return JsonSerializer.Deserialize(json, ClusterClientJsonContext.Default.StringArray) is { } values
                ? [.. values.Select(Normalize).OfType<string>().Distinct(StringComparer.Ordinal)]
                : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>
    /// <paramref name="value"/> as a browser sends it in <c>Origin</c> — scheme, host and a non-default
    /// port, lowercased, no slash — or null when it is not an http(s) origin.
    /// </summary>
    public static string? Normalize(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            ? uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant()
            : null;
}

/// <summary>Serializer metadata for a client announcement and the origins fact.</summary>
[JsonSerializable(typeof(ClusterClientAnnouncement))]
[JsonSerializable(typeof(string[]))]
public sealed partial class ClusterClientJsonContext : JsonSerializerContext;
