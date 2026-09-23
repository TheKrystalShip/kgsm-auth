using System.Text.Json;
using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Sessions;

/// <summary>
/// A browser surface a member serves, announced so the cluster's sign-in provider will send people back
/// to it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Paths, never URLs.</b> The provider joins each one to the browser address the member's own roster
/// row carries, so a member can only ever announce somewhere on the address the cluster already hands out
/// for it. A member announcing full URLs could name any origin on the internet as a place codes are sent.
/// </para>
/// <para>
/// The client id is the announcing member's id. One member serves at most one surface; a second is a
/// second member or a client an administrator registers.
/// </para>
/// </remarks>
/// <param name="Name">What a person is shown on the sign-in page: whose sign-in they are completing.</param>
/// <param name="RedirectPaths">Where on the member's address a code may be sent, each beginning with <c>/</c>.</param>
/// <param name="PostLogoutRedirectPaths">Where on it a signed-out browser may be returned.</param>
public sealed record ClusterClientAnnouncement(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("redirectPaths")] IReadOnlyList<string> RedirectPaths,
    [property: JsonPropertyName("postLogoutRedirectPaths")] IReadOnlyList<string> PostLogoutRedirectPaths)
{
    /// <summary>
    /// The published fact a member states its surface under. Read by the sign-in provider off every
    /// member's row, which is the opposite direction from <see cref="ClusterAuthFacts"/>.
    /// </summary>
    public const string FactKey = "auth.client";

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

/// <summary>Serializer metadata for a client announcement.</summary>
[JsonSerializable(typeof(ClusterClientAnnouncement))]
public sealed partial class ClusterClientJsonContext : JsonSerializerContext;
