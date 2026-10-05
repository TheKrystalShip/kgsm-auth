using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// Discord could not be reached, or answered in a way that leaves authority unknown. The caller
/// surfaces this as an upstream error (<c>502</c>) and <b>never</b> as a denial or a default grant:
/// "we could not ask" is a different fact from "the answer is no", and collapsing them either locks
/// out the Owner during an outage or, far worse, admits someone during one.
/// </summary>
/// <remarks>
/// A <see cref="KgsmAuthProviderException"/>, so a caller that handles any provider's outage the same
/// way catches the base type and needs to know nothing about Discord.
/// </remarks>
public sealed class DiscordAuthException(string message, Exception? inner = null)
    : KgsmAuthProviderException(message, inner);

/// <summary>Where this anchor's Discord round trip returns, and what it asks for.</summary>
/// <param name="RedirectUri">
/// Where Discord returns the browser. Must match a redirect registered on the application exactly.
/// </param>
/// <param name="Scopes">
/// What sign-in asks for. <c>identify</c> is enough: a login establishes who someone is and nothing
/// else, and no scope Discord can grant says what they may do on a KGSM host.
/// </param>
public sealed record DiscordOAuthEndpoints(string RedirectUri, string Scopes = "identify");

/// <summary>What Discord says about one of its access tokens.</summary>
/// <param name="ApplicationId">The Discord application the token was issued to.</param>
/// <param name="Identity">The Discord user it belongs to, as <c>discord:&lt;id&gt;</c>.</param>
/// <param name="Expires">When Discord stops honouring it.</param>
public sealed record DiscordAuthorization(string ApplicationId, KgsmIdentity Identity, DateTimeOffset Expires);

/// <summary>The body of Discord's <c>GET /oauth2/@me</c>, as much of it as is read.</summary>
internal sealed record DiscordAuthorizationWire(
    [property: JsonPropertyName("application")] DiscordApplicationWire? Application,
    [property: JsonPropertyName("scopes")] IReadOnlyList<string>? Scopes,
    [property: JsonPropertyName("expires")] DateTimeOffset? Expires,
    [property: JsonPropertyName("user")] DiscordUserWire? User);

/// <summary>The application a Discord token was issued to.</summary>
internal sealed record DiscordApplicationWire([property: JsonPropertyName("id")] string? Id);

/// <summary>The user a Discord token belongs to, present when it carries <c>identify</c>.</summary>
internal sealed record DiscordUserWire(
    [property: JsonPropertyName("id")] string? Id,
    [property: JsonPropertyName("username")] string? Username,
    [property: JsonPropertyName("global_name")] string? GlobalName,
    [property: JsonPropertyName("avatar")] string? Avatar);

/// <summary>Serializer metadata for what is read from Discord, so nothing is reflected over under AOT.</summary>
[JsonSerializable(typeof(DiscordAuthorizationWire))]
internal sealed partial class DiscordJsonContext : JsonSerializerContext;

/// <summary>
/// The one chokepoint to <c>discord.com</c>. Everything the anchor asks Discord goes through here,
/// which is what makes a provider sign-in testable in-process against a fake.
/// <para>
/// It answers <b>one</b> half of a login: <see cref="IIdentityProvider"/> verifies who someone is by
/// exchanging the OAuth code. What they may do is the account store's answer and only its answer, so
/// a Discord account here is one way to prove you are a KGSM account — the same thing a password is,
/// and the same thing every other provider will be.
/// </para>
/// </summary>
public sealed class DiscordDirectory(
    HttpClient http,
    KgsmOAuthApplication application,
    DiscordOAuthEndpoints endpoints) : IIdentityProvider
{
    private const string ApiBase = "https://discord.com/api";

    public string Provider => KgsmActorProvider.Discord;

    public string BuildAuthorizeUrl(string state, string codeChallenge, string prompt)
    {
        Dictionary<string, string?> query = new()
        {
            ["client_id"] = application.ClientId,
            ["redirect_uri"] = endpoints.RedirectUri,
            ["response_type"] = "code",
            ["scope"] = endpoints.Scopes,
            ["state"] = state,
            ["prompt"] = prompt is "consent" ? "consent" : "none",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
        };

        string encoded = string.Join('&', query.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value ?? "")}"));
        return $"{ApiBase}/oauth2/authorize?{encoded}";
    }

    public async Task<KgsmIdentity?> VerifyAsync(string code, string codeVerifier, CancellationToken ct)
    {
        string? userToken = await ExchangeCodeAsync(code, codeVerifier, ct);
        if (userToken is null)
            return null;

        // The caller's token buys exactly one thing — a verified user id — and is then dropped.
        return await FetchIdentityAsync(userToken, ct);
    }

    private async Task<string?> ExchangeCodeAsync(string code, string codeVerifier, CancellationToken ct)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = application.ClientId,
            ["client_secret"] = application.ClientSecret,
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = endpoints.RedirectUri,
            ["code_verifier"] = codeVerifier,
        });

        HttpResponseMessage response;
        try
        {
            response = await http.PostAsync($"{ApiBase}/oauth2/token", form, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new DiscordAuthException("Discord token endpoint unreachable.", ex);
        }

        using (response)
        {
            if (response.StatusCode >= HttpStatusCode.InternalServerError)
                throw new DiscordAuthException($"Discord token endpoint returned {(int)response.StatusCode}.");

            // 4xx: the code is invalid, expired or already used. The caller's problem to retry.
            if (!response.IsSuccessStatusCode)
                return null;

            string json = await response.Content.ReadAsStringAsync(ct);
            using JsonDocument doc = SafeParse(json);
            return doc.RootElement.TryGetProperty("access_token", out JsonElement token)
                ? token.GetString()
                : null;
        }
    }

    private async Task<KgsmIdentity> FetchIdentityAsync(string userToken, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{ApiBase}/users/@me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userToken);

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new DiscordAuthException("Discord users/@me endpoint unreachable.", ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
                throw new DiscordAuthException($"Discord users/@me returned {(int)response.StatusCode}.");

            string json = await response.Content.ReadAsStringAsync(ct);
            using JsonDocument doc = SafeParse(json);
            JsonElement me = doc.RootElement;

            string userId = GetString(me, "id")
                ?? throw new DiscordAuthException("Discord users/@me carried no id.");
            string username = GetString(me, "username") ?? userId;
            string display = GetString(me, "global_name") ?? username;
            string? avatarHash = GetString(me, "avatar");

            return new KgsmIdentity(
                KgsmActorProvider.Discord,
                userId,
                username,
                display,
                avatarHash is null ? null : $"https://cdn.discordapp.com/avatars/{userId}/{avatarHash}.png",
                [.. endpoints.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)]);
        }
    }

    /// <summary>
    /// Who a Discord access token belongs to and which Discord application issued it, as Discord's
    /// <c>GET /oauth2/@me</c> answers for the bearer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It needs no application of this provider's: the token is its own credential, issued to somebody
    /// else's Discord application, and this provider never holds that application's secret. That is why
    /// it is static and takes only the typed client.
    /// </para>
    /// <para>
    /// <b>A token Discord refuses is <see langword="null"/>; an outage throws.</b> A <c>401</c> or
    /// <c>403</c> is a token that is expired, revoked or forged — the caller's problem. A token without the
    /// <c>identify</c> scope names no user, and is the same answer: it cannot say who it belongs to. A
    /// <c>5xx</c>, a rate limit, an unreachable host or an unreadable body is
    /// <see cref="DiscordAuthException"/>: "we could not ask" is not "the answer is no".
    /// </para>
    /// </remarks>
    public static async Task<DiscordAuthorization?> ReadAuthorizationAsync(
        HttpClient http, string accessToken, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{ApiBase}/oauth2/@me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new DiscordAuthException("Discord oauth2/@me endpoint unreachable.", ex);
        }

        using (response)
        {
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return null;
            if (!response.IsSuccessStatusCode)
                throw new DiscordAuthException($"Discord oauth2/@me returned {(int)response.StatusCode}.");

            DiscordAuthorizationWire? wire;
            try
            {
                wire = JsonSerializer.Deserialize(
                    await response.Content.ReadAsStringAsync(ct), DiscordJsonContext.Default.DiscordAuthorizationWire);
            }
            catch (JsonException ex)
            {
                throw new DiscordAuthException("Discord returned malformed JSON.", ex);
            }

            if (wire?.Application?.Id is not { Length: > 0 } applicationId || wire.Expires is not { } expires)
                throw new DiscordAuthException("Discord oauth2/@me named no application or expiry.");
            if (wire.User?.Id is not { Length: > 0 } userId)
                return null;

            string username = wire.User.Username ?? userId;
            return new DiscordAuthorization(
                applicationId,
                new KgsmIdentity(
                    KgsmActorProvider.Discord,
                    userId,
                    username,
                    wire.User.GlobalName ?? username,
                    wire.User.Avatar is { } avatar ? $"https://cdn.discordapp.com/avatars/{userId}/{avatar}.png" : null,
                    [.. wire.Scopes ?? []]),
                expires);
        }
    }

    private static JsonDocument SafeParse(string json)
    {
        try
        {
            return JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new DiscordAuthException("Discord returned malformed JSON.", ex);
        }
    }

    private static string? GetString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;
}
