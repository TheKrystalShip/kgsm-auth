using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace TheKrystalShip.KGSM.Auth.Discord;

/// <summary>
/// A Discord identity verified once at login. The caller's OAuth token is used for exactly one call
/// (<c>/users/@me</c>) and discarded — no KGSM surface retains a Discord token — so the profile here
/// is a snapshot taken at login, not something that can be re-read later.
/// </summary>
public sealed record DiscordIdentity(
    string UserId,
    string Username,
    string Display,
    string? AvatarUrl,
    IReadOnlyList<string> Scopes);

/// <summary>
/// The outcome of a login: the verified identity plus the tier this host grants it.
/// <see cref="KgsmTier.None"/> means "we know who you are, and you have no access here" — a terminal
/// denial, distinct from a failure to find out.
/// </summary>
public sealed record ResolvedPrincipal(DiscordIdentity Identity, KgsmTier Tier);

/// <summary>
/// Discord could not be reached, or answered in a way that leaves authority unknown. The caller
/// surfaces this as an upstream error (<c>502</c>) and <b>never</b> as a denial or a default grant:
/// "we could not ask" is a different fact from "the answer is no", and collapsing them either locks
/// out a legitimate admin during an outage or, far worse, admits someone during one.
/// </summary>
public sealed class DiscordAuthException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>This surface's own OAuth endpoint details — not shared, because every surface has its own.</summary>
/// <param name="RedirectUri">
/// Where Discord returns the browser. Must match a redirect registered on the application exactly.
/// </param>
/// <param name="Scopes">
/// What sign-in asks for. <c>identify</c> is enough: roles are never in the user's token and are read
/// with the bot token instead.
/// </param>
public sealed record DiscordOAuthEndpoints(string RedirectUri, string Scopes = "identify");

/// <summary>
/// The one chokepoint to <c>discord.com</c>. Everything a KGSM surface asks Discord goes through
/// here, which is what makes the whole authorization surface — the callback verdict, the tier gate,
/// the 401/403 matrix — testable in-process against a fake.
/// </summary>
public interface IDiscordDirectory
{
    /// <summary>
    /// The authorize URL to send the browser to. <paramref name="codeChallenge"/> is the PKCE
    /// challenge from <see cref="OAuthHandshake.CodeChallenge"/>; <paramref name="prompt"/> is
    /// <c>none</c> for silent SSO or <c>consent</c> for the interactive fallback.
    /// </summary>
    string BuildAuthorizeUrl(string state, string codeChallenge, string prompt);

    /// <summary>
    /// Exchange the code for an identity and resolve the tier this host grants it.
    /// <para>
    /// Returns <see langword="null"/> when the code itself is bad — expired, replayed, or issued to
    /// another client — which is a client-recoverable problem, not a server one. Throws
    /// <see cref="DiscordAuthException"/> when Discord is unreachable or answers unusably. A
    /// successful return may still carry <see cref="KgsmTier.None"/>: identity verified, no access
    /// here.
    /// </para>
    /// </summary>
    Task<ResolvedPrincipal?> ResolveAsync(string code, string codeVerifier, CancellationToken ct);

    /// <summary>
    /// The guild roles a user holds, by user id, read with the bot token. <see langword="null"/> means
    /// <b>not a member of the guild</b>; an empty list means a member holding only <c>@everyone</c>.
    /// Those are different answers and the tier depends on which it is.
    /// </summary>
    Task<IReadOnlyList<string>?> GetGuildRolesAsync(string userId, CancellationToken ct);
}

/// <summary>
/// The real <see cref="IDiscordDirectory"/>. Exchanges the OAuth code, verifies identity once, then
/// reads the member's roles with the <b>bot token</b> — the only path to roles, because the
/// <c>identify</c> scopes a user grants do not carry them. Holding a bot token here is shared
/// external configuration, not a dependency on whatever else uses the same application.
/// </summary>
public sealed class DiscordDirectory(
    HttpClient http,
    KgsmAuthOptions auth,
    DiscordOAuthEndpoints endpoints,
    KgsmRoleMap roleMap) : IDiscordDirectory
{
    private const string ApiBase = "https://discord.com/api";

    public string BuildAuthorizeUrl(string state, string codeChallenge, string prompt)
    {
        Dictionary<string, string?> query = new()
        {
            ["client_id"] = auth.ClientId,
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

    public async Task<ResolvedPrincipal?> ResolveAsync(string code, string codeVerifier, CancellationToken ct)
    {
        string? userToken = await ExchangeCodeAsync(code, codeVerifier, ct);
        if (userToken is null)
            return null;

        // The caller's token buys exactly one thing — a verified user id — and is then dropped.
        DiscordIdentity identity = await FetchIdentityAsync(userToken, ct);

        IReadOnlyList<string>? roles = await GetGuildRolesAsync(identity.UserId, ct);
        return new ResolvedPrincipal(identity, roleMap.Resolve(roles));
    }

    public async Task<IReadOnlyList<string>?> GetGuildRolesAsync(string userId, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"{ApiBase}/guilds/{auth.GuildId}/members/{userId}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bot", auth.BotToken);

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new DiscordAuthException("Discord guild-member endpoint unreachable.", ex);
        }

        using (response)
        {
            // Not a member of this guild. A real verdict, not an error — and deliberately NOT the same
            // as a member with an empty roles array, which floors at viewer.
            if (response.StatusCode is HttpStatusCode.NotFound)
                return null;

            // Rate-limited, or anything else unexpected: authority is unknown. Throwing keeps the
            // caller from reading a failure as an absence of roles and quietly granting the floor.
            if (!response.IsSuccessStatusCode)
                throw new DiscordAuthException(
                    $"Discord guild-member lookup returned {(int)response.StatusCode}.");

            string json = await response.Content.ReadAsStringAsync(ct);
            using JsonDocument doc = SafeParse(json);

            if (!doc.RootElement.TryGetProperty("roles", out JsonElement roles)
                || roles.ValueKind != JsonValueKind.Array)
                return [];

            return [.. roles.EnumerateArray()
                .Select(r => r.GetString())
                .Where(s => !string.IsNullOrEmpty(s))
                .Select(s => s!)];
        }
    }

    private async Task<string?> ExchangeCodeAsync(string code, string codeVerifier, CancellationToken ct)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = auth.ClientId,
            ["client_secret"] = auth.ClientSecret,
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

    private async Task<DiscordIdentity> FetchIdentityAsync(string userToken, CancellationToken ct)
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

            return new DiscordIdentity(
                userId,
                username,
                display,
                avatarHash is null ? null : $"https://cdn.discordapp.com/avatars/{userId}/{avatarHash}.png",
                [.. endpoints.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)]);
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
