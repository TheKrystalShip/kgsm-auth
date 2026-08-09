using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace TheKrystalShip.KGSM.Auth.Discord;

/// <summary>
/// Discord could not be reached, or answered in a way that leaves authority unknown. The caller
/// surfaces this as an upstream error (<c>502</c>) and <b>never</b> as a denial or a default grant:
/// "we could not ask" is a different fact from "the answer is no", and collapsing them either locks
/// out a legitimate admin during an outage or, far worse, admits someone during one.
/// </summary>
/// <remarks>
/// A <see cref="KgsmAuthProviderException"/>, so a caller that handles any provider's outage the same
/// way catches the base type and needs to know nothing about Discord.
/// </remarks>
public sealed class DiscordAuthException(string message, Exception? inner = null)
    : KgsmAuthProviderException(message, inner);

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
/// <para>
/// It answers both halves of a login for this provider: <see cref="IIdentityProvider"/> verifies who
/// someone is by exchanging the OAuth code, and <see cref="IAuthorityProvider"/> says what they may
/// do by reading their guild roles with the <b>bot token</b> — the only path to roles, because the
/// <c>identify</c> scopes a user grants do not carry them. Implementing the two separately is what
/// lets a host keep Discord as its login while taking authority from somewhere else.
/// </para>
/// </summary>
/// <remarks>
/// Holding a bot token here is shared external configuration, not a dependency on whatever else uses
/// the same application.
/// </remarks>
public sealed class DiscordDirectory(
    HttpClient http,
    KgsmAuthOptions auth,
    DiscordOAuthEndpoints endpoints,
    KgsmRoleMap roleMap) : IIdentityProvider, IAuthorityProvider
{
    private const string ApiBase = "https://discord.com/api";

    public string Provider => KgsmActorProvider.Discord;

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

    public async Task<KgsmIdentity?> VerifyAsync(string code, string codeVerifier, CancellationToken ct)
    {
        string? userToken = await ExchangeCodeAsync(code, codeVerifier, ct);
        if (userToken is null)
            return null;

        // The caller's token buys exactly one thing — a verified user id — and is then dropped.
        return await FetchIdentityAsync(userToken, ct);
    }

    /// <summary>
    /// The tier this host grants, from the caller's guild roles. Not being a member of the guild is
    /// the access gate and resolves to <see cref="KgsmTier.None"/>; a member holding only
    /// <c>@everyone</c> floors at <see cref="KgsmTier.Viewer"/>. A lookup that fails throws rather
    /// than returning either, so an outage is never read as a verdict.
    /// </summary>
    public async Task<KgsmTier> ResolveTierAsync(KgsmIdentity identity, CancellationToken ct) =>
        roleMap.Resolve(await GetGuildRolesAsync(identity.Subject, ct));

    /// <summary>
    /// The guild roles a user holds, by user id, read with the bot token. <see langword="null"/> means
    /// <b>not a member of the guild</b>; an empty list means a member holding only <c>@everyone</c>.
    /// Those are different answers and the tier depends on which it is.
    /// </summary>
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
