using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Caching.Memory;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// What Discord says about the access tokens applications exchange here, remembered for a while.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why it remembers.</b> An Activity holds one Discord token for as long as it runs and exchanges it
/// again before every five-minute application token runs out, so every viewer would ask Discord the same
/// question every few minutes. Discord's answer for a token does not change while the token lives, short
/// of its revocation.
/// </para>
/// <para>
/// <b>The rule.</b> An answer is held under the SHA-256 of the token — never the token itself — for the
/// token's remaining life, capped at <see cref="AnchorOptions.DiscordTokenCache"/>. The cap is how long a
/// token revoked at Discord is still accepted here. A refusal and an outage are never held: the next
/// exchange asks again. The cache is bounded by entry count, and when it is full an answer simply is not
/// held.
/// </para>
/// <para>
/// Every question goes to Discord through <see cref="DiscordDirectory.ReadAuthorizationAsync"/>, on the
/// directory's typed client, created per question so the factory keeps rotating its handler.
/// </para>
/// </remarks>
internal sealed class DiscordAuthorizations(IHttpClientFactory httpClientFactory, AnchorOptions options) : IDisposable
{
    /// <summary>The most answers held at once.</summary>
    internal const int Capacity = 10_000;

    private readonly MemoryCache _held = new(new MemoryCacheOptions { SizeLimit = Capacity });

    /// <summary>
    /// What Discord says about <paramref name="accessToken"/>, or null when Discord does not honour it as
    /// a token naming a user. Throws <see cref="DiscordAuthException"/> when Discord could not be asked.
    /// </summary>
    public async Task<DiscordAuthorization?> ReadAsync(string accessToken, CancellationToken ct)
    {
        string key = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));
        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (_held.TryGetValue(key, out DiscordAuthorization? held) && held is not null && held.Expires > now)
            return held;

        DiscordAuthorization? answer = await DiscordDirectory.ReadAuthorizationAsync(
            httpClientFactory.CreateClient(nameof(DiscordDirectory)), accessToken, ct);
        if (answer is null)
            return null;

        DateTimeOffset until = answer.Expires < now + options.DiscordTokenCache ? answer.Expires : now + options.DiscordTokenCache;
        if (until > now)
            _held.Set(key, answer, new MemoryCacheEntryOptions { AbsoluteExpiration = until, Size = 1 });

        return answer;
    }

    public void Dispose() => _held.Dispose();
}
