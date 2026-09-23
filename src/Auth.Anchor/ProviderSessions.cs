using System.Security.Cryptography;
using System.Text;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The two cookies the provider keeps on its own origin, and how they are written.
/// </summary>
/// <remarks>
/// <para>
/// Both are <c>HttpOnly; SameSite=Lax; Path=/</c>. Every arrival at the provider is a top-level
/// navigation, which is exactly what <c>Lax</c> sends a cookie on, so no shared registrable domain with
/// any client is needed. <c>Secure</c> whenever the provider is reached over TLS, read from the scheme the
/// browser spoke rather than the loopback hop behind the proxy.
/// </para>
/// <para>
/// Each carries a random secret and nothing else. The row it names is found by the secret's hash, so a
/// copy of the database is not a set of cookies anybody can present.
/// </para>
/// </remarks>
internal static class ProviderCookies
{
    /// <summary>A browser's sign-in at the provider.</summary>
    public const string Session = "kgsm_anchor";

    /// <summary>The authorization request this browser has in flight.</summary>
    public const string Request = "kgsm_authz";

    /// <summary>How long a request in flight is held.</summary>
    public static readonly TimeSpan RequestLifetime = TimeSpan.FromMinutes(10);

    public static CookieOptions Options(HttpContext ctx, TimeSpan maxAge) => new()
    {
        HttpOnly = true,
        Secure = IsTls(ctx),
        SameSite = SameSiteMode.Lax,
        Path = "/",
        MaxAge = maxAge,
    };

    public static bool IsTls(HttpContext ctx) =>
        ctx.Request.IsHttps
        || string.Equals(ctx.Request.Headers["X-Forwarded-Proto"], "https", StringComparison.Ordinal);

    /// <summary>A fresh secret: 256 bits, base64url.</summary>
    public static string NewSecret() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>What a secret is stored as.</summary>
    public static string Hash(string secret) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
}

/// <summary>
/// A browser's sign-in at the provider: the session its <c>kgsm_anchor</c> cookie names, which lets a
/// second surface obtain a session without a credential.
/// </summary>
/// <remarks>
/// <para>
/// <b>One provider session per browser, and every session minted through it records it.</b> That is
/// what keeps the set coherent: a second credential for the same account proves the same provider
/// session again and strands nothing, a credential for a different account ends the old one and
/// everything minted under it, and ending it ends all of them. Without the column a sign-out ends one
/// surface and leaves a sibling live — or leaves the cookie standing, and the next bounce silently signs
/// the person back in, which no log records as anything but a successful sign-in.
/// </para>
/// <para>
/// It lives the refresh lifetime from the last credential. Being recognised extends nothing: the cookie
/// is proof that a browser signed in within that window, not that the person in front of it is the one
/// who did.
/// </para>
/// </remarks>
internal sealed class ProviderSessions(
    SqliteSessionRegistry registry,
    AnchorOptions options,
    IUserStore store,
    ISessionValidator validator,
    ReauthGate gate,
    SessionBroadcast broadcast,
    AnchorJournal journal)
{
    /// <summary>The live provider session this browser's cookie names, or null.</summary>
    public async Task<ProviderSessionRow?> CurrentAsync(HttpContext ctx)
    {
        string? secret = ctx.Request.Cookies[ProviderCookies.Session];
        if (string.IsNullOrEmpty(secret))
            return null;

        return await registry.FindProviderSessionByCookieAsync(ProviderCookies.Hash(secret), ctx.RequestAborted)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Record that <paramref name="identity"/> just proved <paramref name="user"/> on this browser.
    /// </summary>
    /// <remarks>
    /// The same account proves its provider session again, keeping every session under it. A different
    /// account ends the old provider session and everything minted under it before starting its own, so
    /// one browser never holds two people's sign-ins at once.
    /// </remarks>
    public async Task<ProviderSessionRow> EstablishAsync(HttpContext ctx, KgsmIdentity identity, KgsmUser user)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset expires = now.Add(options.RefreshLifetime);
        StoredIdentity stored = StoredIdentity.From(identity);

        if (await CurrentAsync(ctx).ConfigureAwait(false) is { } current)
        {
            KgsmUser? holder = await store.FindByCredentialAsync(current.Handle, ctx.RequestAborted).ConfigureAwait(false);
            if (holder is not null && string.Equals(holder.UserId, user.UserId, StringComparison.Ordinal)
                && await registry.ReproveProviderSessionAsync(
                    current.SessionId, identity.Handle, stored.ToJson(), now, expires, ctx.RequestAborted).ConfigureAwait(false))
            {
                // The cookie is written again for its new lifetime; its secret is unchanged, because the
                // row it names is the same sign-in.
                ctx.Response.Cookies.Append(ProviderCookies.Session, ctx.Request.Cookies[ProviderCookies.Session]!,
                    ProviderCookies.Options(ctx, options.RefreshLifetime));
                return current with { Handle = identity.Handle, Identity = stored, Expires = expires, CredentialAt = now };
            }

            await EndAsync(ctx, current.SessionId).ConfigureAwait(false);
        }

        string sessionId = Endpoints.NewSessionId();
        string secret = ProviderCookies.NewSecret();

        await registry.CreateProviderSessionAsync(
            sessionId, identity.Handle, stored.ToJson(), ProviderCookies.Hash(secret), options.ClusterId,
            now, expires, Endpoints.UserAgentOf(ctx), ctx.RequestAborted).ConfigureAwait(false);

        ctx.Response.Cookies.Append(ProviderCookies.Session, secret, ProviderCookies.Options(ctx, options.RefreshLifetime));
        return new ProviderSessionRow(sessionId, identity.Handle, stored, now, expires, now);
    }

    /// <summary>
    /// End a provider session and every session minted under it, on every member.
    /// </summary>
    /// <remarks>
    /// Each surface session is announced over the bus the deny-list rides, because it is accepted on every
    /// member and has a row only here. The provider session itself is never a bearer anywhere, so it is
    /// ended here and announced nowhere.
    /// </remarks>
    /// <returns>How many surface sessions ended.</returns>
    public async Task<int> EndAsync(HttpContext ctx, string providerSession)
    {
        IReadOnlyList<(string SessionId, string Handle, bool Provider)> ended =
            await registry.EndProviderSessionAsync(providerSession, ctx.RequestAborted).ConfigureAwait(false);

        var accounts = new Dictionary<string, KgsmUser?>(StringComparer.Ordinal);
        int surfaces = 0;

        foreach ((string sid, string handle, bool provider) in ended)
        {
            validator.Evict(sid);
            gate.Forget(sid);
            if (provider)
                continue;

            surfaces++;
            await broadcast.RevokedAsync(sid, ctx.RequestAborted).ConfigureAwait(false);

            if (!accounts.TryGetValue(handle, out KgsmUser? user))
            {
                user = await store.FindByCredentialAsync(handle, ctx.RequestAborted).ConfigureAwait(false);
                accounts[handle] = user;
            }

            string username = user?.Username ?? handle;
            string providerName = KgsmActor.TryParse(handle, out string p, out _) ? p : handle;
            await journal.SessionAsync(
                AuthEvents.SignedOut,
                userId: user?.UserId,
                username: username,
                identity: handle,
                provider: providerName,
                tier: null,
                sid: sid,
                userAgent: Endpoints.UserAgentOf(ctx),
                actor: KgsmActor.Format(providerName, username),
                origin: AnchorJournal.OriginUi,
                ct: ctx.RequestAborted).ConfigureAwait(false);
        }

        return surfaces;
    }

    /// <summary>Tell the browser to forget its sign-in here.</summary>
    public void ClearCookie(HttpContext ctx) =>
        ctx.Response.Cookies.Delete(ProviderCookies.Session, ProviderCookies.Options(ctx, TimeSpan.Zero));
}
