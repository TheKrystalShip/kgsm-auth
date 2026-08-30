using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

using TheKrystalShip.KGSM.Auth;
using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The anchor's HTTP surface: signing in, keeping a session, and reading the accounts.
/// </summary>
/// <remarks>
/// <para>
/// Every handler is a plain <see cref="RequestDelegate"/> that reads its own request and writes its
/// own response. The convenient routing overloads bind an arbitrary delegate's parameters by
/// reflecting over them, which no Native-AOT service can do — and the failure appears at publish
/// time rather than at build time, so it is avoided by construction rather than caught.
/// </para>
/// <para>
/// Bodies are deserialized through <see cref="AnchorJsonContext"/> for the same reason: there is no
/// reflection fallback, so every shape on the wire is one this assembly generated metadata for.
/// </para>
/// </remarks>
internal static class Endpoints
{
    /// <summary>The largest body any of these endpoints accepts.</summary>
    /// <remarks>
    /// A sign-in is a username and a password. A cap this size costs nothing legitimate and stops an
    /// unauthenticated caller from making this daemon buffer whatever it feels like sending.
    /// </remarks>
    private const int MaxBodyBytes = 8 * 1024;

    /// <summary>
    /// Whether this anchor may answer as the cluster's account authority, with the refusal already
    /// written when it may not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A member standing by is not broken and not denying anybody — it is not the authority, and the
    /// sessions it could mint would be signed with a key no member verifies against. So it answers
    /// <c>503</c> and names the holder, which reads as an outage with a cause rather than as a
    /// denial, and tells an operator where to go.
    /// </para>
    /// <para>
    /// A standalone install never reaches this: with no cluster there is no assignment, this anchor
    /// holds the machine's accounts, and every door is open exactly as it was.
    /// </para>
    /// </remarks>
    private static async Task<bool> RequireAuthorityAsync(HttpContext ctx)
    {
        var role = ctx.RequestServices.GetRequiredService<AnchorRole>();
        if (role.IsAuthority)
            return true;

        // Named so a client can route to the member that can actually answer, rather than retrying
        // against one that never will.
        if (role.Holder is { Length: > 0 } holder)
            ctx.Response.Headers["X-Kgsm-Auth-Holder"] = holder;

        await Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "not_the_anchor",
            role.Holder is { Length: > 0 } h
                ? $"This member does not hold the cluster's accounts. {h} does."
                : "No member holds the cluster's accounts yet.");
        return false;
    }

    // ── Sign in ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Verify a KGSM password and mint a cluster-scoped session for it.
    /// </summary>
    /// <remarks>
    /// This is the one door. A person signs in here, once, and the session works on every member —
    /// so no member ever holds a credential, and none of them proxies one.
    /// </remarks>
    internal static async Task SignIn(HttpContext ctx)
    {
        if (!await RequireAuthorityAsync(ctx))
            return;

        SignInRequest? body = await ReadBodyAsync(ctx, AnchorJsonContext.Default.SignInRequest);
        if (body is null)
        {
            await Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request", "The request body is not readable.");
            return;
        }

        var signIn = ctx.RequestServices.GetRequiredService<LocalSignInService>();
        DateTimeOffset now = DateTimeOffset.UtcNow;

        LocalSignInResult result;
        try
        {
            result = await signIn.SignInAsync(body.Username, body.Password, now, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await Unavailable(ctx);
            return;
        }

        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.KGSM.Auth.Anchor.SignIn");

        switch (result.Outcome)
        {
            case LocalSignInOutcome.LockedOut:
                // The wait is stated, because a person who has mistyped their own password twice
                // needs to know it is a wait rather than a permanent refusal.
                if (result.RetryAfter is { } until)
                {
                    int seconds = (int)Math.Max(1, Math.Ceiling((until - now).TotalSeconds));
                    ctx.Response.Headers.RetryAfter = seconds.ToString();
                }
                logger.LogWarning(
                    "sign-in refused for '{Username}': locked out until {Until}",
                    body.Username, result.RetryAfter);
                await Refuse(ctx, StatusCodes.Status429TooManyRequests, "account_locked",
                    "Too many failed attempts. Try again shortly.");
                return;

            case LocalSignInOutcome.Disabled:
                logger.LogWarning("sign-in refused for '{Username}': the account is switched off", body.Username);
                await Refuse(ctx, StatusCodes.Status403Forbidden, "account_disabled",
                    "This account has been switched off.");
                return;

            case LocalSignInOutcome.Success when result.Principal is { } principal && result.User is { } user:
                logger.LogInformation(
                    "'{Username}' signed in with a password at {Tier}",
                    user.Username, KgsmTiers.ToWire(principal.Tier));
                await MintSession(ctx, principal.Identity, principal.Tier, user, now);
                return;

            default:
                // The attempted name and nothing else. It is what an operator needs to tell one
                // person mistyping from somebody working through a list, and the answer to the
                // CALLER stays one outcome at one cost either way — this journal is not reachable
                // by whoever is guessing.
                logger.LogWarning(
                    "sign-in refused for '{Username}': no account matched that name and password",
                    body.Username);
                await Refuse(ctx, StatusCodes.Status401Unauthorized, "invalid_credentials",
                    "That username and password do not match an account.");
                return;
        }
    }

    private static Task MintSession(
        HttpContext ctx, KgsmIdentity identity, KgsmTier tier, KgsmUser user, DateTimeOffset now) =>
        MintSessionFor(ctx, identity, tier, user, now, StatusCodes.Status200OK);

    /// <summary>
    /// Record a session and answer with it. One path, so a session that arrives through any door is
    /// the same session recorded the same way — the doors differ in what proves a person and in
    /// nothing after that.
    /// </summary>
    internal static async Task MintSessionFor(
        HttpContext ctx, KgsmIdentity identity, KgsmTier tier, KgsmUser user, DateTimeOffset now,
        int status)
    {
        var tokens = ctx.RequestServices.GetRequiredService<ISessionTokenService>();
        var registry = ctx.RequestServices.GetRequiredService<ISessionRegistry>();
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();

        string sessionId = NewSessionId();
        MintedToken access = tokens.MintAccess(identity, tier, sessionId);
        MintedToken refresh = tokens.MintRefresh(identity, tier, sessionId);

        await registry.CreateAsync(
            new SessionRegistration(
                SessionId: sessionId,
                // Keyed by the provider-qualified handle, never the username: a rename must not
                // detach somebody from their own sessions.
                UserId: identity.Handle,
                HostId: options.ClusterId,
                Created: now,
                Expires: refresh.ExpiresAt,
                UserAgent: UserAgentOf(ctx),
                CurrentJti: refresh.Jti),
            ctx.RequestAborted);

        await WriteJson(ctx, status, new SignInResult(
            Token: access.Token,
            Refresh: refresh.Token,
            Tier: KgsmTiers.ToWire(tier),
            UserId: user.UserId,
            Status: UserStatuses.ToWire(user.Status),
            Cluster: options.ClusterId,
            AccessTokenExpiresAt: access.ExpiresAt,
            RefreshExpiresAt: refresh.ExpiresAt),
            AnchorJsonContext.Default.SignInResult);
    }

    // ── Keep a session ────────────────────────────────────────────────────────

    /// <summary>
    /// Rotate a session: a new access bearer and a new refresh token, with standing re-read.
    /// </summary>
    /// <remarks>
    /// Nothing on this path leaves the machine. That is what makes a session survive an outage of
    /// anything else — the tier comes from the account store on this host, and the signature from the
    /// key this daemon holds.
    /// </remarks>
    internal static async Task Refresh(HttpContext ctx)
    {
        // Refusing here as well as at sign-in is what stops a member that has stood down from
        // extending the sessions it minted while it still believed it was the authority.
        if (!await RequireAuthorityAsync(ctx))
            return;

        RefreshRequest? body = await ReadBodyAsync(ctx, AnchorJsonContext.Default.RefreshRequest);
        if (body?.Refresh is not { Length: > 0 } presented)
        {
            await Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request", "No refresh token was sent.");
            return;
        }

        var tokens = ctx.RequestServices.GetRequiredService<ISessionTokenService>();
        RefreshClaims? claims = await tokens.ReadRefreshAsync(presented);
        if (claims is null)
        {
            await Refuse(ctx, StatusCodes.Status401Unauthorized, "invalid_refresh_token",
                "That session cannot be continued. Sign in again.");
            return;
        }

        var registry = ctx.RequestServices.GetRequiredService<ISessionRegistry>();
        var validator = ctx.RequestServices.GetRequiredService<ISessionValidator>();
        var authority = ctx.RequestServices.GetRequiredService<UserStoreAuthority>();

        // Standing is re-read rather than carried over from the presented token, so a demotion or a
        // disable takes effect at the next rotation instead of at the end of the session.
        AuthorityAnswer answer;
        try
        {
            answer = await authority.ResolveAsync(claims.Identity, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await Unavailable(ctx);
            return;
        }

        if (answer.Outcome != AuthorityOutcome.Ok)
        {
            // A withdrawn account keeps no session. Killing the row here is what stops the remaining
            // access bearer from being refreshed into a new one for its whole lifetime, and telling
            // the other members is what stops that bearer from being spent on them meanwhile.
            await registry.RevokeAsync(claims.SessionId, ctx.RequestAborted);
            validator.Evict(claims.SessionId);
            await ctx.RequestServices.GetRequiredService<SessionBroadcast>()
                .RevokedAsync(claims.SessionId, ctx.RequestAborted);

            await Refuse(ctx, StatusCodes.Status403Forbidden, "account_disabled",
                "This account has been switched off.");
            return;
        }

        MintedToken refresh = tokens.MintRefresh(claims.Identity, answer.Tier, claims.SessionId);

        // The presented jti has to be the one the session currently holds. Anything else is a replay
        // of a token that has already been rotated away — a stale client or a stolen token, and this
        // daemon cannot tell which, so it refuses and lets the real holder sign in again.
        bool rotated = await registry.RotateAsync(
            claims.SessionId, claims.Jti, refresh.Jti, refresh.ExpiresAt, ctx.RequestAborted);

        if (!rotated)
        {
            validator.Evict(claims.SessionId);
            await Refuse(ctx, StatusCodes.Status401Unauthorized, "invalid_refresh_token",
                "That session cannot be continued. Sign in again.");
            return;
        }

        MintedToken access = tokens.MintAccess(claims.Identity, answer.Tier, claims.SessionId);

        await WriteJson(ctx, StatusCodes.Status200OK, new RefreshResult(
            Token: access.Token,
            Refresh: refresh.Token,
            Tier: KgsmTiers.ToWire(answer.Tier),
            ExpiresAt: access.ExpiresAt),
            AnchorJsonContext.Default.RefreshResult);
    }

    /// <summary>
    /// End a session.
    /// </summary>
    /// <remarks>
    /// Answers 204 whether or not there was something to end. A signed-out caller wants to be signed
    /// out, and reporting "there was no such session" would tell a stranger holding a stolen token
    /// whether it was still live.
    /// <para>
    /// Not gated on holding the capability, unlike every other door here. Ending a session takes
    /// authority away rather than granting it, and a member that has stood down still holds the rows
    /// for sessions it minted — refusing would strand somebody signed in to a member that has since
    /// become a candidate.
    /// </para>
    /// </remarks>
    internal static async Task SignOut(HttpContext ctx)
    {
        var tokens = ctx.RequestServices.GetRequiredService<ISessionTokenService>();
        var registry = ctx.RequestServices.GetRequiredService<ISessionRegistry>();
        var validator = ctx.RequestServices.GetRequiredService<ISessionValidator>();

        string? sessionId = null;

        RefreshRequest? body = await ReadBodyAsync(ctx, AnchorJsonContext.Default.RefreshRequest);
        if (body?.Refresh is { Length: > 0 } presented)
            sessionId = (await tokens.ReadRefreshAsync(presented))?.SessionId;

        // A caller that sent no refresh token still ends the session its bearer belongs to, so
        // signing out works from a client that holds only the access token.
        if (sessionId is null)
        {
            var auth = ctx.RequestServices.GetRequiredService<AnchorAuth>();
            try
            {
                sessionId = (await auth.ResolveAsync(ctx.Request, ctx.RequestAborted)).SessionId;
            }
            catch (KgsmAuthProviderException)
            {
                await Unavailable(ctx);
                return;
            }
        }

        if (sessionId is not null)
        {
            await registry.RevokeAsync(sessionId, ctx.RequestAborted);
            validator.Evict(sessionId);

            // The row is here and the session is accepted everywhere. Ending it locally without
            // saying so leaves somebody signed out on the door they used and signed in on every
            // other one.
            await ctx.RequestServices.GetRequiredService<SessionBroadcast>()
                .RevokedAsync(sessionId, ctx.RequestAborted);
        }

        ctx.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// <summary>Who the caller is, resolved against the store rather than read off their token.</summary>
    internal static async Task Session(HttpContext ctx)
    {
        if (!await RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await RequireCaller(ctx, KgsmTier.None);
        if (maybe is not { } caller || caller.User is not { } user)
            return;

        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();

        await WriteJson(ctx, StatusCodes.Status200OK, new WhoAmI(
            UserId: user.UserId,
            Username: user.Username,
            DisplayName: user.DisplayName,
            Tier: KgsmTiers.ToWire(caller.Tier),
            Status: UserStatuses.ToWire(user.Status),
            Cluster: options.ClusterId),
            AnchorJsonContext.Default.WhoAmI);
    }

    /// <summary>Every account the anchor holds. Never carries a secret in any form.</summary>
    internal static async Task Accounts(HttpContext ctx)
    {
        if (!await RequireAuthorityAsync(ctx))
            return;

        if (await RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();

        IReadOnlyList<KgsmUser> users = await store.ListAsync(ctx.RequestAborted);
        var records = new List<AccountRecord>(users.Count);

        foreach (KgsmUser user in users)
        {
            IReadOnlyList<UserCredential> credentials =
                await store.ListCredentialsAsync(user.UserId, ctx.RequestAborted);

            records.Add(ToRecord(user, credentials));
        }

        await WriteJson(ctx, StatusCodes.Status200OK, new AccountsPage(records),
            AnchorJsonContext.Default.AccountsPage);
    }

    /// <summary>
    /// Change an account's tier or status. The single write path for what a person may do.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every change takes a version from this member's counter, and that version is what every other
    /// member orders by — so a demotion and a re-promotion delivered out of order still settle on
    /// whichever this member issued last. It is returned, because a caller that has it knows its
    /// change is the newest statement about the account.
    /// </para>
    /// <para>
    /// <b>An account cannot lower itself out of being able to fix this.</b> An admin removing their
    /// own last admin tier leaves the cluster with an account store nobody can administer, and the
    /// only way back is editing the file by hand on the machine holding it.
    /// </para>
    /// </remarks>
    internal static async Task PatchAccount(HttpContext ctx)
    {
        if (!await RequireAuthorityAsync(ctx))
            return;

        Caller? maybe = await RequireCaller(ctx, KgsmTier.Admin);
        if (maybe is not { } caller)
            return;

        string? userId = ctx.Request.RouteValues["userId"] as string;
        if (string.IsNullOrWhiteSpace(userId))
        {
            await Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_user", "A user id is required.");
            return;
        }

        AccountPatchRequest? body = await ReadBodyAsync(ctx, AnchorJsonContext.Default.AccountPatchRequest);
        if (body is null)
        {
            await Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request", "The request body is not readable.");
            return;
        }

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();
        KgsmUser? user = await store.FindByIdAsync(userId, ctx.RequestAborted);
        if (user is null)
        {
            await Refuse(ctx, StatusCodes.Status404NotFound, "no_such_account", "No account has that id.");
            return;
        }

        // Parsed strictly here rather than fail-closed. Everywhere else an unreadable tier means
        // "grants nothing", which is the safe reading of a value somebody else wrote; here it is what
        // the caller is asking for, and silently granting None instead of refusing a typo would
        // demote somebody the admin meant to promote.
        KgsmTier tier = user.Tier;
        if (body.Tier is { Length: > 0 } wantedTier)
        {
            if (!TryReadTier(wantedTier, out tier))
            {
                await Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_tier",
                    $"'{wantedTier}' is not a tier. Use admin, operator, viewer or none.");
                return;
            }
        }

        UserStatus status = user.Status;
        if (body.Status is { Length: > 0 } wantedStatus)
        {
            if (!TryReadStatus(wantedStatus, out status))
            {
                await Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_status",
                    $"'{wantedStatus}' is not a status. Use active, pending or disabled.");
                return;
            }
        }

        // The last-admin rule, and it is about the CLUSTER rather than a machine: there is one
        // account store, so an admin who demotes or disables themselves while holding the only admin
        // tier leaves nobody able to undo it through any surface.
        bool losesAdmin = user.Tier == KgsmTier.Admin
            && (tier != KgsmTier.Admin || status != UserStatus.Active);
        if (losesAdmin && caller.User?.UserId == user.UserId && !await AnotherAdminExistsAsync(store, user.UserId, ctx.RequestAborted))
        {
            await Refuse(ctx, StatusCodes.Status409Conflict, "last_admin",
                "This is the only administrator the cluster has. Promote somebody else first.");
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        var updated = user with
        {
            Tier = tier,
            // An admin choosing a tier is exactly what provenance records, so a change here is
            // always deliberate rather than seeded from a mapping.
            TierSource = TierSource.Granted,
            Status = status,
            Updated = now,
        };

        await store.UpdateAsync(updated, ctx.RequestAborted);

        var versions = ctx.RequestServices.GetRequiredService<IAccountVersions>();
        long version = await versions.NextAsync(updated.UserId, now, ctx.RequestAborted);

        // Announced after the local write has committed, so nothing tells another member about a
        // change that did not land here. A failure to announce is logged and does not fail the
        // request: the change is real, and reporting it as failed would invite the admin to repeat it.
        var broadcast = ctx.RequestServices.GetRequiredService<AccountBroadcast>();
        await broadcast.PublishAsync(updated, version, ctx.RequestAborted);

        IReadOnlyList<UserCredential> credentials =
            await store.ListCredentialsAsync(updated.UserId, ctx.RequestAborted);

        await WriteJson(ctx, StatusCodes.Status200OK,
            new AccountChanged(ToRecord(updated, credentials), version),
            AnchorJsonContext.Default.AccountChanged);
    }

    /// <summary>Whether any other account is a usable administrator.</summary>
    private static async Task<bool> AnotherAdminExistsAsync(
        IUserStore store, string excluding, CancellationToken ct)
    {
        IReadOnlyList<KgsmUser> all = await store.ListAsync(ct);
        return all.Any(u =>
            !string.Equals(u.UserId, excluding, StringComparison.Ordinal)
            && u.EffectiveTier == KgsmTier.Admin);
    }

    /// <summary>A tier a caller asked for, refusing anything that is not one.</summary>
    private static bool TryReadTier(string wire, out KgsmTier tier)
    {
        tier = KgsmTiers.Parse(wire);
        return tier != KgsmTier.None
            || string.Equals(wire.Trim(), KgsmTiers.None, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A status a caller asked for, refusing anything that is not one.</summary>
    private static bool TryReadStatus(string wire, out UserStatus status)
    {
        status = UserStatuses.Parse(wire);
        return status != UserStatus.Disabled
            || string.Equals(wire.Trim(), UserStatuses.Disabled, StringComparison.OrdinalIgnoreCase);
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The caller, or null with the refusal already written.
    /// </summary>
    /// <remarks>
    /// The four refusals are distinguishable because a client acts differently on each: an
    /// unauthenticated caller signs in, an ended session signs in again, a disabled account is told
    /// so, and an insufficient tier is a person who is signed in and may not do this.
    /// </remarks>
    private static async Task<Caller?> RequireCaller(HttpContext ctx, KgsmTier required)
    {
        var auth = ctx.RequestServices.GetRequiredService<AnchorAuth>();

        Caller caller;
        try
        {
            caller = await auth.ResolveAsync(ctx.Request, ctx.RequestAborted);
        }
        catch (KgsmAuthProviderException)
        {
            await Unavailable(ctx);
            return null;
        }

        switch (caller.Refusal)
        {
            case CallerRefusal.Unauthenticated:
                await Refuse(ctx, StatusCodes.Status401Unauthorized, "unauthenticated",
                    "Sign in to continue.");
                return null;

            case CallerRefusal.SessionEnded:
                await Refuse(ctx, StatusCodes.Status401Unauthorized, "session_ended",
                    "That session has ended. Sign in again.");
                return null;

            case CallerRefusal.AccountDisabled:
                await Refuse(ctx, StatusCodes.Status403Forbidden, "account_disabled",
                    "This account has been switched off.");
                return null;
        }

        if (!caller.Holds(required))
        {
            await Refuse(ctx, StatusCodes.Status403Forbidden, "forbidden",
                "This account does not hold the tier required for that.");
            return null;
        }

        return caller;
    }

    /// <summary>
    /// The account store could not be read.
    /// </summary>
    /// <remarks>
    /// 503, never 403. "We could not find out what this person may do" is a different fact from "they
    /// may do nothing", and reporting the first as the second locks out an admin mid-incident.
    /// </remarks>
    private static Task Unavailable(HttpContext ctx) =>
        Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
            "The account store could not be read.");

    /// <summary>An account as this surface renders one. Never carries a secret in any form.</summary>
    private static AccountRecord ToRecord(KgsmUser user, IReadOnlyList<UserCredential> credentials) =>
        new(
            Id: user.UserId,
            Username: user.Username,
            DisplayName: user.DisplayName,
            Tier: KgsmTiers.ToWire(user.Tier),
            TierSource: TierSources.ToWire(user.TierSource),
            Status: UserStatuses.ToWire(user.Status),
            HasPassword: credentials.Any(c => c.Kind == CredentialKind.Password),
            Identities: [.. credentials.Where(c => c.Kind == CredentialKind.Identity).Select(c => c.Handle)],
            Created: user.Created,
            Updated: user.Updated);

    internal static Task Refuse(HttpContext ctx, int status, string code, string message) =>
        WriteJson(ctx, status, new ErrorEnvelope(new ErrorBody(code, message)),
            AnchorJsonContext.Default.ErrorEnvelope);

    internal static Task WriteJson<T>(HttpContext ctx, int status, T value, JsonTypeInfo<T> type)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(ctx.Response.Body, value, type, ctx.RequestAborted);
    }

    /// <summary>
    /// The request body, or null when it is absent, oversized or not readable as
    /// <typeparamref name="T"/>.
    /// </summary>
    internal static async Task<T?> ReadBodyAsync<T>(HttpContext ctx, JsonTypeInfo<T> type) where T : class
    {
        if (ctx.Request.ContentLength > MaxBodyBytes)
            return null;

        try
        {
            ctx.Request.EnableBuffering(bufferThreshold: MaxBodyBytes, bufferLimit: MaxBodyBytes);
            return await JsonSerializer.DeserializeAsync(ctx.Request.Body, type, ctx.RequestAborted);
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// The device, for a person reading their own session list. Truncated, because it is arbitrary
    /// text from a caller that ends up on a page somebody reads.
    /// </summary>
    private static string? UserAgentOf(HttpContext ctx)
    {
        string agent = ctx.Request.Headers.UserAgent.ToString();
        if (string.IsNullOrWhiteSpace(agent))
            return null;
        return agent.Length > 256 ? agent[..256] : agent;
    }

    /// <summary>
    /// A fresh session id: 128 bits from the cryptographic RNG, matching the <c>usr_</c>/<c>crd_</c>
    /// convention the account store already uses.
    /// </summary>
    private static string NewSessionId() =>
        "sid_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}
