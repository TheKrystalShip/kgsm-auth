using System.Text.RegularExpressions;

using TheKrystalShip.Auth.Journal;
using TheKrystalShip.Auth.Minting;
using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// The token-exchange grant at <c>/token</c> (RFC 8693): a confidential client of an application outside
/// KGSM trades a Discord credential for that application's access token, naming the account the Discord
/// identity is attached to.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two subjects, one token.</b> A Discord access token
/// (<see cref="DiscordAccessToken"/>) is the person's own credential, presented by the application whose
/// Discord application it was issued to — an Activity's. A Discord user id (<see cref="DiscordUserId"/>) is
/// only a name, so the client presenting it must be registered to act for Discord users, and the token
/// names that client as actor in <c>act</c> (§4.1) — a bot acting for whoever invoked it. Either way the
/// token is the one the code flow mints for that application: <c>at+jwt</c>, its audience, its lifetime,
/// <c>tks_actions</c> evaluated now. It belongs to no session and comes with no refresh token; the holder
/// exchanges again.
/// </para>
/// <para>
/// <b>The client authenticates, and is confidential.</b> A public client is <c>unauthorized_client</c>;
/// a client that does not prove its secret, or names none, is <c>invalid_client</c>. KGSM's clients are
/// refused: a KGSM session lives under a browser's sign-in here, and an exchange has none.
/// </para>
/// <para>
/// <b>The account decides the answer, and says why.</b> Only an active account gets a token. A pending,
/// disabled or unknown one is <c>invalid_grant</c> with the extension parameter <c>account_status</c>
/// (<c>pending</c>, <c>disabled</c>, <c>unknown</c>), which the caller words for the person. A Discord
/// identity nobody holds, presented with its own token, is provisioned pending under the same rule and cap
/// as a Discord sign-in here. One named only by its id is not provisioned: nothing here can ask Discord
/// who an id is without a bot token, which this provider never holds.
/// </para>
/// <para>
/// <b>Every exchange an authenticated client asks for is journaled</b>, given or refused, with the client,
/// the Discord identity, the account and the acting client. An outage at Discord or the store records
/// nothing: nothing was decided.
/// </para>
/// </remarks>
internal static partial class TokenExchange
{
    /// <summary>The grant type (RFC 8693 §2.1).</summary>
    internal const string GrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>The token type every exchange issues: an OAuth access token (RFC 8693 §3).</summary>
    internal const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>A Discord OAuth2 access token, issued to a Discord application for a user with <c>identify</c>.</summary>
    internal const string DiscordAccessToken = "urn:tks:params:oauth:token-type:discord-access-token";

    /// <summary>A Discord user id (a snowflake), presented by a client acting for that user.</summary>
    internal const string DiscordUserId = "urn:tks:params:oauth:token-type:discord-user-id";

    /// <summary>The values of the <c>account_status</c> error parameter.</summary>
    internal static class AccountStatus
    {
        /// <summary>The account waits on an administrator's approval.</summary>
        public const string Pending = "pending";

        /// <summary>The account is switched off.</summary>
        public const string Disabled = "disabled";

        /// <summary>No account holds the Discord identity.</summary>
        public const string Unknown = "unknown";
    }

    /// <summary>Answer a token-exchange request whose client credentials have been read.</summary>
    internal static async Task ExchangeAsync(HttpContext ctx, IFormCollection form, ClientAuthentication auth)
    {
        IServiceProvider services = ctx.RequestServices;

        if (auth.Result != ClientAuthentication.Outcome.Authenticated)
        {
            if (auth.ClientId is { } named && services.GetRequiredService<ClientRegistry>().Find(named) is { Confidential: false })
            {
                await OidcEndpoints.OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "unauthorized_client",
                    "Token exchange is for a confidential client.");
                return;
            }

            await auth.RefuseAsync(ctx, "Token exchange needs the client to authenticate with its secret.");
            return;
        }

        RegisteredClient client = auth.Client!;
        if (services.GetRequiredService<ApplicationRegistry>().Of(client) is not { IsKgsm: false } application)
        {
            await OidcEndpoints.OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "unauthorized_client",
                "Token exchange mints for an application outside KGSM.");
            return;
        }

        if (Problem(form, application) is ({ } error, { } description))
        {
            await OidcEndpoints.OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, error, description);
            return;
        }

        string subject = OidcEndpoints.Single(form, "subject_token")!;
        var exchange = new Exchange(ctx, client, application);
        switch (OidcEndpoints.Single(form, "subject_token_type"))
        {
            case DiscordAccessToken:
                await exchange.FromDiscordTokenAsync(subject);
                return;

            case DiscordUserId:
                await exchange.ForDiscordUserAsync(subject);
                return;

            default:
                await OidcEndpoints.OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, "invalid_request",
                    $"subject_token_type is {DiscordAccessToken} or {DiscordUserId}.");
                return;
        }
    }

    /// <summary>The error a request's parameters earn before its subject is looked at, or none.</summary>
    /// <remarks>
    /// The actor is the client that authenticated, so no actor token is read. What is issued is the
    /// application's access token for its own audience, so a different token type, another audience, a
    /// resource or a scope is refused rather than quietly ignored.
    /// </remarks>
    private static (string? Error, string? Description) Problem(IFormCollection form, Application application)
    {
        if (OidcEndpoints.Single(form, "subject_token") is null || OidcEndpoints.Single(form, "subject_token_type") is null)
            return ("invalid_request", "subject_token and subject_token_type are both required, once each.");

        if (form.ContainsKey("actor_token") || form.ContainsKey("actor_token_type"))
            return ("invalid_request", "The actor is the client that authenticated; an actor token is not accepted.");

        if (form.ContainsKey("requested_token_type") && OidcEndpoints.Single(form, "requested_token_type") != AccessTokenType)
            return ("invalid_request", $"The token issued is {AccessTokenType}.");

        if (form.ContainsKey("resource"))
            return ("invalid_target", "A token is issued for the client's application, named by its audience; resource is not accepted.");

        if (form.ContainsKey("audience") && OidcEndpoints.Single(form, "audience") != application.Audience)
            return ("invalid_target", $"This client's tokens are for the audience '{application.Audience}'.");

        if (form.ContainsKey("scope"))
            return ("invalid_scope", $"An exchanged token carries the application's actions in {ApplicationClaims.Actions}, not scopes.");

        return (null, null);
    }

    [GeneratedRegex("^[0-9]{5,25}$")]
    private static partial Regex SnowflakeShape();

    /// <summary>One exchange, for one authenticated client of one application.</summary>
    private sealed class Exchange(HttpContext ctx, RegisteredClient client, Application application)
    {
        private readonly IServiceProvider _services = ctx.RequestServices;
        private readonly CancellationToken _ct = ctx.RequestAborted;

        private AnchorJournal Journal => _services.GetRequiredService<AnchorJournal>();

        private ILogger Logger => _services.GetRequiredService<ILoggerFactory>()
            .CreateLogger("TheKrystalShip.Auth.Anchor.TokenExchange");

        /// <summary>
        /// A Discord access token: Discord says whose it is and which application holds it, and the
        /// identity is resolved — or provisioned pending — like a Discord sign-in here.
        /// </summary>
        public async Task FromDiscordTokenAsync(string token)
        {
            if (application.DiscordApplications.Count == 0)
            {
                await RefuseAsync(identity: null, actedBy: null, TokenExchangeRefusals.ClientNotAllowed, actor: null);
                await ErrorAsync("unauthorized_client", "This client's application presents no Discord application's tokens.");
                return;
            }

            DiscordAuthorization? authorization;
            try
            {
                authorization = await _services.GetRequiredService<DiscordAuthorizations>().ReadAsync(token, _ct);
            }
            catch (DiscordAuthException ex)
            {
                Logger.LogWarning(ex, "Discord could not be asked about a token {Client} exchanged", client.ClientId);
                await OidcEndpoints.OAuthErrorAsync(ctx, StatusCodes.Status502BadGateway, "temporarily_unavailable",
                    "Discord could not be asked who that token belongs to.");
                return;
            }

            if (authorization is null)
            {
                await RefuseAsync(identity: null, actedBy: null, TokenExchangeRefusals.SubjectInvalid, actor: null);
                await ErrorAsync("invalid_grant", "Discord does not honour that token as a user's.");
                return;
            }

            KgsmIdentity identity = authorization.Identity;
            if (!application.DiscordApplications.Contains(authorization.ApplicationId, StringComparer.Ordinal))
            {
                await RefuseAsync(identity.Handle, actedBy: null, TokenExchangeRefusals.DiscordApplication, identity.ActorString);
                await ErrorAsync("invalid_grant", "That token was issued to a Discord application this client may not present.");
                return;
            }

            AnchorOptions options = _services.GetRequiredService<AnchorOptions>();
            LinkResult link;
            try
            {
                link = await _services.GetRequiredService<IdentityLinkService>()
                    .ResolveOrProvisionAsync(identity, DateTimeOffset.UtcNow, options.Pending, _ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Logger.LogError(ex, "could not resolve {Handle} against the account store", identity.Handle);
                await UnavailableAsync();
                return;
            }

            if (link.Outcome == LinkOutcome.PendingCapReached)
            {
                // Not a refusal of this person: a refusal to hold more unapproved accounts. Logged, because
                // from the outside it is indistinguishable from being turned away.
                Logger.LogWarning("{Handle} was exchanged and {Cap} accounts already await approval",
                    identity.Handle, options.Pending.Cap);
                await RefuseAsync(identity.Handle, actedBy: null, TokenExchangeRefusals.AccountUnknown, identity.ActorString);
                await AccountErrorAsync(AccountStatus.Unknown,
                    "No account holds that Discord identity, and no new account can be made for it now.");
                return;
            }

            KgsmUser user = link.User!;
            if (link.Outcome == LinkOutcome.Provisioned)
            {
                // The same two facts a Discord sign-in here records for an account that did not exist.
                await Journal.AccountAsync(AuthEvents.UserProvisioned, user.UserId, user.Username,
                    toStatus: UserStatuses.ToWire(user.Status), actor: identity.ActorString,
                    origin: AnchorJournal.OriginDiscord, ct: _ct);
                await Journal.IdentityAsync(AuthEvents.IdentityLinked, user.UserId, user.Username,
                    KgsmActorProvider.Discord, identity.Handle, identity.ActorString, AnchorJournal.OriginDiscord, _ct);
            }

            await MintAsync(user, identity.Handle, identity.ActorString, identity.AvatarUrl, actedBy: null);
        }

        /// <summary>
        /// A Discord user id, from a client registered to act for Discord users. The account is found by the
        /// identity attached to it; nothing is provisioned.
        /// </summary>
        public async Task ForDiscordUserAsync(string userId)
        {
            if (!SnowflakeShape().IsMatch(userId))
            {
                await ErrorAsync("invalid_request", "subject_token is a Discord user id.");
                return;
            }

            string handle = KgsmActor.Format(KgsmActorProvider.Discord, userId);
            if (!application.ActForDiscord)
            {
                await RefuseAsync(handle, client.ClientId, TokenExchangeRefusals.ClientNotAllowed, handle);
                await ErrorAsync("unauthorized_client", "This client's application may not act for Discord users.");
                return;
            }

            KgsmUser? user;
            try
            {
                user = await _services.GetRequiredService<IUserStore>().FindByCredentialAsync(handle, _ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Logger.LogError(ex, "could not resolve {Handle} against the account store", handle);
                await UnavailableAsync();
                return;
            }

            if (user is null)
            {
                await RefuseAsync(handle, client.ClientId, TokenExchangeRefusals.AccountUnknown, handle);
                await AccountErrorAsync(AccountStatus.Unknown, "No account holds that Discord identity.");
                return;
            }

            await MintAsync(user, handle, handle, picture: null, actedBy: client.ClientId);
        }

        /// <summary>The application's access token for an active account; the account's standing otherwise.</summary>
        private async Task MintAsync(KgsmUser user, string identity, string actor, string? picture, string? actedBy)
        {
            if (user.Status != UserStatus.Active)
            {
                bool pending = user.Status == UserStatus.Pending;
                await RefuseAsync(identity, actedBy,
                    pending ? TokenExchangeRefusals.AccountPending : TokenExchangeRefusals.AccountDisabled, actor, user);
                await AccountErrorAsync(
                    pending ? AccountStatus.Pending : AccountStatus.Disabled,
                    pending ? "The account waits on an administrator's approval." : "The account is switched off.");
                return;
            }

            IReadOnlyList<string> held;
            try
            {
                held = await _services.GetRequiredService<ApplicationCatalog>().HeldAsync(application, user.UserId, _ct);
            }
            catch (Exception e) when (e is InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
            {
                await UnavailableAsync();
                return;
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            MintedToken access = _services.GetRequiredService<ISessionTokenService>().MintApplicationAccess(
                new ApplicationAccess(
                    Subject: user.UserId,
                    Username: user.Username,
                    DisplayName: user.DisplayName,
                    Picture: picture,
                    SessionId: null,
                    ClientId: client.ClientId,
                    Audience: application.Audience,
                    Lifetime: application.AccessLifetime,
                    Actions: held)
                { Actor = actedBy });

            await Journal.TokenExchangeAsync(client.ClientId, application.Id, identity, user.UserId, user.Username,
                actedBy, reason: null, actor, _ct);

            await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new TokenExchangeResponse(
                AccessToken: access.Token,
                IssuedTokenType: AccessTokenType,
                TokenType: "Bearer",
                ExpiresIn: Math.Max(0, (long)(access.ExpiresAt - now).TotalSeconds)),
                AnchorJsonContext.Default.TokenExchangeResponse);
        }

        private Task RefuseAsync(string? identity, string? actedBy, string reason, string? actor, KgsmUser? user = null) =>
            Journal.TokenExchangeAsync(client.ClientId, application.Id, identity, user?.UserId, user?.Username,
                actedBy, reason, actor ?? "", _ct);

        private Task ErrorAsync(string error, string description) =>
            OidcEndpoints.OAuthErrorAsync(ctx, StatusCodes.Status400BadRequest, error, description);

        private Task AccountErrorAsync(string status, string description) =>
            Endpoints.WriteJson(ctx, StatusCodes.Status400BadRequest,
                new OAuthAccountError("invalid_grant", description, status),
                AnchorJsonContext.Default.OAuthAccountError);

        private Task UnavailableAsync() =>
            OidcEndpoints.OAuthErrorAsync(ctx, StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable",
                "The account store could not be read.");
    }
}
