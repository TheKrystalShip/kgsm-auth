using Microsoft.Extensions.Caching.Memory;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Minting;
using TheKrystalShip.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Extensions;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// The provider itself: accounts, sessions, the OpenID Connect provider, the applications it signs people
/// in to and their clients, the account and admin doors, and the journal. Everything here runs with no
/// KGSM on the machine.
/// </summary>
/// <remarks>
/// <para>
/// The KGSM module (<see cref="KgsmModule"/>) is composed beside this only when a KGSM cluster is
/// configured. Where the core has something to tell other members — a session ended, an authority write
/// landed — it says so through <see cref="ISessionAnnouncer"/> and <see cref="IAuthorityAnnouncer"/>, and
/// the module supplies the implementations that reach the cluster. A standalone anchor is the only thing
/// that holds its accounts and its sessions, so it gets <see cref="StandaloneAnnouncements"/>, and its own
/// actions enter its catalog through <see cref="StandaloneCatalog"/>.
/// </para>
/// <para>
/// Nothing here reads or writes under <c>/etc/kgsm</c> or <c>/var/lib/kgsm</c>.
/// </para>
/// </remarks>
internal static class TksAuthCore
{
    /// <param name="services">The daemon's services.</param>
    /// <param name="options">Its validated settings.</param>
    /// <param name="signer">The session signing key, loaded before the host is built.</param>
    /// <param name="clustered">Whether a KGSM cluster is configured, which composes the module beside this.</param>
    internal static IServiceCollection AddTksAuthCore(
        this IServiceCollection services, AnchorOptions options, EcdsaSessionSigner signer, bool clustered)
    {
        services.AddSingleton(options);
        services.AddSingleton(signer);

        services.AddSingleton<IUserStore>(sp => sp.GetRequiredService<AnchorAuthority>().Store
            ?? throw new InvalidOperationException(sp.GetRequiredService<AnchorAuthority>().UnavailableReason));
        services.AddSingleton<IUserPasswordHasher, IdentityPasswordHasher>();

        // How long a switched-off account can still be found usable. Short, because the read behind it is
        // a local point query and there is nothing to buy by keeping it long.
        services.AddSingleton(sp => new AccountResolver(
            sp.GetRequiredService<IUserStore>(), TimeSpan.FromSeconds(5)));

        services.AddSingleton(sp => new LocalSignInService(
            sp.GetRequiredService<IUserStore>(),
            sp.GetRequiredService<IUserPasswordHasher>()));

        // This anchor's own event journal — the record of what happened to its accounts. It writes to
        // this daemon's state directory under its own producer name, which is the same rule a reader
        // inverts to attribute a line, so writer and reader agree on the location without either being
        // told.
        //
        // A Control Panel on this machine finds it by scanning for journals and serves it merged with
        // every other producer's. One on a DIFFERENT machine does not: a journal is a local file, and an
        // anchor running where no API does keeps a complete record that no panel renders.
        services.AddKgsmJournal(AnchorJournal.ProducerId, typeof(AnchorJournal).Assembly);
        services.AddSingleton<AnchorJournal>();

        // The Owner account an empty store gets. Without it a fresh install is a door nobody can open —
        // registration is off unless configured on, and an account made through it waits for an
        // approval only somebody holding auth:accounts.approve can give.
        services.AddHostedService<AnchorBootstrapper>();

        // The links the account page has started and a provider has not yet sent back. In memory: a
        // restart drops links in flight, which costs a click and cannot grant anything.
        services.AddSingleton<LinkTicketStore>();

        // The audience is the cluster id, not this machine: in a KGSM cluster a session minted here is
        // presented to every member of it. Signed with the private key, so a member can verify one and
        // cannot mint one.
        services.AddSingleton<ISessionTokenService>(_ => new SessionTokenService(
            new SessionTokenOptions(
                Audience: options.ClusterId,
                AccessLifetime: options.AccessLifetime,
                RefreshLifetime: options.RefreshLifetime,
                Issuer: options.Issuer),
            signer));

        // Where this anchor stands. With no cluster it is Standalone from the first request and stays
        // there; in one, the module's membership worker moves it.
        services.AddSingleton(_ => new AnchorRole(clustered));

        // Who may do what, and the one place a catalog report lands and is journaled.
        services.AddSingleton<AnchorAuthority>();
        services.AddSingleton<AuthorityIntake>();
        services.AddSingleton(TimeProvider.System);

        services.AddSingleton(_ => new SqliteSessionRegistry(options.SessionStorePath));
        services.AddSingleton<ISessionRegistry>(sp => sp.GetRequiredService<SqliteSessionRegistry>());
        services.AddSingleton<AnchorAccess>();

        // The OpenID Connect provider: the clients it answers, the browsers signed in at it, and the
        // id_token beside every session it mints. Its rows live beside the sessions, because a browser's
        // sign-in here is a session and every session minted through it records which one it came from.
        services.AddSingleton(sp => new ClientRegistry(
            sp.GetRequiredService<SqliteSessionRegistry>(), options.PanelOrigins));

        // The applications those clients sign people in to — KGSM's built in, every other registered by
        // the admin surface or the host command — and the actions each declares in the manifest it serves,
        // read on registration and on an interval.
        AddApplications(services);
        services.AddHostedService<ApplicationManifestWorker>();
        services.AddSingleton<ProviderSessions>();
        services.AddSingleton<IdTokens>();
        services.AddSingleton<ProviderBundle>();
        services.AddSingleton<ReauthRoundTrips>();
        services.AddSingleton<IMemoryCache>(_ => new MemoryCache(new MemoryCacheOptions()));
        services.AddSingleton<ISessionValidator>(sp => new SessionValidator(
            sp.GetRequiredService<ISessionRegistry>(),
            sp.GetRequiredService<IMemoryCache>(),
            TimeSpan.FromSeconds(5)));
        services.AddSingleton<SessionReader>();
        services.AddSingleton<AnchorAuth>();
        services.AddSingleton<AuthorityCaller>();

        // Signing in with an account somebody already holds elsewhere. The provider answers WHO, and the
        // account store answers what they may do — so a provider is added with no authority story of its
        // own. Transient like the typed HttpClient underneath it: holding one for the process lifetime
        // pins its handler and silently stops the factory rotating it, so DNS changes never land.
        //
        // The address the callbacks are built from is the configured one, or — with the module — the
        // name a cluster's DNS anchor assigned; with neither registered the sequence is empty.
        services.AddHttpClient(nameof(DiscordDirectory), c => c.Timeout = TimeSpan.FromSeconds(10));
        services.AddSingleton(sp => new AnchorAddress(
            sp.GetRequiredService<AnchorOptions>(),
            sp.GetServices<ISelfAddressSource>()));
        services.AddTransient(sp => new ProviderCatalog(
            sp.GetRequiredService<IConfiguration>(),
            sp.GetRequiredService<IHttpClientFactory>(),
            sp.GetRequiredService<AnchorAddress>()));
        services.AddSingleton(sp => new IdentityLinkService(sp.GetRequiredService<IUserStore>()));

        // Deletes rows already past their cap. Housekeeping — it ends no session that is still alive.
        services.AddHostedService(sp => new SessionCleanupWorker(
            sp.GetRequiredService<ISessionRegistry>(),
            options.SessionCleanup,
            sp.GetRequiredService<ILogger<SessionCleanupWorker>>()));

        if (!clustered)
        {
            services.AddSingleton<StandaloneAnnouncements>();
            services.AddSingleton<ISessionAnnouncer>(sp => sp.GetRequiredService<StandaloneAnnouncements>());
            services.AddSingleton<IAuthorityAnnouncer>(sp => sp.GetRequiredService<StandaloneAnnouncements>());
            services.AddHostedService<StandaloneCatalog>();
        }

        return services;
    }

    /// <summary>
    /// The application registry and the catalog of what applications declare: the one path every change
    /// to an application takes, from the admin surface and from the host command alike.
    /// </summary>
    internal static IServiceCollection AddApplications(IServiceCollection services)
    {
        services.AddHttpClient(ApplicationCatalog.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(10));
        services.AddSingleton<ApplicationCatalog>();
        services.AddSingleton<ApplicationRegistry>();
        return services;
    }

    /// <summary>Every door the provider serves, with or without the module.</summary>
    internal static WebApplication MapTksAuthCore(this WebApplication app)
    {
        // Unified ecosystem liveness probe: 200 means this anchor is up and serving.
        app.MapGet("/health", () => Results.Text("ok\n"));

        // What this is. Unauthenticated, because a client handed one address has to establish what is
        // behind it before it can do anything, and a caller with no session is exactly who is asking.
        app.MapGet("/auth/identity", DiscoveryEndpoints.Identity);

        // The OpenID Connect provider every browser surface signs in through. Served only when the issuer
        // is this anchor's browser-facing URL; otherwise each door says so rather than guessing one.
        app.MapGet("/.well-known/openid-configuration", OidcEndpoints.Discovery);
        app.MapGet("/.well-known/jwks.json", OidcEndpoints.Jwks);
        app.MapGet("/authorize", OidcEndpoints.Authorize);
        app.MapPost("/authorize/credentials", OidcEndpoints.Credentials);
        app.MapGet("/authorize/wait", OidcEndpoints.Wait);
        app.MapGet("/authorize/floor.css", ProviderPages.StylesheetAsync);
        app.MapGet("/authorize/context", OidcEndpoints.Context);
        app.MapPost("/authorize/register", OidcEndpoints.Register);
        app.MapGet("/authorize/{provider}", OidcEndpoints.ProviderStart);
        app.MapPost("/token", OidcEndpoints.Token);
        app.MapGet("/userinfo", OidcEndpoints.UserInfo);
        app.MapPost("/userinfo", OidcEndpoints.UserInfo);
        app.MapGet("/sign-out", OidcEndpoints.SignOut);
        app.MapPost("/sign-out", OidcEndpoints.ConfirmSignOut);

        // The provider's own pages as kgsm-web builds them, and the account page's calls. Every one of
        // those is authenticated by the provider's cookie and answered on this origin alone.
        app.MapGet("/ui/{**path}", ProviderBundle.ServeAssetAsync);
        app.MapGet("/account", AccountPageEndpoints.Page);
        app.MapGet("/account/sign-in", AccountPageEndpoints.SignIn);
        app.MapGet("/account/me", AccountPageEndpoints.Me);
        app.MapPost("/account/reauth", AccountPageEndpoints.Reauth);
        app.MapGet("/account/reauth/{provider}", AccountPageEndpoints.ReauthWithProvider);
        app.MapPost("/account/password", AccountPageEndpoints.SetPassword);
        app.MapPost("/account/identities/{provider}/start", AccountPageEndpoints.StartLink);
        app.MapDelete("/account/identities/{credentialId}", AccountPageEndpoints.Unlink);
        app.MapPost("/account/sessions/revoke", AccountPageEndpoints.Revoke);
        app.MapPost("/account/sign-out", AccountPageEndpoints.SignOut);

        // The clients it answers that were registered by hand. In a KGSM cluster the surfaces members
        // announce join them over gossip.
        app.MapGet("/auth/cluster/clients", OidcEndpoints.ListClients);
        app.MapPost("/auth/cluster/clients", OidcEndpoints.RegisterClient);
        app.MapDelete("/auth/cluster/clients/{clientId}", OidcEndpoints.RemoveClient);

        // The applications this provider signs people in to, their clients and their client secrets.
        ApplicationEndpoints.Map(app);

        // Where a provider sends the browser back: to complete the request in flight, or to prove the
        // person again for the account page. The one address registered with the provider's application.
        app.MapGet("/auth/{provider}/callback", ProviderEndpoints.Callback);

        // Each gated route declares its action on itself (`AuthAction`); the handler enforces that entry
        // and `GET /auth/cluster/operations` publishes it. Approving and switching off share a route,
        // told apart by the status asked for.
        app.MapGet("/auth/cluster/users", Endpoints.Accounts);
        app.MapPost("/auth/cluster/users", AccountEndpoints.CreateAccount)
            .WithMetadata(new AuthAction(AuthActions.AccountsCreate));
        app.MapPatch("/auth/cluster/users/{userId}", Endpoints.PatchAccount)
            .WithMetadata(new AuthAction(AuthActions.AccountsApprove, "status", "active"))
            .WithMetadata(new AuthAction(AuthActions.AccountsDisable, "status", "disabled"));

        // Where a provider sends the browser back after the account page began attaching an identity. A
        // different address from the sign-in callback: one attaches whoever comes back to an account
        // already signed in, and sharing an address would let a link return through the sign-in door.
        app.MapGet("/auth/identities/{provider}/callback", IdentityEndpoints.CompleteLink);

        // What may be done to somebody else's account, each on its own action. Setting a password knows
        // no current one, because the case it exists for is a person who has lost theirs.
        app.MapPost("/auth/cluster/users/{userId}/password", AccountEndpoints.SetPassword)
            .WithMetadata(new AuthAction(AuthActions.AccountsCreate));
        app.MapDelete("/auth/cluster/users/{userId}", AccountEndpoints.DeleteAccount)
            .WithMetadata(new AuthAction(AuthActions.AccountsDelete));

        // The devices somebody is signed in on, and ending them. Listed here because they exist ONLY
        // here: a member verifies a cluster session offline against a published key and stores nothing,
        // so a member asked what devices somebody holds answers honestly with none — an empty card rather
        // than a wrong question. Ending one is never gated on holding the capability, because revoking
        // takes authority away and a member that has stood down still holds the rows for what it minted.
        app.MapGet("/auth/cluster/users/{userId}/sessions", SessionEndpoints.List)
            .WithMetadata(new AuthAction(AuthActions.AccountsDisable));
        app.MapPost("/auth/cluster/users/{userId}/sessions/revoke-all", SessionEndpoints.RevokeAll)
            .WithMetadata(new AuthAction(AuthActions.AccountsDisable));
        app.MapPost("/auth/cluster/users/{userId}/sessions/{sid}/revoke", SessionEndpoints.RevokeOne)
            .WithMetadata(new AuthAction(AuthActions.AccountsDisable));

        // Who may do what: the authority for the pages that administer it, one change at a time, whether
        // the rules would allow a change without making it, and the caller's own actions here. Served
        // from a store at schema version 2, and 503 from one that is not.
        app.MapGet("/auth/cluster/authority", AuthorityEndpoints.Read);
        app.MapPost(AnchorOperations.EditsRoute, AuthorityEndpoints.Edit);
        app.MapPost(AnchorOperations.ChecksRoute, AuthorityEndpoints.Check);
        app.MapGet("/me/access", AuthorityEndpoints.MeAccess);

        // Every gated route here and the action it requires, built from the routes themselves. Public: it
        // is a description of this build, and a client reads it to know which action a request it is
        // about to make needs, without holding a list of its own.
        app.MapGet("/auth/cluster/operations", AnchorOperations.Serve);

        return app;
    }
}
