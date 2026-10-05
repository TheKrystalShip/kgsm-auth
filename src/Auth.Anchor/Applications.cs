using System.Text.RegularExpressions;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Journal;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>Where an application came from.</summary>
internal static class ApplicationSources
{
    /// <summary>
    /// Built into this provider and never stored: KGSM, whose audience is the cluster id, and tks-auth's
    /// own admin pages.
    /// </summary>
    public const string Builtin = "builtin";

    /// <summary>Registered on this provider, by the host command or the admin surface.</summary>
    public const string Admin = "admin";
}

/// <summary>
/// An application this provider signs people in to: the API its clients' tokens are for.
/// </summary>
/// <param name="Id">
/// What it is known by, and the namespace its actions are declared in (<c>cinema</c> declares
/// <c>cinema:*</c>).
/// </param>
/// <param name="Name">What a person is shown on the sign-in page.</param>
/// <param name="Audience">The <c>aud</c> its access tokens carry, the one string its resource server checks.</param>
/// <param name="ManifestUrl">Where it serves its action manifest, or null when it declares none.</param>
/// <param name="AccessLifetime">How long an access token for it lives.</param>
/// <param name="DiscordApplications">The Discord applications whose tokens its clients may present.</param>
/// <param name="ActForDiscord">Whether its confidential clients may act for a linked Discord user.</param>
/// <param name="Source"><c>builtin</c> for KGSM and tks-auth's own, <c>admin</c> for one registered here.</param>
/// <param name="Created">When it was registered.</param>
internal sealed record Application(
    string Id,
    string Name,
    string Audience,
    string? ManifestUrl,
    TimeSpan AccessLifetime,
    IReadOnlyList<string> DiscordApplications,
    bool ActForDiscord,
    string Source,
    DateTimeOffset Created)
{
    /// <summary>KGSM's id.</summary>
    public const string KgsmId = "kgsm";

    /// <summary>
    /// tks-auth's own id: the namespace of the actions its admin routes require, which its access tokens list.
    /// </summary>
    public const string ProviderId = ActionIds.AuthComponent;

    /// <summary>The audience of an access token for tks-auth's own admin routes.</summary>
    public const string ProviderAudience = "tks-auth";

    /// <summary>The admin pages' client: public, its redirect on the issuer's own origin.</summary>
    public const string ProviderClientId = "tks-auth";

    /// <summary>Where the admin pages are served, and where their client's codes and sign-outs return.</summary>
    public const string ProviderPagesPath = "/admin/";

    /// <summary>What the catalog records an application's report under, before its id.</summary>
    public const string CatalogMemberPrefix = "application:";

    /// <summary>Whether this is KGSM, whose tokens carry no actions and whose members evaluate from a replica.</summary>
    public bool IsKgsm => Source == ApplicationSources.Builtin && Id == KgsmId;

    /// <summary>Whether this is built into the provider: never stored, and never changed or removed here.</summary>
    public bool IsBuiltin => Source == ApplicationSources.Builtin;

    /// <summary>The name its manifest's report is held under in the catalog, beside every member's.</summary>
    public string CatalogMember => CatalogMemberPrefix + Id;
}

/// <summary>A client secret, shown once: when it is made.</summary>
/// <param name="ClientId">The client it authenticates.</param>
/// <param name="Secret">The secret. Only its hash is stored.</param>
internal sealed record IssuedSecret(string ClientId, string Secret);

/// <summary>What an administrative change to the applications came to.</summary>
internal enum ApplicationOutcome
{
    /// <summary>Done.</summary>
    Done,

    /// <summary>The request is not one that can be honoured; the problem says why.</summary>
    Invalid,

    /// <summary>An id or an audience is already somebody else's.</summary>
    Taken,

    /// <summary>No such application or client.</summary>
    NotFound,

    /// <summary>KGSM's application, which is built in and changed by configuring the cluster.</summary>
    BuiltIn,
}

/// <summary>An administrative change's answer.</summary>
/// <param name="Outcome">What it came to.</param>
/// <param name="Application">The application as it now stands, when it stands.</param>
/// <param name="Secrets">Every secret the change made, each shown here and never again.</param>
/// <param name="Problem">Why it was refused, as a person reads it.</param>
/// <param name="Manifest">What reading its manifest came to, when the change read it.</param>
internal sealed record ApplicationResult(
    ApplicationOutcome Outcome,
    Application? Application = null,
    IReadOnlyList<IssuedSecret>? Secrets = null,
    string? Problem = null,
    ManifestState? Manifest = null)
{
    public static ApplicationResult Refused(ApplicationOutcome outcome, string problem) => new(outcome, Problem: problem);
}

/// <summary>An application to register.</summary>
/// <param name="Id">Its id and action namespace.</param>
/// <param name="Name">What a person is shown.</param>
/// <param name="Audience">Its tokens' audience; its id when absent.</param>
/// <param name="ManifestUrl">Where it serves its action manifest.</param>
/// <param name="AccessLifetimeMinutes">Its access tokens' lifetime; five minutes when absent.</param>
/// <param name="DiscordApplications">The Discord applications its clients may present.</param>
/// <param name="ActForDiscord">Whether it may act for linked Discord users.</param>
/// <param name="Clients">The clients it signs in through, registered with it.</param>
internal sealed record ApplicationRequest(
    string? Id,
    string? Name,
    string? Audience,
    string? ManifestUrl,
    int? AccessLifetimeMinutes,
    IReadOnlyList<string>? DiscordApplications,
    bool? ActForDiscord,
    IReadOnlyList<ApplicationClientRequest>? Clients);

/// <summary>A change to an application's own fields. An absent field is left as it is.</summary>
/// <param name="Name">What a person is shown.</param>
/// <param name="Audience">Its tokens' audience. Changing it ends every token a resource server holds.</param>
/// <param name="ManifestUrl">Where it serves its manifest; empty for none, which takes its actions out of the catalog.</param>
/// <param name="AccessLifetimeMinutes">Its access tokens' lifetime.</param>
/// <param name="DiscordApplications">The Discord applications its clients may present, replacing the list.</param>
/// <param name="ActForDiscord">Whether it may act for linked Discord users.</param>
internal sealed record ApplicationChange(
    string? Name,
    string? Audience,
    string? ManifestUrl,
    int? AccessLifetimeMinutes,
    IReadOnlyList<string>? DiscordApplications,
    bool? ActForDiscord);

/// <summary>A client to register with an application.</summary>
/// <param name="ClientId">Its id; one is made when absent.</param>
/// <param name="RedirectUris">Where codes may be sent, matched exactly.</param>
/// <param name="PostLogoutRedirectUris">Where a signed-out browser may be returned, matched exactly.</param>
/// <param name="Confidential">Whether it authenticates with a secret, made here and shown once.</param>
internal sealed record ApplicationClientRequest(
    string? ClientId,
    IReadOnlyList<string>? RedirectUris,
    IReadOnlyList<string>? PostLogoutRedirectUris,
    bool? Confidential);

/// <summary>
/// The applications this provider signs people in to, and the one code path every change to them takes.
/// </summary>
/// <remarks>
/// <para>
/// <b>One path, two doors.</b> The admin surface (<see cref="ApplicationEndpoints"/>) and the host command
/// (<see cref="ApplicationCommand"/>) both call this, so an application registered either way is checked
/// by the same rules, journaled as the same line and has its manifest read the same way.
/// </para>
/// <para>
/// <b>KGSM is an application, built in.</b> Its audience is the cluster id and its clients are the ones
/// members announce, the panels this anchor's configuration declares and the ones registered for the
/// cluster. It is never stored and cannot be changed here: its audience is a cluster setting, and a
/// different one would end every KGSM session.
/// </para>
/// <para>
/// <b>tks-auth's own admin routes are an application too, built in.</b> Its id is <c>auth</c>, the
/// namespace of the actions those routes require, its audience <c>tks-auth</c>, and its one client the
/// admin pages, declared from the issuer (<see cref="ClientRegistry"/>). A KGSM session reaches those
/// routes as well, so a cluster's Control Panel administers with the session it holds; no other
/// application's token does.
/// </para>
/// <para>
/// <b>A client secret is made here, shown once and stored as its hash.</b> It is 256 random bits, so a
/// fast hash is as strong as a slow one would be, and nobody can choose a weak one.
/// </para>
/// </remarks>
internal sealed partial class ApplicationRegistry(
    ClientRegistry clients,
    SqliteSessionRegistry store,
    AnchorOptions options,
    ApplicationCatalog catalog,
    AnchorJournal journal,
    ILogger<ApplicationRegistry> logger)
{
    /// <summary>An application's access lifetime when registered without one.</summary>
    internal const int DefaultAccessLifetimeMinutes = 5;

    /// <summary>The longest access lifetime an application may have.</summary>
    internal const int MaxAccessLifetimeMinutes = 60;

    /// <summary>KGSM's application.</summary>
    public Application Kgsm { get; } = new(
        Application.KgsmId, "KGSM", options.ClusterId, ManifestUrl: null, options.AccessLifetime,
        DiscordApplications: [], ActForDiscord: false, ApplicationSources.Builtin, DateTimeOffset.UnixEpoch);

    /// <summary>
    /// tks-auth's own application: its admin routes, signed in to by the admin pages' client. Its tokens
    /// are an application's like any other, listing the <c>auth:*</c> actions the account holds.
    /// </summary>
    public Application Provider { get; } = new(
        Application.ProviderId, "tks-auth", Application.ProviderAudience, ManifestUrl: null,
        TimeSpan.FromMinutes(DefaultAccessLifetimeMinutes), DiscordApplications: [], ActForDiscord: false,
        ApplicationSources.Builtin, DateTimeOffset.UnixEpoch);

    /// <summary>Every application, the built-in ones first.</summary>
    public IReadOnlyList<Application> All => [Kgsm, Provider, .. clients.Applications];

    /// <summary>The application with this id, the built-in ones included, or null.</summary>
    public Application? Find(string? id) => id switch
    {
        Application.KgsmId => Kgsm,
        Application.ProviderId => Provider,
        _ => clients.FindApplication(id),
    };

    /// <summary>The application a client signs people in to.</summary>
    /// <remarks>Null only for a client whose application is gone, which its removal took with it.</remarks>
    public Application? Of(RegisteredClient client) =>
        client.ApplicationId is { } id ? Find(id) : Kgsm;

    /// <summary>The clients an application signs people in through.</summary>
    public IReadOnlyList<RegisteredClient> ClientsOf(Application application) =>
        application.IsKgsm ? clients.Kgsm : clients.Of(application.Id);

    // ── Changes ───────────────────────────────────────────────────────────────

    /// <summary>Register an application and its clients, then read its manifest.</summary>
    public async Task<ApplicationResult> AddAsync(ApplicationRequest request, string actor, string? origin, CancellationToken ct)
    {
        string id = request.Id?.Trim() ?? "";
        if (!IdShape().IsMatch(id))
        {
            return ApplicationResult.Refused(ApplicationOutcome.Invalid,
                "An application id is 2–32 lowercase letters, digits or '-', beginning with a letter or a digit. "
                + "It is the namespace its actions are declared in.");
        }

        if (id == Application.KgsmId || id == ActionIds.AuthComponent || await catalog.IsKgsmNamespaceAsync(id, ct))
            return ApplicationResult.Refused(ApplicationOutcome.Taken, $"'{id}' is a KGSM component's namespace.");

        if (clients.FindApplication(id) is not null)
            return ApplicationResult.Refused(ApplicationOutcome.Taken, $"'{id}' is already an application.");

        DateTimeOffset now = DateTimeOffset.UtcNow;
        (Application? application, string? problem) = Shape(
            new Application(id, request.Name?.Trim() ?? "", request.Audience?.Trim() is { Length: > 0 } a ? a : id,
                Blank(request.ManifestUrl),
                TimeSpan.FromMinutes(request.AccessLifetimeMinutes ?? DefaultAccessLifetimeMinutes),
                [.. (request.DiscordApplications ?? []).Select(d => d.Trim())],
                request.ActForDiscord ?? false, ApplicationSources.Admin, now),
            except: null);
        if (application is null)
            return ApplicationResult.Refused(ApplicationOutcome.Invalid, problem!);

        var registered = new List<RegisteredClient>();
        var secrets = new List<IssuedSecret>();
        foreach (ApplicationClientRequest wanted in request.Clients ?? [])
        {
            (RegisteredClient? client, IssuedSecret? secret, string? clientProblem) = NewClient(application, wanted, now);
            if (client is null)
                return ApplicationResult.Refused(ApplicationOutcome.Invalid, clientProblem!);
            if (clients.IsTaken(client.ClientId) || registered.Any(c => c.ClientId == client.ClientId))
                return ApplicationResult.Refused(ApplicationOutcome.Taken, $"'{client.ClientId}' is already a client.");

            registered.Add(client);
            if (secret is not null)
                secrets.Add(secret);
        }

        switch (await store.AddApplicationAsync(application, registered, ct).ConfigureAwait(false))
        {
            case SqliteSessionRegistry.AddApplicationOutcome.IdTaken:
                return ApplicationResult.Refused(ApplicationOutcome.Taken, $"'{id}' is already an application.");
            case SqliteSessionRegistry.AddApplicationOutcome.AudienceTaken:
                return ApplicationResult.Refused(ApplicationOutcome.Taken,
                    $"'{application.Audience}' is already another application's audience.");
            case SqliteSessionRegistry.AddApplicationOutcome.ClientTaken:
                return ApplicationResult.Refused(ApplicationOutcome.Taken, "One of those client ids is already a client.");
        }

        await clients.ReloadAsync(ct).ConfigureAwait(false);
        await journal.ApplicationAsync(AuthEvents.ApplicationChanged, application.Id, application.Name, clientId: null,
            actor, origin, ct).ConfigureAwait(false);
        foreach (RegisteredClient client in registered)
        {
            await journal.ApplicationAsync(AuthEvents.ApplicationChanged, application.Id, application.Name, client.ClientId,
                actor, origin, ct).ConfigureAwait(false);
        }

        logger.LogInformation("{Actor} registered the application {Application} ({Name}), audience {Audience}, clients {Clients}",
            actor, application.Id, application.Name, application.Audience, string.Join(", ", registered.Select(c => c.ClientId)));

        ManifestState? manifest = application.ManifestUrl is null
            ? null
            : await catalog.RefreshAsync(application, ct).ConfigureAwait(false);

        return new ApplicationResult(ApplicationOutcome.Done, application, secrets, Manifest: manifest);
    }

    /// <summary>Change an application's own fields, reading its manifest again when its address changed.</summary>
    public async Task<ApplicationResult> SetAsync(string id, ApplicationChange change, string actor, string? origin, CancellationToken ct)
    {
        if (Find(id) is not { } current)
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"No application is called '{id}'.");
        if (current.IsBuiltin)
        {
            return ApplicationResult.Refused(ApplicationOutcome.BuiltIn, current.IsKgsm
                ? "KGSM's application is changed by configuring the cluster."
                : $"{current.Name}'s own application is built in.");
        }

        (Application? changed, string? problem) = Shape(current with
        {
            Name = change.Name?.Trim() ?? current.Name,
            Audience = change.Audience?.Trim() ?? current.Audience,
            ManifestUrl = change.ManifestUrl is null ? current.ManifestUrl : Blank(change.ManifestUrl),
            AccessLifetime = change.AccessLifetimeMinutes is { } minutes ? TimeSpan.FromMinutes(minutes) : current.AccessLifetime,
            DiscordApplications = change.DiscordApplications is { } discord ? [.. discord.Select(d => d.Trim())] : current.DiscordApplications,
            ActForDiscord = change.ActForDiscord ?? current.ActForDiscord,
        }, except: current.Id);
        if (changed is null)
            return ApplicationResult.Refused(ApplicationOutcome.Invalid, problem!);

        if (!await store.UpdateApplicationAsync(changed, ct).ConfigureAwait(false))
        {
            return clients.FindApplication(id) is null
                ? ApplicationResult.Refused(ApplicationOutcome.NotFound, $"No application is called '{id}'.")
                : ApplicationResult.Refused(ApplicationOutcome.Taken, $"'{changed.Audience}' is already another application's audience.");
        }

        await clients.ReloadAsync(ct).ConfigureAwait(false);
        if (Same(current, changed))
            return new ApplicationResult(ApplicationOutcome.Done, changed);

        await journal.ApplicationAsync(AuthEvents.ApplicationChanged, changed.Id, changed.Name, clientId: null,
            actor, origin, ct).ConfigureAwait(false);

        ManifestState? manifest = null;
        if (!string.Equals(current.ManifestUrl, changed.ManifestUrl, StringComparison.Ordinal))
        {
            // No address is no manifest: what the application declared leaves the catalog, as a member's
            // does when it is removed.
            if (changed.ManifestUrl is null)
                await catalog.ForgetAsync(changed, ct).ConfigureAwait(false);
            else
                manifest = await catalog.RefreshAsync(changed, ct).ConfigureAwait(false);
        }

        return new ApplicationResult(ApplicationOutcome.Done, changed, Manifest: manifest);
    }

    /// <summary>
    /// Remove an application: its clients, every session minted through them, and its actions from the
    /// catalog.
    /// </summary>
    public async Task<ApplicationResult> RemoveAsync(string id, string actor, string? origin, CancellationToken ct)
    {
        if (Find(id) is not { } current)
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"No application is called '{id}'.");
        if (current.IsBuiltin)
            return ApplicationResult.Refused(ApplicationOutcome.BuiltIn, $"{current.Name}'s application is built in.");

        if (!await store.RemoveApplicationAsync(id, ct).ConfigureAwait(false))
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"No application is called '{id}'.");

        await clients.ReloadAsync(ct).ConfigureAwait(false);
        await catalog.ForgetAsync(current, ct).ConfigureAwait(false);
        await journal.ApplicationAsync(AuthEvents.ApplicationRemoved, current.Id, current.Name, clientId: null,
            actor, origin, ct).ConfigureAwait(false);

        logger.LogInformation("{Actor} removed the application {Application}", actor, current.Id);
        return new ApplicationResult(ApplicationOutcome.Done, current);
    }

    /// <summary>Register one more client with an application.</summary>
    public async Task<ApplicationResult> AddClientAsync(
        string id, ApplicationClientRequest request, string actor, string? origin, CancellationToken ct)
    {
        if (Find(id) is not { } application)
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"No application is called '{id}'.");
        if (application.IsBuiltin)
        {
            return ApplicationResult.Refused(ApplicationOutcome.BuiltIn, application.IsKgsm
                ? "KGSM's clients are its members' surfaces, its declared panels and the clients registered for the cluster."
                : $"{application.Name}'s one client is its admin pages, built in.");
        }

        (RegisteredClient? client, IssuedSecret? secret, string? problem) = NewClient(application, request, DateTimeOffset.UtcNow);
        if (client is null)
            return ApplicationResult.Refused(ApplicationOutcome.Invalid, problem!);
        if (clients.IsTaken(client.ClientId) || !await store.AddApplicationClientAsync(client, ct).ConfigureAwait(false))
            return ApplicationResult.Refused(ApplicationOutcome.Taken, $"'{client.ClientId}' is already a client.");

        await clients.ReloadAsync(ct).ConfigureAwait(false);
        await journal.ApplicationAsync(AuthEvents.ApplicationChanged, application.Id, application.Name, client.ClientId,
            actor, origin, ct).ConfigureAwait(false);

        return new ApplicationResult(ApplicationOutcome.Done, application, secret is null ? [] : [secret]);
    }

    /// <summary>Remove one client of an application, ending every session minted through it.</summary>
    public async Task<ApplicationResult> RemoveClientAsync(
        string id, string clientId, string actor, string? origin, CancellationToken ct)
    {
        if (Find(id) is not { } application)
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"No application is called '{id}'.");
        if (application.IsBuiltin)
        {
            return ApplicationResult.Refused(ApplicationOutcome.BuiltIn, application.IsKgsm
                ? "KGSM's clients are removed from the cluster's client list."
                : $"{application.Name}'s one client is its admin pages, built in.");
        }

        if (!await store.RemoveApplicationClientAsync(id, clientId, ct).ConfigureAwait(false))
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"'{id}' has no client '{clientId}'.");

        await clients.ReloadAsync(ct).ConfigureAwait(false);
        await journal.ApplicationAsync(AuthEvents.ApplicationClientRemoved, application.Id, application.Name, clientId,
            actor, origin, ct).ConfigureAwait(false);

        return new ApplicationResult(ApplicationOutcome.Done, application);
    }

    /// <summary>
    /// Give a client of an application a new secret, which ends the old one at once. A public client
    /// given one becomes confidential.
    /// </summary>
    public async Task<ApplicationResult> RotateSecretAsync(
        string id, string clientId, string actor, string? origin, CancellationToken ct)
    {
        if (Find(id) is not { } application)
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"No application is called '{id}'.");
        if (clients.Find(clientId) is not { } client || client.ApplicationId != (application.IsKgsm ? null : application.Id)
            || client.Source != ClientSources.Admin)
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"'{id}' has no client '{clientId}' registered here.");

        string secret = ProviderCookies.NewSecret();
        if (!await store.SetClientSecretAsync(clientId, ProviderCookies.Hash(secret), ct).ConfigureAwait(false))
            return ApplicationResult.Refused(ApplicationOutcome.NotFound, $"'{id}' has no client '{clientId}' registered here.");

        await clients.ReloadAsync(ct).ConfigureAwait(false);
        await journal.ApplicationAsync(AuthEvents.ClientSecretRotated, application.Id, application.Name, clientId,
            actor, origin, ct).ConfigureAwait(false);

        logger.LogInformation("{Actor} gave the client {Client} of {Application} a new secret", actor, clientId, application.Id);
        return new ApplicationResult(ApplicationOutcome.Done, application, [new IssuedSecret(clientId, secret)]);
    }

    // ── Rules ─────────────────────────────────────────────────────────────────

    /// <summary>The application, or why it cannot be one.</summary>
    /// <param name="application">What was asked for.</param>
    /// <param name="except">The application being changed, whose own audience is no conflict.</param>
    private (Application? Application, string? Problem) Shape(Application application, string? except)
    {
        if (application.Name.Length is 0 or > 80)
            return (null, "An application needs a name of at most 80 characters.");

        string audience = application.Audience;
        if (audience.Length is 0 or > 200 || audience.Any(char.IsWhiteSpace))
            return (null, "An audience is up to 200 characters with no spaces.");

        // KGSM's audience and this provider's own admin routes' are theirs, and the issuer is what an
        // application's refresh tokens are audienced to: any of them would make a token for this
        // application one something else accepts.
        if (string.Equals(audience, options.ClusterId, StringComparison.Ordinal)
            || string.Equals(audience, options.Issuer, StringComparison.Ordinal)
            || string.Equals(audience, Application.ProviderAudience, StringComparison.Ordinal))
            return (null, $"'{audience}' is not an audience an application may have: it is KGSM's or this provider's own.");

        if (clients.Applications.Any(a => a.Id != except && string.Equals(a.Audience, audience, StringComparison.Ordinal)))
            return (null, $"'{audience}' is already another application's audience.");

        if (application.ManifestUrl is { } manifest && ClientRegistry.Problem(manifest) is { } problem)
            return (null, $"The manifest address '{manifest}': {problem}");

        int minutes = (int)application.AccessLifetime.TotalMinutes;
        if (minutes < 1 || minutes > MaxAccessLifetimeMinutes || application.AccessLifetime != TimeSpan.FromMinutes(minutes))
            return (null, $"An access lifetime is a whole number of minutes from 1 to {MaxAccessLifetimeMinutes}.");

        if (application.DiscordApplications.FirstOrDefault(d => !SnowflakeShape().IsMatch(d)) is { } bad)
            return (null, $"'{bad}' is not a Discord application id.");

        return (application with { DiscordApplications = [.. application.DiscordApplications.Distinct(StringComparer.Ordinal)] }, null);
    }

    private static (RegisteredClient? Client, IssuedSecret? Secret, string? Problem) NewClient(
        Application application, ApplicationClientRequest request, DateTimeOffset now)
    {
        string? secret = request.Confidential == true ? ProviderCookies.NewSecret() : null;
        (RegisteredClient? client, string? problem) = ClientRegistry.Shape(
            request.ClientId, application.Name, request.RedirectUris, request.PostLogoutRedirectUris,
            application.Id, secret is null ? null : ProviderCookies.Hash(secret), now);

        return client is null
            ? (null, null, problem)
            : (client, secret is null ? null : new IssuedSecret(client.ClientId, secret), null);
    }

    private static bool Same(Application a, Application b) =>
        a.Name == b.Name && a.Audience == b.Audience && a.ManifestUrl == b.ManifestUrl
        && a.AccessLifetime == b.AccessLifetime && a.ActForDiscord == b.ActForDiscord
        && a.DiscordApplications.SequenceEqual(b.DiscordApplications, StringComparer.Ordinal);

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,31}$")]
    private static partial Regex IdShape();

    [GeneratedRegex("^[0-9]{5,25}$")]
    private static partial Regex SnowflakeShape();
}
