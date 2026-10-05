using System.Security.Cryptography;
using System.Text.RegularExpressions;

using TheKrystalShip.Auth.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// The clients this provider issues codes to, and the only places it sends a browser back.
/// </summary>
/// <remarks>
/// <para>
/// <b>Registration is the consent.</b> There is no consent screen: a client is here because a member of
/// the cluster announced it or somebody registered it here, and either is a decision about the whole
/// cluster rather than a question for the person signing in.
/// </para>
/// <para>
/// <b>Every URI is matched exactly.</b> A prefix or a pattern is a redirect this provider did not decide
/// to make, and an authorization endpoint that redirects anywhere a pattern admits is an open redirect
/// carrying a code.
/// </para>
/// <para>
/// Held in memory, because it is read on every request that carries an <c>Origin</c> and on every
/// authorization. It is reloaded after every write this process makes, and when the store's generation
/// says another process — the host command — has written since.
/// </para>
/// <para>
/// <b>Every client belongs to an application.</b> KGSM's clients come from three sources: a member
/// announces the panel it serves; anything else is registered here by hand; and a panel on a static
/// host, which no member can announce, is declared in this anchor's configuration. A declared panel is
/// never stored — it is what the deploy said this process should serve, so it comes back with every
/// start and goes when the setting does, and it wins over a stored client of the same id. An
/// application outside KGSM has the clients registered for it, and only those
/// (<see cref="ApplicationRegistry"/>). tks-auth's own admin pages are one more declared client, on the
/// issuer's origin.
/// </para>
/// </remarks>
internal sealed partial class ClientRegistry
{
    /// <summary>How long a read trusts the snapshot before asking the store whether it has moved.</summary>
    private static readonly TimeSpan GenerationCheck = TimeSpan.FromSeconds(1);

    private readonly SqliteSessionRegistry _store;
    private readonly IReadOnlyList<RegisteredClient> _declared;
    private readonly Lock _reload = new();
    private volatile Snapshot _snapshot;
    private long _checkedAt;

    private sealed record Snapshot(
        IReadOnlyDictionary<string, RegisteredClient> ById,
        IReadOnlySet<string> Origins,
        IReadOnlyDictionary<string, Application> Applications,
        long Generation);

    /// <param name="store">The session store the registered clients and applications live in.</param>
    /// <param name="panelOrigins">Origins a Control Panel is served from with no member behind it.</param>
    /// <param name="issuer">
    /// This provider's issuer; when it is a URL, the admin pages' client is declared on its origin.
    /// </param>
    public ClientRegistry(SqliteSessionRegistry store, IReadOnlyList<string>? panelOrigins = null, string? issuer = null)
    {
        _store = store;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        (IReadOnlyList<RegisteredClient> panels, RefusedPanelOrigins) = Declare(panelOrigins ?? [], now);
        _declared = AdminPages(issuer, now) is { } admin ? [.. panels, admin] : panels;
        _snapshot = Read();
        _checkedAt = Environment.TickCount64;
    }

    /// <summary>
    /// The admin pages' client: public, built in, and sending its codes and sign-outs back to the pages on
    /// the issuer's own origin. Null when the issuer is not a URL, where no OpenID Connect door is served.
    /// </summary>
    /// <remarks>
    /// Declared, never stored, like a configured panel: it is what this build serves, so it comes back on
    /// every start, and nothing can register over it or remove it.
    /// </remarks>
    private static RegisteredClient? AdminPages(string? issuer, DateTimeOffset now)
    {
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("https" or "http"))
            return null;

        string pages = uri.GetLeftPart(UriPartial.Authority) + Application.ProviderPagesPath;
        return new RegisteredClient(
            Application.ProviderClientId, "tks-auth", [pages], [pages], ClientSources.Builtin, MemberId: null, now,
            Application.ProviderId);
    }

    /// <summary>The snapshot, reloaded first when another process has written the store since it was read.</summary>
    private Snapshot Current
    {
        get
        {
            long now = Environment.TickCount64;
            if (now - Interlocked.Read(ref _checkedAt) < (long)GenerationCheck.TotalMilliseconds)
                return _snapshot;

            lock (_reload)
            {
                if (now - _checkedAt >= (long)GenerationCheck.TotalMilliseconds)
                {
                    if (_store.RegistryGeneration() != _snapshot.Generation)
                        _snapshot = Read();
                    Interlocked.Exchange(ref _checkedAt, now);
                }

                return _snapshot;
            }
        }
    }

    /// <summary>Configured panel origins that cannot be a client, each with why.</summary>
    public IReadOnlyList<(string Origin, string Problem)> RefusedPanelOrigins { get; }

    /// <summary>The panels this anchor's configuration declares.</summary>
    public IReadOnlyList<RegisteredClient> Declared => _declared;

    /// <summary>
    /// A client per configured panel origin, at the paths every Control Panel lands on. Its id is
    /// <see cref="ClusterClientAnnouncement.ClientIdFor"/> the origin, the one a panel loaded there
    /// derives for itself.
    /// </summary>
    private static (IReadOnlyList<RegisteredClient> Declared, IReadOnlyList<(string, string)> Refused) Declare(
        IReadOnlyList<string> origins, DateTimeOffset now)
    {
        var declared = new List<RegisteredClient>();
        var refused = new List<(string, string)>();
        ClusterClientAnnouncement panel = ClusterClientAnnouncement.ControlPanel;

        foreach (string origin in origins)
        {
            if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? uri) || uri.AbsolutePath != "/"
                || !string.IsNullOrEmpty(uri.Query))
            {
                refused.Add((origin, "not an origin: a scheme and a host, with no path"));
                continue;
            }

            if (Problem(origin) is { } problem)
            {
                refused.Add((origin, problem));
                continue;
            }

            if (ClusterClientAnnouncement.ClientIdFor(origin) is not { } id || !ClientIdShape().IsMatch(id))
            {
                refused.Add((origin, "its host cannot name a client"));
                continue;
            }

            string address = uri.GetLeftPart(UriPartial.Authority);
            declared.Add(new RegisteredClient(
                id, panel.Name, [.. Join(address, panel.RedirectPaths)], [.. Join(address, panel.PostLogoutRedirectPaths)],
                ClientSources.Config, MemberId: null, now));
        }

        return (declared, refused);
    }

    /// <summary>Every registered client, of every application.</summary>
    public IReadOnlyList<RegisteredClient> All => [.. Current.ById.Values.OrderBy(c => c.ClientId, StringComparer.Ordinal)];

    /// <summary>KGSM's clients: announced, declared and registered for the cluster.</summary>
    public IReadOnlyList<RegisteredClient> Kgsm => [.. All.Where(c => c.ApplicationId is null)];

    /// <summary>The clients of one application outside KGSM.</summary>
    public IReadOnlyList<RegisteredClient> Of(string applicationId) =>
        [.. All.Where(c => string.Equals(c.ApplicationId, applicationId, StringComparison.Ordinal))];

    /// <summary>The client with this id, or null.</summary>
    public RegisteredClient? Find(string? clientId) =>
        clientId is { Length: > 0 } && Current.ById.TryGetValue(clientId, out RegisteredClient? client) ? client : null;

    /// <summary>Every application registered here, KGSM's aside.</summary>
    public IReadOnlyList<Application> Applications =>
        [.. Current.Applications.Values.OrderBy(a => a.Id, StringComparer.Ordinal)];

    /// <summary>The registered application with this id, or null. KGSM's is never stored.</summary>
    public Application? FindApplication(string? applicationId) =>
        applicationId is { Length: > 0 } && Current.Applications.TryGetValue(applicationId, out Application? a) ? a : null;

    /// <summary>
    /// Whether <paramref name="origin"/> is where some registered client lives, of any application. Such
    /// an origin may read what this provider publishes and exchange codes, and nothing that reads its
    /// cookie.
    /// </summary>
    public bool IsClientOrigin(string origin) => Current.Origins.Contains(origin);

    /// <summary>
    /// Every origin one of KGSM's clients lives at — what members admit across origins. An application
    /// outside KGSM is nothing a member serves, so none of its origins is published to one.
    /// </summary>
    public IReadOnlyCollection<string> Origins =>
        [.. Kgsm.SelectMany(c => c.RedirectUris.Concat(c.PostLogoutRedirectUris))
            .Where(u => Uri.TryCreate(u, UriKind.Absolute, out _))
            .Select(OriginOf)
            .Distinct(StringComparer.OrdinalIgnoreCase)];

    /// <summary>Whether <paramref name="uri"/> is one of the client's redirect URIs, exactly.</summary>
    public static bool Redirects(RegisteredClient client, string? uri) =>
        uri is { Length: > 0 } && client.RedirectUris.Contains(uri, StringComparer.Ordinal);

    /// <summary>Whether <paramref name="uri"/> is one of the client's post-sign-out URIs, exactly.</summary>
    public static bool ReturnsAfterSignOut(RegisteredClient client, string? uri) =>
        uri is { Length: > 0 } && client.PostLogoutRedirectUris.Contains(uri, StringComparer.Ordinal);

    /// <summary>The origin of a URI a client is registered with.</summary>
    public static string OriginOf(string uri) => new Uri(uri).GetLeftPart(UriPartial.Authority);

    /// <summary>What registering a client did.</summary>
    internal enum RegisterOutcome { Registered, Invalid, Taken }

    /// <summary>Register a public client of KGSM's by hand.</summary>
    public async Task<(RegisterOutcome Outcome, RegisteredClient? Client, string? Problem)> RegisterAsync(
        ClientRegistration request, DateTimeOffset now, CancellationToken ct)
    {
        string name = request.Name?.Trim() ?? "";
        if (name.Length is 0 or > 80)
            return (RegisterOutcome.Invalid, null, "A client needs a name of at most 80 characters.");

        (RegisteredClient? client, string? problem) = Shape(
            request.ClientId, name, request.RedirectUris, request.PostLogoutRedirectUris,
            applicationId: null, secretHash: null, now);
        if (client is null)
            return (RegisterOutcome.Invalid, null, problem);

        if (IsTaken(client.ClientId))
            return (RegisterOutcome.Taken, null, $"'{client.ClientId}' is already a client.");

        if (!await _store.AddClientAsync(client, ct).ConfigureAwait(false))
            return (RegisterOutcome.Taken, null, $"'{client.ClientId}' is already a client.");

        await ReloadAsync(ct).ConfigureAwait(false);
        return (RegisterOutcome.Registered, client, null);
    }

    /// <summary>
    /// A client registered by hand, or why the request cannot be one.
    /// </summary>
    /// <remarks>
    /// A public client needs somewhere to send a code. A confidential one may have nowhere: a service
    /// that authenticates with its secret and exchanges a token never takes a browser through a sign-in.
    /// </remarks>
    internal static (RegisteredClient? Client, string? Problem) Shape(
        string? clientId, string name, IReadOnlyList<string>? redirectUris, IReadOnlyList<string>? postLogoutUris,
        string? applicationId, string? secretHash, DateTimeOffset now)
    {
        string id = string.IsNullOrWhiteSpace(clientId)
            ? "cli_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8))
            : clientId.Trim();
        if (!ClientIdShape().IsMatch(id))
            return (null,
                "A client id is 3–64 lowercase letters, digits, '.', '_' or '-', beginning with a letter or a digit.");

        IReadOnlyList<string> redirects = redirectUris ?? [];
        if (redirects.Count == 0 && secretHash is null)
            return (null, "A public client needs at least one redirect URI.");

        foreach (string uri in redirects.Concat(postLogoutUris ?? []))
        {
            if (Problem(uri) is { } problem)
                return (null, $"'{uri}': {problem}");
        }

        return (new RegisteredClient(
            id, name, [.. redirects.Distinct(StringComparer.Ordinal)],
            [.. (postLogoutUris ?? []).Distinct(StringComparer.Ordinal)],
            ClientSources.Admin, MemberId: null, now, applicationId, secretHash), null);
    }

    /// <summary>
    /// Whether a client id is in use. A declared panel is not stored, so the store would accept its id
    /// and the declaration would then hide the row it wrote.
    /// </summary>
    internal bool IsTaken(string clientId) => Find(clientId) is not null;

    /// <summary>What removing a client did.</summary>
    internal enum RemoveOutcome { Removed, NotFound, Announced, Declared }

    /// <summary>
    /// Remove a client registered by hand. A member's leaves when the member stops announcing it, and a
    /// declared panel when the configuration stops declaring it.
    /// </summary>
    public async Task<RemoveOutcome> RemoveAsync(string clientId, CancellationToken ct)
    {
        // An application's client is removed through its application, never through KGSM's list.
        if (Find(clientId) is not { ApplicationId: null } client)
            return RemoveOutcome.NotFound;
        if (client.Source == ClientSources.Config)
            return RemoveOutcome.Declared;
        if (client.Source != ClientSources.Admin)
            return RemoveOutcome.Announced;

        bool removed = await _store.RemoveAdminClientAsync(clientId, ct).ConfigureAwait(false);
        await ReloadAsync(ct).ConfigureAwait(false);
        return removed ? RemoveOutcome.Removed : RemoveOutcome.NotFound;
    }

    /// <summary>
    /// Make the members' clients what the roster currently announces.
    /// </summary>
    /// <remarks>
    /// Each announcement's paths are joined to every address it names that the member's own roster row
    /// carries as a browser address — or, naming none of them, to the row's browser address — so a member
    /// announces only somewhere the cluster hands out for it, and each client id is the one a surface
    /// loaded from that address derives. A member with no such address announces nothing reachable, and
    /// is skipped rather than registered at a guess.
    /// </remarks>
    /// <returns>Whether the set changed.</returns>
    public async Task<bool> SyncMembersAsync(IReadOnlyList<MemberRow> roster, DateTimeOffset now, CancellationToken ct)
    {
        var announced = new List<RegisteredClient>();
        var taken = new HashSet<string>(StringComparer.Ordinal);
        foreach (MemberRow row in roster)
        {
            if (ClusterClientAnnouncement.Read(row.Read(ClusterClientAnnouncement.FactKey)) is not { } announcement)
                continue;

            string name = string.IsNullOrWhiteSpace(announcement.Name) ? row.MemberId : announcement.Name.Trim();
            foreach (string address in ServedAt(announcement, MemberCandidates.Decode(row.Candidates)))
            {
                if (Problem(address) is not null
                    || ClusterClientAnnouncement.ClientIdFor(address) is not { } id || !ClientIdShape().IsMatch(id)
                    || !taken.Add(id))
                    continue;

                string[] redirects = [.. Join(address, announcement.RedirectPaths)];
                if (redirects.Length == 0)
                    continue;

                announced.Add(new RegisteredClient(
                    id, name.Length > 80 ? name[..80] : name, redirects,
                    [.. Join(address, announcement.PostLogoutRedirectPaths)],
                    ClientSources.Member, row.MemberId, now));
            }
        }

        if (!await _store.ReplaceMemberClientsAsync(announced, ct).ConfigureAwait(false))
            return false;

        await ReloadAsync(ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// The addresses a member's surface is registered at: those its announcement names that its row also
    /// carries as browser addresses, in the row's order, or the row's browser address alone when it names
    /// none of them. Empty when the row carries no browser address.
    /// </summary>
    internal static IReadOnlyList<string> ServedAt(
        ClusterClientAnnouncement announcement, IReadOnlyList<MemberCandidate> candidates)
    {
        var named = new HashSet<string>(
            (announcement.Addresses ?? []).Select(ClusterClientOrigins.Normalize).OfType<string>(),
            StringComparer.Ordinal);

        string[] served = [.. candidates
            .Where(c => c.Client)
            .Select(c => c.Url.TrimEnd('/'))
            .Where(url => ClusterClientOrigins.Normalize(url) is { } origin && named.Contains(origin))
            .Distinct(StringComparer.OrdinalIgnoreCase)];
        if (served.Length > 0)
            return served;

        string primary = MemberCandidates.ClientUrl(candidates).TrimEnd('/');
        return primary.Length == 0 ? [] : [primary];
    }

    private static IEnumerable<string> Join(string address, IReadOnlyList<string>? paths)
    {
        foreach (string path in paths ?? [])
        {
            // A path, and only a path: "//host" is a scheme-relative URL naming somewhere else entirely.
            if (path.StartsWith('/') && !path.StartsWith("//", StringComparison.Ordinal)
                && !path.Contains('#') && !path.Contains('\\'))
                yield return address + path;
        }
    }

    /// <summary>
    /// Why <paramref name="uri"/> cannot be registered, or null when it can.
    /// </summary>
    /// <remarks>
    /// <para>
    /// HTTPS, or plain HTTP where the cluster itself accepts plaintext — this machine, a private network,
    /// a local name (<c>MemberHandshakeService.IsTransportAcceptable</c>). A cluster of one on a LAN serves
    /// its panel over plain HTTP, and refusing it here would leave the machine with nowhere a code can be
    /// sent. On such a network the operator owns the wire, and a code seen on it is still worthless
    /// without the verifier the browser holds. Anywhere else a code in the clear crosses somebody's path.
    /// </para>
    /// <para>
    /// No fragment, which a code redirect cannot carry, and no user information, which is how a URL is
    /// dressed as another host.
    /// </para>
    /// </remarks>
    internal static string? Problem(string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? parsed))
            return "not an absolute URI";
        if (!string.IsNullOrEmpty(parsed.Fragment) || uri.Contains('#'))
            return "a redirect cannot carry a fragment";
        if (!string.IsNullOrEmpty(parsed.UserInfo))
            return "a redirect cannot carry user information";
        if (parsed.Scheme is not ("https" or "http"))
            return "only https, or http on this machine or a private network";
        if (MemberHandshakeService.IsTransportAcceptable(uri))
            return null;
        return "only https, or http on this machine or a private network";
    }

    /// <summary>Read the store again, after a write this process made.</summary>
    internal Task ReloadAsync(CancellationToken ct)
    {
        lock (_reload)
        {
            _snapshot = Read();
            Interlocked.Exchange(ref _checkedAt, Environment.TickCount64);
        }

        return Task.CompletedTask;
    }

    private Snapshot Read()
    {
        // The generation first: a write landing between it and the lists is picked up by the next check
        // rather than hidden under a generation that already counts it.
        long generation = _store.RegistryGeneration();
        IReadOnlyList<RegisteredClient> stored = _store.ListClientsAsync().GetAwaiter().GetResult();
        IReadOnlyList<Application> applications = _store.ListApplicationsAsync().GetAwaiter().GetResult();
        return Load(stored, applications, generation);
    }

    private Snapshot Load(IReadOnlyList<RegisteredClient> stored, IReadOnlyList<Application> applications, long generation)
    {
        var apps = applications.ToDictionary(a => a.Id, StringComparer.Ordinal);

        // An application's client is shown by its application's name, which a rename changes in one place.
        var byId = stored
            .Select(c => c.ApplicationId is { } app && apps.TryGetValue(app, out Application? owner) ? c with { Name = owner.Name } : c)
            .ToDictionary(c => c.ClientId, StringComparer.Ordinal);
        foreach (RegisteredClient client in _declared)
            byId[client.ClientId] = client;

        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (RegisteredClient client in byId.Values)
        {
            foreach (string uri in client.RedirectUris.Concat(client.PostLogoutRedirectUris))
            {
                if (Uri.TryCreate(uri, UriKind.Absolute, out _))
                    origins.Add(OriginOf(uri));
            }
        }

        return new Snapshot(byId, origins, apps, generation);
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{2,63}$")]
    private static partial Regex ClientIdShape();
}
