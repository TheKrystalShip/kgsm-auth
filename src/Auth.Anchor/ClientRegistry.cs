using System.Security.Cryptography;
using System.Text.RegularExpressions;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The clients this provider issues codes to, and the only places it sends a browser back.
/// </summary>
/// <remarks>
/// <para>
/// <b>Registration is the consent.</b> There is no consent screen: a client is here because a member of
/// the cluster announced it or an administrator put it here, and either is a decision about the whole
/// cluster rather than a question for the person signing in.
/// </para>
/// <para>
/// <b>Every URI is matched exactly.</b> A prefix or a pattern is a redirect this provider did not decide
/// to make, and an authorization endpoint that redirects anywhere a pattern admits is an open redirect
/// carrying a code.
/// </para>
/// <para>
/// Held in memory and reloaded after every write, because it is read on every request that carries an
/// <c>Origin</c> and on every authorization, and the only writer is this process.
/// </para>
/// <para>
/// <b>Three sources.</b> A member announces the panel it serves; an administrator registers anything
/// else; and a panel on a static host, which no member can announce, is declared in this anchor's
/// configuration. A declared panel is never stored — it is what the deploy said this process should
/// serve, so it comes back with every start and goes when the setting does, and it wins over a stored
/// client of the same id.
/// </para>
/// </remarks>
internal sealed partial class ClientRegistry
{
    private readonly SqliteSessionRegistry _store;
    private readonly IReadOnlyList<RegisteredClient> _declared;
    private volatile Snapshot _snapshot;

    private sealed record Snapshot(
        IReadOnlyDictionary<string, RegisteredClient> ById, IReadOnlySet<string> Origins);

    public ClientRegistry(SqliteSessionRegistry store, IReadOnlyList<string>? panelOrigins = null)
    {
        _store = store;
        (_declared, RefusedPanelOrigins) = Declare(panelOrigins ?? [], DateTimeOffset.UtcNow);
        _snapshot = Load(store.ListClientsAsync().GetAwaiter().GetResult());
    }

    /// <summary>Configured panel origins that cannot be a client, each with why.</summary>
    public IReadOnlyList<(string Origin, string Problem)> RefusedPanelOrigins { get; }

    /// <summary>The panels this anchor's configuration declares.</summary>
    public IReadOnlyList<RegisteredClient> Declared => _declared;

    /// <summary>
    /// A client per configured panel origin, at the paths every Control Panel lands on. Its id is the
    /// origin's host, with the port when there is one, which is stable across restarts and readable in a
    /// listing.
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

            string id = uri.IsDefaultPort ? uri.Host.ToLowerInvariant() : $"{uri.Host.ToLowerInvariant()}-{uri.Port}";
            if (!ClientIdShape().IsMatch(id))
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

    /// <summary>Every registered client.</summary>
    public IReadOnlyList<RegisteredClient> All => [.. _snapshot.ById.Values.OrderBy(c => c.ClientId, StringComparer.Ordinal)];

    /// <summary>The client with this id, or null.</summary>
    public RegisteredClient? Find(string? clientId) =>
        clientId is { Length: > 0 } && _snapshot.ById.TryGetValue(clientId, out RegisteredClient? client) ? client : null;

    /// <summary>
    /// Whether <paramref name="origin"/> is where some registered client lives. Such an origin may read
    /// what this provider publishes and exchange codes, and nothing that reads its cookie.
    /// </summary>
    public bool IsClientOrigin(string origin) => _snapshot.Origins.Contains(origin);

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

    /// <summary>Register an administrator's client.</summary>
    public async Task<(RegisterOutcome Outcome, RegisteredClient? Client, string? Problem)> RegisterAsync(
        ClientRegistration request, DateTimeOffset now, CancellationToken ct)
    {
        string name = request.Name?.Trim() ?? "";
        if (name.Length is 0 or > 80)
            return (RegisterOutcome.Invalid, null, "A client needs a name of at most 80 characters.");

        string id = string.IsNullOrWhiteSpace(request.ClientId)
            ? "cli_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8))
            : request.ClientId.Trim();
        if (!ClientIdShape().IsMatch(id))
            return (RegisterOutcome.Invalid, null,
                "A client id is 3–64 lowercase letters, digits, '.', '_' or '-', beginning with a letter or a digit.");

        IReadOnlyList<string> redirects = request.RedirectUris ?? [];
        if (redirects.Count == 0)
            return (RegisterOutcome.Invalid, null, "A client needs at least one redirect URI.");

        foreach (string uri in redirects.Concat(request.PostLogoutRedirectUris ?? []))
        {
            if (Problem(uri) is { } problem)
                return (RegisterOutcome.Invalid, null, $"'{uri}': {problem}");
        }

        var client = new RegisteredClient(
            id, name, [.. redirects.Distinct(StringComparer.Ordinal)],
            [.. (request.PostLogoutRedirectUris ?? []).Distinct(StringComparer.Ordinal)],
            ClientSources.Admin, MemberId: null, now);

        // A declared panel is not stored, so the store would accept its id and the declaration would
        // then hide the row it wrote.
        if (Find(id) is { Source: ClientSources.Config })
            return (RegisterOutcome.Taken, null, $"'{id}' is already a client.");

        if (!await _store.AddClientAsync(client, ct).ConfigureAwait(false))
            return (RegisterOutcome.Taken, null, $"'{id}' is already a client.");

        await ReloadAsync(ct).ConfigureAwait(false);
        return (RegisterOutcome.Registered, client, null);
    }

    /// <summary>What removing a client did.</summary>
    internal enum RemoveOutcome { Removed, NotFound, Announced, Declared }

    /// <summary>
    /// Remove an administrator's client. A member's leaves when the member stops announcing it, and a
    /// declared panel when the configuration stops declaring it.
    /// </summary>
    public async Task<RemoveOutcome> RemoveAsync(string clientId, CancellationToken ct)
    {
        if (Find(clientId) is not { } client)
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
    /// Each announcement's paths are joined to the browser address the member's own roster row carries,
    /// so a member announces only somewhere on the address the cluster hands out for it. A member with no
    /// such address announces nothing reachable, and is skipped rather than registered at a guess.
    /// </remarks>
    /// <returns>Whether the set changed.</returns>
    public async Task<bool> SyncMembersAsync(IReadOnlyList<MemberRow> roster, DateTimeOffset now, CancellationToken ct)
    {
        var announced = new List<RegisteredClient>();
        foreach (MemberRow row in roster)
        {
            if (ClusterClientAnnouncement.Read(row.Read(ClusterClientAnnouncement.FactKey)) is not { } announcement)
                continue;

            string address = MemberCandidates.ClientUrl(MemberCandidates.Decode(row.Candidates)).TrimEnd('/');
            if (address.Length == 0 || Problem(address) is not null)
                continue;

            string[] redirects = [.. Join(address, announcement.RedirectPaths)];
            if (redirects.Length == 0)
                continue;

            string name = string.IsNullOrWhiteSpace(announcement.Name) ? row.MemberId : announcement.Name.Trim();
            announced.Add(new RegisteredClient(
                row.MemberId, name.Length > 80 ? name[..80] : name, redirects,
                [.. Join(address, announcement.PostLogoutRedirectPaths)],
                ClientSources.Member, row.MemberId, now));
        }

        if (!await _store.ReplaceMemberClientsAsync(announced, ct).ConfigureAwait(false))
            return false;

        await ReloadAsync(ct).ConfigureAwait(false);
        return true;
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

    private async Task ReloadAsync(CancellationToken ct) =>
        _snapshot = Load(await _store.ListClientsAsync(ct).ConfigureAwait(false));

    private Snapshot Load(IReadOnlyList<RegisteredClient> stored)
    {
        var byId = stored.ToDictionary(c => c.ClientId, StringComparer.Ordinal);
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

        return new Snapshot(byId, origins);
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{2,63}$")]
    private static partial Regex ClientIdShape();
}
