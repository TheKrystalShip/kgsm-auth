using TheKrystalShip.Auth.Journal;
using TheKrystalShip.KGSM.Extensions;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// <c>tks-auth app …</c>: register and administer applications from the provider's host.
/// </summary>
/// <remarks>
/// <para>
/// The same fields and the same rules as the admin surface, because it is the same code:
/// <see cref="ApplicationRegistry"/>, composed here over the stores and the journal the daemon uses. A
/// change is journaled with <c>local:&lt;user&gt;</c> as the actor, and the manifest of an application it
/// registers is read at once.
/// </para>
/// <para>
/// Run as the provider's service account, so it writes the files the daemon writes. The running daemon
/// sees the change within a second, by the registry's generation; what the change did to the catalog
/// reaches a KGSM cluster from the authority outbox, which the daemon drains.
/// </para>
/// </remarks>
internal static class ApplicationCommand
{
    /// <summary>The first argument that selects this command instead of the daemon.</summary>
    internal const string Verb = "app";

    private const string Usage =
        """
        usage: tks-auth app list
               tks-auth app add <id> --name <name> [--audience <audience>] [--manifest <url>]
                                [--lifetime <minutes>] [--discord-app <id>]... [--act-for-discord]
                                [--client-id <id>] [--redirect <uri>]... [--post-logout <uri>]... [--confidential]
               tks-auth app set <id> [--name <name>] [--audience <audience>] [--manifest <url> | --no-manifest]
                                [--lifetime <minutes>] [--discord-app <id>]... [--no-discord-apps]
                                [--act-for-discord | --no-act-for-discord]
               tks-auth app remove <id>
               tks-auth app client add <id> [--client-id <id>] [--redirect <uri>]... [--post-logout <uri>]...
                                [--confidential]
               tks-auth app client remove <id> <client-id>
               tks-auth app rotate-secret <id> <client-id>
        """;

    /// <summary>Run the command. Returns the process's exit code.</summary>
    internal static async Task<int> RunAsync(string[] args, AnchorOptions options, TextWriter? output = null)
    {
        TextWriter stdout = output ?? Console.Out;
        string actor = KgsmActor.Format(KgsmActorProvider.Local, Environment.UserName);

        await using ServiceProvider provider = Compose(options);
        var registry = provider.GetRequiredService<ApplicationRegistry>();
        CancellationToken ct = CancellationToken.None;

        switch (args)
        {
            case [Verb, "list"]:
                foreach (Application application in registry.All)
                    Describe(stdout, application, registry, provider.GetRequiredService<ApplicationCatalog>());
                return 0;

            case [Verb, "add", { Length: > 0 } id, .. var rest] when Options.Parse(rest) is { } o:
            {
                ApplicationClientRequest? client = o.Has("client-id") || o.Has("redirect") || o.Has("confidential")
                    ? new ApplicationClientRequest(o.One("client-id"), o.Many("redirect"), o.Many("post-logout"), o.Has("confidential"))
                    : null;
                return Report(stdout, await registry.AddAsync(
                    new ApplicationRequest(id, o.One("name"), o.One("audience"), o.One("manifest"), o.Minutes("lifetime"),
                        o.Many("discord-app"), o.Has("act-for-discord"), client is null ? [] : [client]),
                    actor, origin: null, ct), registry, provider);
            }

            case [Verb, "set", { Length: > 0 } id, .. var rest] when Options.Parse(rest) is { } o:
                return Report(stdout, await registry.SetAsync(id,
                    new ApplicationChange(
                        o.One("name"),
                        o.One("audience"),
                        o.Has("no-manifest") ? "" : o.One("manifest"),
                        o.Minutes("lifetime"),
                        o.Has("no-discord-apps") ? [] : o.Many("discord-app") is { Count: > 0 } discord ? discord : null,
                        o.Has("act-for-discord") ? true : o.Has("no-act-for-discord") ? false : null),
                    actor, origin: null, ct), registry, provider);

            case [Verb, "remove", { Length: > 0 } id]:
                return Report(stdout, await registry.RemoveAsync(id, actor, origin: null, ct), registry, provider);

            case [Verb, "client", "add", { Length: > 0 } id, .. var rest] when Options.Parse(rest) is { } o:
                return Report(stdout, await registry.AddClientAsync(id,
                    new ApplicationClientRequest(o.One("client-id"), o.Many("redirect"), o.Many("post-logout"), o.Has("confidential")),
                    actor, origin: null, ct), registry, provider);

            case [Verb, "client", "remove", { Length: > 0 } id, { Length: > 0 } clientId]:
                return Report(stdout, await registry.RemoveClientAsync(id, clientId, actor, origin: null, ct), registry, provider);

            case [Verb, "rotate-secret", { Length: > 0 } id, { Length: > 0 } clientId]:
                return Report(stdout, await registry.RotateSecretAsync(id, clientId, actor, origin: null, ct), registry, provider);

            default:
                Console.Error.WriteLine(Usage);
                return 2;
        }
    }

    /// <summary>
    /// The registry over the daemon's own files: its session store, its account store and its journal.
    /// </summary>
    private static ServiceProvider Compose(AnchorOptions options)
    {
        ServiceCollection services = new();

        // Warnings and worse only: what the command did is its own output, and the journal holds the record.
        services.AddLogging(logging => logging.AddSystemdConsole().SetMinimumLevel(LogLevel.Warning));
        services.AddSingleton(options);
        services.AddSingleton(TimeProvider.System);
        services.AddKgsmJournal(AnchorJournal.ProducerId, typeof(AnchorJournal).Assembly);
        services.AddSingleton<AnchorJournal>();
        services.AddSingleton<AnchorAuthority>();
        services.AddSingleton<IAuthorityAnnouncer, DeferredAnnouncements>();
        services.AddSingleton<AuthorityIntake>();
        services.AddSingleton(_ => new SqliteSessionRegistry(options.SessionStorePath));
        services.AddSingleton(sp => new ClientRegistry(sp.GetRequiredService<SqliteSessionRegistry>(), options.PanelOrigins));
        TksAuthCore.AddApplications(services);
        return services.BuildServiceProvider();
    }

    private static int Report(TextWriter stdout, ApplicationResult result, ApplicationRegistry registry, IServiceProvider provider)
    {
        if (result.Outcome != ApplicationOutcome.Done)
        {
            Console.Error.WriteLine(result.Problem);
            return 1;
        }

        if (result.Application is { } application)
        {
            Describe(stdout, registry.Find(application.Id) ?? application, registry,
                provider.GetRequiredService<ApplicationCatalog>());
        }

        foreach (IssuedSecret secret in result.Secrets ?? [])
            stdout.WriteLine($"client {secret.ClientId} secret: {secret.Secret}  (shown once; only its hash is kept)");

        return 0;
    }

    private static void Describe(TextWriter stdout, Application application, ApplicationRegistry registry, ApplicationCatalog catalog)
    {
        ApplicationRecord r = ApplicationEndpoints.ToRecord(application, registry, catalog);
        stdout.WriteLine($"{r.Id}  {r.Name}  audience {r.Audience}  access {r.AccessLifetimeMinutes} min  ({r.Source})");
        if (r.ManifestUrl is not null)
            stdout.WriteLine($"  manifest {r.ManifestUrl}");
        if (r.Manifest is { } m)
            stdout.WriteLine(m.Taken ? $"  manifest read: {m.Actions} action(s)" : $"  manifest not taken: {m.Problem}");
        if (r.DiscordApplications.Count > 0)
            stdout.WriteLine($"  discord applications {string.Join(", ", r.DiscordApplications)}");
        if (r.ActForDiscord)
            stdout.WriteLine("  may act for linked Discord users");
        foreach (ApplicationClientRecord c in r.Clients)
        {
            stdout.WriteLine($"  client {c.ClientId}  {(c.Confidential ? "confidential" : "public")}  ({c.Source})");
            foreach (string uri in c.RedirectUris)
                stdout.WriteLine($"    redirect {uri}");
            foreach (string uri in c.PostLogoutRedirectUris)
                stdout.WriteLine($"    post-logout {uri}");
        }
    }

    /// <summary><c>--name value</c> options, repeatable, and bare flags.</summary>
    private sealed class Options
    {
        private static readonly HashSet<string> Flags =
            ["act-for-discord", "no-act-for-discord", "confidential", "no-manifest", "no-discord-apps"];

        private static readonly HashSet<string> Valued =
            ["name", "audience", "manifest", "lifetime", "discord-app", "client-id", "redirect", "post-logout"];

        private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);

        /// <summary>The options, or null with the problem written when one is not known or has no value.</summary>
        public static Options? Parse(IReadOnlyList<string> args)
        {
            var options = new Options();
            for (int i = 0; i < args.Count; i++)
            {
                string arg = args[i];
                string name = arg.StartsWith("--", StringComparison.Ordinal) ? arg[2..] : "";

                if (Flags.Contains(name))
                {
                    options.Add(name, "");
                }
                else if (Valued.Contains(name) && i + 1 < args.Count)
                {
                    options.Add(name, args[++i]);
                }
                else
                {
                    Console.Error.WriteLine($"'{arg}' is not an option here, or is missing its value.");
                    return null;
                }
            }

            return options;
        }

        public bool Has(string name) => _values.ContainsKey(name);

        public string? One(string name) => _values.TryGetValue(name, out List<string>? v) ? v[^1] : null;

        public IReadOnlyList<string> Many(string name) => _values.TryGetValue(name, out List<string>? v) ? v : [];

        /// <summary>A number of minutes; one that is not a number is passed on as zero, which the rules refuse.</summary>
        public int? Minutes(string name) =>
            One(name) is { } value ? int.TryParse(value, out int minutes) ? minutes : 0 : null;

        private void Add(string name, string value)
        {
            if (!_values.TryGetValue(name, out List<string>? list))
                _values[name] = list = [];
            list.Add(value);
        }
    }
}

/// <summary>
/// The authority outbox, left for the daemon to drain: the command is not a member of any cluster and has
/// nobody to tell.
/// </summary>
internal sealed class DeferredAnnouncements : IAuthorityAnnouncer
{
    /// <inheritdoc />
    public Task DrainAsync(CancellationToken ct) => Task.CompletedTask;
}
