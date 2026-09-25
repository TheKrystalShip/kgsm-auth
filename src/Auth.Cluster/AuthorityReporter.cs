using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// Where this member's action manifests are, and how often it tells the auth anchor about them.
/// </summary>
public sealed class AuthorityReporterOptions
{
    /// <summary>
    /// Directories whose every <c>*.json</c> is a manifest this member reports. A node names
    /// <c>/var/lib/kgsm/leaves/actions</c>, which holds its engine's and every leaf's.
    /// </summary>
    public IReadOnlyList<string> ManifestDirectories { get; init; } = [];

    /// <summary>
    /// Single manifests this member reports. An anchor names its own; several anchors can share one
    /// machine's <c>/var/lib/kgsm/anchors/actions</c>, and each reports only itself.
    /// </summary>
    public IReadOnlyList<string> ManifestFiles { get; init; } = [];

    /// <summary>How often the manifests are read for a change.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How often the report is sent again when nothing changed.</summary>
    public TimeSpan ReportInterval { get; init; } = TimeSpan.FromMinutes(15);
}

/// <summary>
/// The auth anchor's own intake, for a member that holds the accounts itself: its report goes straight
/// in rather than across the bus to itself.
/// </summary>
public interface IAuthorityIntake
{
    /// <summary>Take <paramref name="member"/>'s catalog report.</summary>
    Task CatalogDeclaredAsync(string member, MemberCatalogReport report, CancellationToken ct);

    /// <summary>Take <paramref name="member"/>'s word that one install of an instance is gone.</summary>
    Task InstanceUninstalledAsync(string member, InstanceUninstalledReport report, CancellationToken ct);
}

/// <summary>
/// Tells the auth anchor what this member is responsible for: every action manifest it holds, and every
/// install of an instance that goes away.
/// </summary>
/// <remarks>
/// <para>
/// A member reports on joining, whenever a manifest changes, whenever the holder of the accounts
/// changes, and every <see cref="AuthorityReporterOptions.ReportInterval"/> regardless — a report
/// replaces the last one, so sending it again is always safe. The member reads its manifests from disk,
/// so a leaf gains no dependency by having one: it installs a file, and its node reports it.
/// </para>
/// <para>
/// The report goes through the bus, which holds it until the anchor answers. A member that holds the
/// accounts itself hands it to its own <see cref="IAuthorityIntake"/> instead.
/// </para>
/// <para>
/// A manifest that cannot be read is logged and left out of the report. That takes its actions out
/// of the catalog, which is what a component shipping no readable manifest means: it declares nothing.
/// </para>
/// </remarks>
public sealed class AuthorityReporter(
    ClusterOptions cluster,
    ClusterStateStore clusterState,
    MembersStore members,
    IClusterBus bus,
    AuthorityReporterOptions options,
    ILogger<AuthorityReporter> logger,
    IAuthorityIntake? intake = null) : BackgroundService
{
    private string? _sentFingerprint;
    private string? _sentTo;
    private DateTimeOffset _sentAt = DateTimeOffset.MinValue;
    private long _sequence;

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!cluster.Enabled)
            return;

        using PeriodicTimer timer = new(options.PollInterval);
        try
        {
            do
            {
                await ReportIfDueAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // The host is stopping. Not a failure.
        }
    }

    /// <summary>
    /// Send this member's report when it changed, when the holder changed, or when the interval has
    /// passed. Returns whether it was sent.
    /// </summary>
    public async Task<bool> ReportIfDueAsync(CancellationToken ct)
    {
        try
        {
            MemberCatalogReport report = Read();
            string fingerprint = Fingerprint(report);
            string? holder = await clusterState.HolderAsync(ClusterCapability.Auth, ct).ConfigureAwait(false);

            if (holder is null)
                return false;

            DateTimeOffset now = DateTimeOffset.UtcNow;
            bool due = fingerprint != _sentFingerprint || holder != _sentTo || now - _sentAt >= options.ReportInterval;
            if (!due)
                return false;

            // Stamped after the fingerprint is taken, so an unchanged report fingerprints the same.
            MemberCatalogReport stamped = report with { Sequence = Math.Max(now.ToUnixTimeMilliseconds(), _sequence + 1) };
            _sequence = stamped.Sequence;

            if (!await SendAsync(holder, AuthorityMessages.CatalogDeclared, stamped, AccessJsonContext.Default.MemberCatalogReport,
                    (i, token) => i.CatalogDeclaredAsync(cluster.MemberId, stamped, token), ct).ConfigureAwait(false))
            {
                return false;
            }

            _sentFingerprint = fingerprint;
            _sentTo = holder;
            _sentAt = now;

            logger.LogInformation(
                "reported {Count} action manifest(s) to '{Holder}'", report.Manifests.Count, holder);
            return true;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            logger.LogWarning(e, "could not report this member's actions");
            return false;
        }
    }

    /// <summary>
    /// Tell the auth anchor that the install of <paramref name="instance"/> with
    /// <paramref name="nonce"/> is gone, so every grant naming it goes too.
    /// </summary>
    /// <returns>Whether it was handed to the bus or the intake.</returns>
    public Task<bool> ReportUninstalledAsync(string instance, string nonce, CancellationToken ct)
    {
        InstanceUninstalledReport report = new(instance, nonce);
        return SendAsync(null, AuthorityMessages.InstanceUninstalled, report, AccessJsonContext.Default.InstanceUninstalledReport,
            (i, token) => i.InstanceUninstalledAsync(cluster.MemberId, report, token), ct);
    }

    private async Task<bool> SendAsync<T>(
        string? holder, string type, T payload, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info,
        Func<IAuthorityIntake, CancellationToken, Task> local, CancellationToken ct)
    {
        holder ??= await clusterState.HolderAsync(ClusterCapability.Auth, ct).ConfigureAwait(false);
        if (holder is null)
        {
            logger.LogWarning("nobody holds this cluster's accounts yet, so '{Type}' reached nobody", type);
            return false;
        }

        if (holder == cluster.MemberId)
        {
            if (intake is null)
            {
                logger.LogWarning("this member holds the accounts and has no intake for '{Type}'", type);
                return false;
            }

            await local(intake, ct).ConfigureAwait(false);
            return true;
        }

        MemberRow? row = await members.GetByMemberIdAsync(holder, ct).ConfigureAwait(false);
        if (row is null || string.IsNullOrWhiteSpace(row.Url))
        {
            logger.LogWarning("'{Holder}' holds the accounts and this member has no address for it; '{Type}' waits", holder, type);
            return false;
        }

        await bus.EnqueueAsync(type, payload, info, [new ClusterTarget(holder, row.Url)], ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>Every manifest this member holds, in a stable order.</summary>
    private MemberCatalogReport Read()
    {
        SortedDictionary<string, ActionManifest> found = new(StringComparer.Ordinal);

        IEnumerable<string> paths = options.ManifestFiles
            .Concat(options.ManifestDirectories
                .Where(Directory.Exists)
                .SelectMany(d => Directory.EnumerateFiles(d, "*.json")));

        foreach (string path in paths.Distinct(StringComparer.Ordinal))
        {
            if (!File.Exists(path))
                continue;

            if (ActionManifests.TryRead(path, out string? problem) is { } manifest)
                found[path] = manifest;
            else
                logger.LogError("the action manifest at {Path} is left out of this member's report: {Problem}", path, problem);
        }

        return new MemberCatalogReport(cluster.Kind == MemberKind.Anchor, [.. found.Values]);
    }

    private static string Fingerprint(MemberCatalogReport report) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(report, AccessJsonContext.Default.MemberCatalogReport))));
}
