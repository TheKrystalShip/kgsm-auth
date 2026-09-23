using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Cluster;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// What a machine's leaves verify a person's session against: the cluster's issuer, its audience and
/// the keys its auth anchor signs with, as the member on the machine read them through the holder.
/// </summary>
/// <remarks>
/// <para>
/// <b>A leaf does not join the cluster, so it cannot read the holder itself.</b> The member on its
/// machine can, and writes what it verified with here, so a leaf accepts exactly what that member
/// accepts and never picks a key of its own. A key a leaf took from anywhere else — a member it
/// happened to reach, a URL it was configured with — would let whoever answered choose what the leaf
/// trusts.
/// </para>
/// <para>
/// <b>One writer per machine</b>: the node's API, which every machine with a leaf runs. The file is
/// public — a key set, an audience and an address, all of which the anchor serves to anybody — so it is
/// world-readable, and written whole by rename so a reader never sees half of one.
/// </para>
/// </remarks>
/// <param name="Issuer">The <c>iss</c> a cluster session carries.</param>
/// <param name="Audience">The <c>aud</c> a cluster session carries.</param>
/// <param name="Keys">Every key a cluster session may currently be signed with.</param>
public sealed record HostProviderFile(
    [property: JsonPropertyName("issuer")] string Issuer,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("keys")] IReadOnlyList<SessionJwk> Keys)
{
    /// <summary>Where the file lives: the directory the members and leaves on a machine share.</summary>
    public const string DefaultPath = "/var/lib/kgsm/cluster/auth-provider.json";

    /// <summary>The file's contents.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, HostProviderJsonContext.Default.HostProviderFile);

    /// <summary>A file read back, or null when <paramref name="json"/> is not a complete one.</summary>
    public static HostProviderFile? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;

        try
        {
            return JsonSerializer.Deserialize(json, HostProviderJsonContext.Default.HostProviderFile) is
                { Issuer.Length: > 0, Audience.Length: > 0, Keys.Count: > 0 } file
                    ? file
                    : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The verification keys the file names.</summary>
    public IReadOnlyList<SecurityKey> VerificationKeys() =>
        [.. EcdsaSessionSigner.VerificationKeysFrom(new SessionJwks(Keys))];
}

/// <summary>Serializer metadata for the host file.</summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(HostProviderFile))]
internal sealed partial class HostProviderJsonContext : JsonSerializerContext;

/// <summary>
/// Keeps the host file saying what this member verifies cluster sessions with.
/// </summary>
/// <remarks>
/// <para>
/// Written when the member knows all three of issuer, audience and keys, and only when that differs
/// from what the file already says. Removed when the member has read the cluster and the holder states
/// nothing — a machine that has moved to another cluster and has not yet been told who holds its
/// accounts — because a file naming the old cluster would have its leaves accept that cluster's
/// sessions. Left alone before this member's first read, so a restart does not take every leaf's
/// sessions away for the length of one gossip round.
/// </para>
/// </remarks>
public sealed class HostProviderFileWriter(
    ClusterSessionKeys keys,
    ClusterOptions cluster,
    string path,
    ILogger<HostProviderFileWriter> logger) : BackgroundService
{
    private TimeSpan Interval =>
        TimeSpan.FromMilliseconds(cluster.GossipMs > 0 ? cluster.GossipMs : 5000);

    private bool _saidNoDirectory;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!cluster.Enabled || string.IsNullOrWhiteSpace(path))
            return;

        using var timer = new PeriodicTimer(Interval);
        try
        {
            do
            {
                Reconcile();
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // The host is stopping. Not a failure.
        }
    }

    /// <summary>Bring the file in line with what this member currently verifies with.</summary>
    public void Reconcile()
    {
        if (!keys.HasRead)
            return;

        try
        {
            HostProviderFile? wanted = Wanted();
            string? present = File.Exists(path) ? File.ReadAllText(path) : null;

            if (wanted is null)
            {
                if (present is null)
                    return;

                File.Delete(path);
                logger.LogWarning(
                    "removed {Path}: no member of this cluster states who signs its sessions, so this "
                    + "machine's leaves accept none until one does", path);
                return;
            }

            string json = wanted.ToJson();
            if (string.Equals(json, present, StringComparison.Ordinal))
                return;

            string? directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (directory is null || !Directory.Exists(directory))
            {
                if (!_saidNoDirectory)
                {
                    logger.LogWarning(
                        "no shared cluster directory at {Directory}, so this machine's leaves have no "
                        + "record of who signs the cluster's sessions", directory);
                    _saidNoDirectory = true;
                }
                return;
            }

            string temp = path + ".tmp";
            File.WriteAllText(temp, json);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temp,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            }
            File.Move(temp, path, overwrite: true);
            _saidNoDirectory = false;

            logger.LogInformation(
                "wrote {Path}: this machine's leaves accept sessions issued by '{Issuer}' for '{Audience}'",
                path, wanted.Issuer, wanted.Audience);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(e, "could not bring {Path} up to date", path);
        }
    }

    private HostProviderFile? Wanted()
    {
        if (keys.Issuer is not { Length: > 0 } issuer || keys.Audience is not { Length: > 0 } audience)
            return null;

        return keys.PublishedKeySet is { } published
            && EcdsaSessionSigner.ReadKeys(published) is { Keys.Count: > 0 } set
                ? new HostProviderFile(issuer, audience, set.Keys)
                : null;
    }
}

/// <summary>
/// A leaf's view of who signs its cluster's sessions, read from the host file the member on its machine
/// keeps.
/// </summary>
/// <remarks>
/// <para>
/// Read on the request path, so it answers from a snapshot and looks at the file again at most once per
/// <see cref="RecheckInterval"/>, re-parsing only when the file has changed.
/// </para>
/// <para>
/// <b>No file, or one it cannot read, accepts nothing and says why</b> — once, and again whenever the
/// answer changes. A leaf that guessed an issuer or kept a key it could no longer confirm would accept a
/// session its own machine's member refuses.
/// </para>
/// </remarks>
public sealed class HostSessionKeys(string path, ILogger<HostSessionKeys> logger, TimeProvider? time = null)
    : IClusterSessionKeys
{
    /// <summary>How long a snapshot is answered from before the file is looked at again.</summary>
    public static readonly TimeSpan RecheckInterval = TimeSpan.FromSeconds(5);

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private volatile Snapshot _snapshot = Snapshot.Unread;

    /// <inheritdoc />
    public string? Audience => Current().File?.Audience;

    /// <inheritdoc />
    public string? Issuer => Current().File?.Issuer;

    /// <inheritdoc />
    public IReadOnlyList<SecurityKey> Keys => Current().Keys;

    private Snapshot Current()
    {
        Snapshot snapshot = _snapshot;
        DateTimeOffset now = _time.GetUtcNow();
        if (!snapshot.IsUnread && now - snapshot.CheckedAt < RecheckInterval)
            return snapshot;

        lock (_gate)
        {
            snapshot = _snapshot;
            if (!snapshot.IsUnread && now - snapshot.CheckedAt < RecheckInterval)
                return snapshot;

            DateTime? written = File.Exists(path) ? File.GetLastWriteTimeUtc(path) : null;
            if (!snapshot.IsUnread && written == snapshot.Written)
            {
                _snapshot = snapshot with { CheckedAt = now };
                return _snapshot;
            }

            HostProviderFile? file = null;
            string? why = null;
            try
            {
                file = written is null ? null : HostProviderFile.Parse(File.ReadAllText(path));
                why = written is null ? "there is no file" : file is null ? "the file is not a complete record" : null;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                why = e.Message;
            }

            IReadOnlyList<SecurityKey> verification = [];
            if (file is not null)
            {
                try
                {
                    verification = file.VerificationKeys();
                }
                catch (Exception e) when (e is ArgumentException or FormatException or System.Security.Cryptography.CryptographicException)
                {
                    (file, why) = (null, "the keys in it cannot be read");
                }
            }

            if (file is null)
            {
                logger.LogWarning(
                    "accepting no cluster session: {Path} says nothing usable about who signs them ({Why}). "
                    + "The node on this machine writes it once it has joined a cluster.", path, why);
            }
            else if (snapshot.File?.Issuer != file.Issuer || snapshot.File?.Audience != file.Audience)
            {
                logger.LogInformation(
                    "accepting cluster sessions issued by '{Issuer}' for '{Audience}', as {Path} records",
                    file.Issuer, file.Audience, path);
            }

            _snapshot = new Snapshot(file, verification, written, now);
            return _snapshot;
        }
    }

    private sealed record Snapshot(
        HostProviderFile? File, IReadOnlyList<SecurityKey> Keys, DateTime? Written, DateTimeOffset CheckedAt)
    {
        public static readonly Snapshot Unread = new(null, [], null, DateTimeOffset.MinValue);

        public bool IsUnread => ReferenceEquals(this, Unread);
    }
}
