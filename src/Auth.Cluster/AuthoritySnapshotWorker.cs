using System.Net.Http.Headers;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Identity;
using TheKrystalShip.KGSM.Cluster.Membership;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// Takes the whole of the cluster's authority from the member holding it: once when this member has
/// never taken it from that holder, and again whenever the replica has gone stale.
/// </summary>
/// <remarks>
/// <para>
/// <b>The stream carries changes; the snapshot carries everything else.</b> A member that joins holds
/// nothing from before it arrived, and one that missed a message holds a state the anchor never
/// published. The first is fixed by taking a snapshot on joining; the second shows up as a replica the
/// heartbeat no longer confirms, because a heartbeat confirms only a replica that holds its version.
/// Past the bound, this takes the whole state again, which confirms it.
/// </para>
/// <para>
/// A stale replica serves reads only, so the member is safe while this waits; what this restores is
/// its ability to serve anything else.
/// </para>
/// </remarks>
public sealed class AuthoritySnapshotWorker(
    ClusterStateStore clusterState,
    MembersStore members,
    IClusterTokenService clusterTokens,
    IHttpClientFactory httpClientFactory,
    ClusterOptions cluster,
    IReplicatedAuthority authority,
    AuthorityChangeNotifier notifier,
    ILogger<AuthoritySnapshotWorker> logger) : BackgroundService
{
    /// <summary>How often to look. A snapshot is taken only when one is owed.</summary>
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    private string? _takenFrom;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!cluster.Enabled)
            return;

        using var timer = new PeriodicTimer(Interval);
        try
        {
            do
            {
                await TakeIfOwedAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // The host is stopping.
        }
    }

    /// <summary>Take a snapshot if this member has none from the current holder, or its replica is stale.</summary>
    /// <returns>Whether one was taken.</returns>
    public async Task<bool> TakeIfOwedAsync(CancellationToken ct)
    {
        try
        {
            string? holder = await clusterState.HolderAsync(ClusterCapability.Auth, ct).ConfigureAwait(false);
            if (holder is null || string.Equals(holder, cluster.MemberId, StringComparison.Ordinal))
                return false;

            if (authority.Replica is not { } replica)
            {
                logger.LogWarning("cannot take the cluster's authority: the replica is unavailable ({Reason})",
                    authority.UnavailableReason);
                return false;
            }

            if (_takenFrom == holder && (await replica.ReplicaStateAsync(ct).ConfigureAwait(false)).Freshness.IsCurrent(DateTimeOffset.UtcNow))
                return false;

            MemberRow? row = await members.GetByMemberIdAsync(holder, ct).ConfigureAwait(false);
            if (row is null || string.IsNullOrWhiteSpace(row.Url))
            {
                logger.LogWarning("'{Holder}' holds the cluster's authority and this member has no address for it", holder);
                return false;
            }

            AuthorityReplicaSnapshot? snapshot = await FetchAsync(row, ct).ConfigureAwait(false);
            if (snapshot is null)
                return false;

            int deferred = await replica.ApplySnapshotAsync(snapshot, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
            _takenFrom = holder;

            logger.LogInformation(
                "took the cluster's authority from '{Holder}' at version {Version} ({Deferred} record(s) left to the stream)",
                holder, snapshot.Version, deferred);
            await notifier.NotifyAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "could not take the cluster's authority");
            return false;
        }
    }

    private async Task<AuthorityReplicaSnapshot?> FetchAsync(MemberRow holder, CancellationToken ct)
    {
        MintedClusterToken token = clusterTokens.Mint();

        HttpClient http = httpClientFactory.CreateClient(OutboxDrainer.HttpClientName);
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{holder.Url.TrimEnd('/')}/auth/cluster/snapshot");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);

        using HttpResponseMessage response = await http.SendAsync(request, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning("asking '{Holder}' for the cluster's authority returned HTTP {Status}",
                holder.MemberId, (int)response.StatusCode);
            return null;
        }

        string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        AuthorityReplicaSnapshot? snapshot =
            System.Text.Json.JsonSerializer.Deserialize(body, AuthorityReplicationJson.Default.AuthorityReplicaSnapshot);

        // A holder whose store holds no authority answers with its accounts alone, which is no snapshot
        // of this kind.
        if (snapshot?.Accounts is null || snapshot.Roles is null || snapshot.Permissions is null
            || snapshot.Assignments is null || snapshot.Catalog is null || snapshot.Current is null)
        {
            logger.LogWarning("'{Holder}' answered with no authority snapshot", holder.MemberId);
            return null;
        }

        return snapshot;
    }
}
