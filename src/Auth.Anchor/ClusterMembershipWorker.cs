using Microsoft.Extensions.Hosting;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Keeps this anchor's place in the cluster current: it publishes the key members verify sessions
/// with, claims the auth capability when nobody holds it on the machine that founded the cluster,
/// re-reads who does, and — while it holds it — keeps the clients the members announce.
/// </summary>
/// <remarks>
/// <para>
/// <b>Claiming is not holding.</b> <c>TryClaimAsync</c> is compare-and-set against what this member
/// currently knows, so two anchors that both see no holder both succeed locally; the tie resolves
/// deterministically when their gossip meets and one copy is overwritten. The claim is therefore
/// always followed by a re-read, and a member that finds itself not the holder stands down and says
/// so — which is what keeps a second install a candidate rather than a second authority.
/// </para>
/// <para>
/// <b>Nothing here promotes anything.</b> The claim only ever writes into an empty assignment; a
/// capability somebody already holds is left alone however unreachable that member is. Failover is an
/// admin reassigning, because an anchor that promoted itself during a partition would produce two
/// members issuing conflicting statements about who may do what.
/// </para>
/// </remarks>
internal sealed class ClusterMembershipWorker(
    ClusterOptions cluster,
    AnchorOptions options,
    ClusterStateStore state,
    SelfPublications publications,
    EcdsaSessionSigner signer,
    AnchorRole role,
    MembersStore members,
    ClientRegistry clients,
    ILogger<ClusterMembershipWorker> logger) : BackgroundService
{
    /// <summary>
    /// Whether this machine founded the cluster this anchor is in. Read once: the secret and the
    /// founding record are both fixed for the life of the process.
    /// </summary>
    private readonly bool _foundedHere = ClusterFounding.IsFoundedHere(cluster);

    private bool _saidNotFounder;

    /// <summary>
    /// How often the assignment is re-read. Matched to the gossip cadence, because that is what the
    /// answer can change from — reading faster than the thing that moves it buys nothing.
    /// </summary>
    private TimeSpan Interval =>
        TimeSpan.FromMilliseconds(cluster.GossipMs > 0 ? cluster.GossipMs : 5000);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!cluster.Enabled)
        {
            // Not a misconfiguration: a standalone host holds its own accounts and has no assignment
            // to read. Said once, at startup, because "this machine is not in a cluster" is a thing
            // an operator looking at an unexpected refusal needs to be able to find.
            logger.LogInformation(
                "not part of a cluster — this anchor holds this machine's accounts and answers for them alone");
            return;
        }

        // Published before the claim, and published whatever this anchor turns out to be. A reader
        // resolves the holder first and takes the fact off that member only, so a candidate's key is
        // never consulted — and having stated it already is what lets a promotion need no restart
        // anywhere.
        publications.Publish(ClusterAuthFacts.PublicKey, signer.PublicKeysJson);

        // What a member needs to accept a session it cannot mint: the keys that verify the signature,
        // and the audience and issuer the token has to carry to be this cluster's. Both are stated
        // rather than agreed by convention — every surface stamps an issuer of its own, and a member
        // that assumed they matched would refuse every session with nothing saying why.
        publications.Publish(ClusterAuthFacts.Audience, options.ClusterId);
        publications.Publish(ClusterAuthFacts.Issuer, options.Issuer);

        // Where a browser goes, which is a different question from where members reach this anchor
        // even though one address answers both here. Stated rather than inferred from the roster:
        // an anchor on a LAN address for member traffic behind a public vhost for browsers has two
        // answers, and sending a browser to the first one sends it somewhere it cannot reach.
        // Blank states nothing, and a reader falls back to the address members learned.
        if (options.PublicBaseUrl is { Length: > 0 } browserUrl)
            publications.Publish(ClusterAuthFacts.SignInUrl, browserUrl);

        using var timer = new PeriodicTimer(Interval);
        try
        {
            do
            {
                await EvaluateAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // The host is stopping. Not a failure.
        }
    }

    private async Task EvaluateAsync(CancellationToken ct)
    {
        try
        {
            ClusterAssignment? assignment =
                await state.GetAsync(ClusterCapability.Auth, ct).ConfigureAwait(false);

            // Bootstrap: the anchor on the machine that founded the cluster takes the accounts when nobody
            // holds them. Only ever into an empty value, and the re-read below is what settles a race
            // between two of them.
            //
            // Only there. An anchor anywhere else sees an empty assignment for exactly as long as gossip
            // has not reached it yet — a joining machine, or a founding one that has taken another
            // cluster's secret — and a claim made in that window competes with the real holder, where
            // the tie-break can hand it the cluster's accounts. Such an anchor holds them only when an
            // administrator assigns them to it.
            if (assignment is null || !assignment.IsHeld)
            {
                if (_foundedHere)
                {
                    if (await state.TryClaimAsync(ClusterCapability.Auth, cluster.MemberId, ct).ConfigureAwait(false))
                        logger.LogInformation("no member held the cluster's accounts — claimed them as {Member}", cluster.MemberId);
                }
                else if (!_saidNotFounder)
                {
                    logger.LogInformation(
                        "this machine did not found the cluster it is in, so this anchor never claims its "
                        + "accounts; it holds them only when an administrator assigns them to it");
                    _saidNotFounder = true;
                }
            }

            string? holder = await state.HolderAsync(ClusterCapability.Auth, ct).ConfigureAwait(false);
            bool isHolder = string.Equals(holder, cluster.MemberId, StringComparison.Ordinal);

            AnchorStanding standing = isHolder ? AnchorStanding.Holder : AnchorStanding.StandingBy;

            // The surfaces the cluster's members announce become clients of this provider, at the
            // addresses the roster hands out for them, and leave when their member does. Only the holder
            // keeps the set: a member standing by issues no codes, and a set it kept would be stale the
            // moment it was promoted.
            if (isHolder)
                await SyncClientsAsync(ct).ConfigureAwait(false);

            if (!role.Update(standing, holder))
                return;

            if (isHolder)
            {
                logger.LogInformation("this member holds the cluster's accounts");
            }
            else if (holder is not null)
            {
                // The safeguard §7·a exists for: a member that believes it is the anchor while the
                // cluster names another stands down and says so, rather than serving writes on the
                // strength of its own opinion.
                logger.LogWarning(
                    "standing by — {Holder} holds the cluster's accounts, so this anchor mints no sessions "
                    + "and answers for no account", holder);
            }
            else
            {
                logger.LogWarning(
                    "standing by — no member holds the cluster's accounts yet, or none has been heard from");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // One failed read must not end the loop, and must not change where this anchor stands:
            // "I could not find out" is not "somebody else holds it".
            logger.LogWarning(ex, "could not read the cluster's account assignment");
        }
    }

    /// <summary>
    /// Bring the clients the members announce into the registry, at the addresses the roster hands out
    /// for them.
    /// </summary>
    private async Task SyncClientsAsync(CancellationToken ct)
    {
        try
        {
            IReadOnlyList<MemberRow> roster = await members.ListEnabledAsync(ct).ConfigureAwait(false);
            if (await clients.SyncMembersAsync(roster, DateTimeOffset.UtcNow, ct).ConfigureAwait(false))
            {
                logger.LogInformation("the clients members announce are now {Clients}",
                    string.Join(", ", clients.All.Where(c => c.Source == ClientSources.Member)
                        .Select(c => $"{c.ClientId} → {string.Join(" ", c.RedirectUris)}")) is { Length: > 0 } list
                        ? list
                        : "none");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "could not bring the members' clients up to date");
        }
    }
}
