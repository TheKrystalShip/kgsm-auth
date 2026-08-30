using Microsoft.Extensions.Hosting;

using TheKrystalShip.KGSM.Auth.Sessions;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Keeps this anchor's place in the cluster current: it publishes the key members verify sessions
/// with, claims the auth capability when nobody holds it, and re-reads who does.
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
    ILogger<ClusterMembershipWorker> logger) : BackgroundService
{
    /// <summary>The fact an anchor states about itself: the keys its sessions can be verified with.</summary>
    internal const string PublicKeyFact = "auth.publickey";

    // The key file is reconciled every pass, so what is said about it has to be said once. These
    // reset on the way down, which is what makes a re-publish after a promotion audible again.
    private bool _saidPublished;
    private bool _saidNoDirectory;

    private void LogOnce(ref bool said, string message, string path)
    {
        if (said)
            return;
        said = true;
        logger.LogInformation(message, path);
    }

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

            // The only anchor there is, so the key it publishes is the one to verify against.
            PublishKeyFile();
            return;
        }

        // Published before the claim, and published whatever this anchor turns out to be. A reader
        // resolves the holder first and takes the fact off that member only, so a candidate's key is
        // never consulted — and having stated it already is what lets a promotion need no restart
        // anywhere. The file below is the opposite case and is gated, because a path says nothing
        // about who wrote it.
        publications.Publish(PublicKeyFact, signer.PublicKeysJson);

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

            // Bootstrap: the first anchor in a cluster with no assignment takes it. Only ever into an
            // empty value, and the re-read below is what settles a race between two of them.
            if (assignment is null || !assignment.IsHeld)
            {
                if (await state.TryClaimAsync(ClusterCapability.Auth, cluster.MemberId, ct).ConfigureAwait(false))
                    logger.LogInformation("no member held the cluster's accounts — claimed them as {Member}", cluster.MemberId);
            }

            string? holder = await state.HolderAsync(ClusterCapability.Auth, ct).ConfigureAwait(false);
            bool isHolder = string.Equals(holder, cluster.MemberId, StringComparison.Ordinal);

            AnchorStanding standing = isHolder ? AnchorStanding.Holder : AnchorStanding.StandingBy;

            // The shared file follows the standing, in both directions: a member that has stood down
            // leaves behind a key every member on this machine would go on verifying against.
            //
            // Reconciled on every pass rather than only when the standing changes, so the file is
            // restored if anything removes it — including a second anchor on this machine that
            // briefly believed it was the holder and withdrew its own key on the way down. Both calls
            // read the file and return without writing when it already says the right thing.
            if (isHolder)
                PublishKeyFile();
            else
                WithdrawKeyFile();

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
    /// Put this anchor's verification keys where members sharing the machine read them.
    /// </summary>
    /// <remarks>
    /// The directory is scaffolded for what several members on one machine share. Absent, there is no
    /// member here to read the file and nothing to do about it — the key is still served over HTTP
    /// and still gossiped, which is how a member on another machine finds it.
    /// </remarks>
    private void PublishKeyFile()
    {
        if (options.PublishedKeyPath is not { } path)
            return;

        try
        {
            if (!SigningKeyStore.Publish(path, signer.PublicKeysJson))
            {
                LogOnce(ref _saidNoDirectory,
                    "no shared cluster directory at {Path} — the verification key is served over HTTP only", path);
                return;
            }

            LogOnce(ref _saidPublished, "published the session verification key to {Path}", path);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "could not publish the session verification key to {Path}", path);
        }
    }

    private void WithdrawKeyFile()
    {
        if (options.PublishedKeyPath is not { } path)
            return;

        try
        {
            if (SigningKeyStore.Withdraw(path, signer.PublicKeysJson))
            {
                logger.LogWarning(
                    "withdrew this member's verification key from {Path} — it no longer holds the cluster's accounts",
                    path);
            }

            // Said again if this member is ever promoted back.
            _saidPublished = false;
            _saidNoDirectory = false;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "could not withdraw the session verification key from {Path}", path);
        }
    }
}
