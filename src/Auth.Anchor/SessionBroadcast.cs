using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Tells every other member that a session is over.
/// </summary>
/// <remarks>
/// <para>
/// A cluster session is accepted by every member and has a row on exactly one of them — this one.
/// So ending it here ends nothing anywhere else: the bearer stays valid on every member for the rest
/// of its life, which is short but is not zero, and "sign out" that leaves somebody signed in
/// elsewhere is not sign-out. The announcement is what closes that.
/// </para>
/// <para>
/// It rides the durable bus for the same reason withdrawing authority does. A member that is down
/// when somebody signs out learns of it when it returns, rather than never — and the message is
/// idempotent at the far end, so a redelivery ends an already-ended session and reports nothing.
/// </para>
/// <para>
/// <b>Not in the same transaction as the revoke it announces.</b> A crash in the gap leaves the
/// session ended here and still accepted elsewhere until its bearer expires. The window is one access
/// token's lifetime, which is the same window the design already accepts between a revoke and the
/// members that have not yet drained it.
/// </para>
/// </remarks>
internal sealed class SessionBroadcast(
    IClusterBus bus,
    MemberTargets targets,
    ILogger<SessionBroadcast> logger)
{
    /// <summary>The type every member already registers a handler for.</summary>
    internal const string RevokeType = "session.revoke";

    /// <summary>Announce that one session is over.</summary>
    internal async Task RevokedAsync(string sessionId, CancellationToken ct)
    {
        IReadOnlyList<ClusterTarget> members = await targets.ResolveAsync(ct).ConfigureAwait(false);
        if (members.Count == 0)
            return;

        try
        {
            await bus.EnqueueAsync(
                RevokeType,
                new SessionRevoke("sid", sessionId),
                AnchorJsonContext.Default.SessionRevoke,
                members,
                ct).ConfigureAwait(false);

            logger.LogInformation(
                "queued {Type} for session {Session} to {Targets} member(s)",
                RevokeType, sessionId, members.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The session is already ended here. Failing the sign-out now would tell somebody it did
            // not work about something that did, and invite them to repeat it.
            logger.LogError(ex,
                "could not queue {Type} for session {Session} — it is ended here and other members will "
                + "go on accepting its bearer until it expires", RevokeType, sessionId);
        }
    }
}
