using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>Who else has to hear that a session ended here.</summary>
/// <remarks>
/// A session minted here has its row here and nowhere else. In a KGSM cluster every member verifies it
/// offline, so ending it here has to be said to them (<see cref="SessionBroadcast"/>); a standalone
/// anchor is the only thing that ever accepts its sessions, and ending the row is the whole of it.
/// </remarks>
internal interface ISessionAnnouncer
{
    /// <summary>Announce that one session is over. Never throws for a failure to tell anybody.</summary>
    Task RevokedAsync(string sessionId, CancellationToken ct);
}

/// <summary>What happens to the records an authority write owes in the store's outbox.</summary>
/// <remarks>
/// Every write files what it changed in <c>authority_outbox</c> in its own transaction. In a KGSM cluster
/// <see cref="AuthorityBroadcast"/> sends each owed record to every member; a standalone anchor has nobody
/// to send them to and clears them.
/// </remarks>
internal interface IAuthorityAnnouncer
{
    /// <summary>Settle everything owed. Safe from anywhere, at any time.</summary>
    Task DrainAsync(CancellationToken ct);
}

/// <summary>
/// The announcements of an anchor that is in no cluster: there is no other member to tell.
/// </summary>
/// <remarks>
/// The outbox is cleared rather than kept. If this machine joins a cluster later, every member takes a
/// snapshot on joining, and the snapshot holds all of it.
/// </remarks>
internal sealed class StandaloneAnnouncements(AnchorAuthority authority, ILogger<StandaloneAnnouncements> logger)
    : ISessionAnnouncer, IAuthorityAnnouncer
{
    /// <inheritdoc />
    public Task RevokedAsync(string sessionId, CancellationToken ct) => Task.CompletedTask;

    /// <inheritdoc />
    public async Task DrainAsync(CancellationToken ct)
    {
        if (authority.Store is not { } store)
            return;

        try
        {
            foreach (AuthorityAnnouncement owed in await store.PendingAnnouncementsAsync(ct).ConfigureAwait(false))
                await store.ClearAnnouncementAsync(owed.Key, owed.Version, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "could not clear the authority outbox");
        }
    }
}
