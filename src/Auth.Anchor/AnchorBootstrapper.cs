using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The Owner account an anchor with no accounts creates for itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>An anchor holding an empty store is a door nobody can open.</b> Registration is off unless a
/// cluster turns it on, and an account made through it holds nothing and waits for an approval
/// that only somebody holding <c>auth:accounts.approve</c> can give — so the first person to arrive at a fresh anchor is stuck
/// behind an account nobody exists to approve.
/// </para>
/// <para>
/// It goes unnoticed wherever an anchor shares a machine with a Control Panel, because they share
/// one account store and the panel bootstrapped it first. An anchor on a machine of its own — which
/// nothing prevents and which is the deployment a small cluster wants — starts with nothing.
/// </para>
/// <para>
/// The same bootstrap a host's own API performs, from the same code, so the two cannot disagree about
/// what the first account is called, what the file holds, or when it is removed. Whichever of them
/// opens an empty store first creates the account; the other finds accounts and does nothing.
/// </para>
/// </remarks>
internal sealed class AnchorBootstrapper(
    IUserStore store,
    LocalSignInService signIn,
    AnchorOptions options,
    AnchorAuthority authority,
    AnchorJournal journal,
    SqliteSessionRegistry sessions,
    UpgradeReport upgrade,
    ILogger<AnchorBootstrapper> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        await EndSessionsAfterUpgradeAsync(ct).ConfigureAwait(false);

        string? password;
        try
        {
            password = await FirstAdmin.CreateAsync(store, signIn, FirstAdmin.DefaultUsername, ct)
                .ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // An anchor nobody can administer is worth an error and is not worth refusing to start:
            // the surface that would report the problem is this same daemon.
            logger.LogError(e, "the first account could not be created in the account store");
            return;
        }

        // Accounts already exist, which is every start but the first.
        if (password is null)
            return;

        // What the first account may do is an assignment: Owner, which only this host can give when there
        // is no Owner to give it.
        if (authority.Store is { } authorityStore)
        {
            string actor = KgsmActor.Format(KgsmActorProvider.System, options.MemberId);
            AuthorityWrite granted = await authorityStore.GrantOwnerLocallyAsync(FirstAdmin.DefaultUsername, actor, DateTimeOffset.UtcNow, ct)
                .ConfigureAwait(false);
            await AuthorityJournaling.JournalAsync(journal, granted, actor, origin: null, member: null, ct).ConfigureAwait(false);
        }

        string path = options.InitialAdminPasswordPath;
        if (FirstAdmin.TryWritePasswordFile(path, FirstAdmin.DefaultUsername, password, out Exception? error))
        {
            logger.LogInformation(
                "this cluster had no accounts, so the Owner account '{Username}' was created. Its "
                + "one-time password is in {Path} — read it, sign in, and change it; the file is "
                + "removed on that first sign-in.", FirstAdmin.DefaultUsername, path);
            return;
        }

        // The account exists either way and it is the account that matters, so the password is said
        // out loud here rather than leaving a cluster with an Owner nobody can be.
        logger.LogWarning(error,
            "the first account's password could not be written to {Path}. It is '{Password}' for "
            + "the account '{Username}', and is not recoverable once this line is gone.",
            path, password, FirstAdmin.DefaultUsername);
    }

    /// <summary>
    /// The start that brought the store to schema version 2 ends every session there is, once, so no
    /// token minted under the tiers outlives them. Passwords and identity links are untouched; everybody
    /// signs in again.
    /// </summary>
    private async Task EndSessionsAfterUpgradeAsync(CancellationToken ct)
    {
        if (!upgrade.Upgraded)
            return;

        int ended = await sessions.RevokeEverythingAsync(ct).ConfigureAwait(false);
        logger.LogWarning(
            "the account store was brought to schema version 2 (a copy of the old file is at {Backup}); {Owners} "
            + "became Owner and every other account holds only everyone. {Count} session(s) were ended.",
            upgrade.Backup, string.Join(", ", upgrade.Owners), ended);

        await journal.SessionRevokedAsync(
            SessionRevokeScopes.Upgrade, userId: "", username: "", sid: null, count: ended,
            actor: KgsmActor.Format(KgsmActorProvider.System, options.MemberId), origin: null, ct).ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
