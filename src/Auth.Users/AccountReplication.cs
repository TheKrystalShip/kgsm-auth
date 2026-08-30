namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// An external identity attached to a replicated account: enough to resolve who somebody is, and
/// nothing that could prove it.
/// </summary>
/// <param name="Handle">The <c>provider:subject</c> handle a session's subject is matched against.</param>
/// <param name="Label">What a person sees in "connected accounts". Never matched on.</param>
public sealed record ReplicatedIdentity(string Handle, string? Label);

/// <summary>
/// An account as it travels between members: who somebody is and what they may do.
/// </summary>
/// <remarks>
/// <para>
/// <b>No credential that could authenticate anybody is here.</b> Password hashes stay on the member
/// holding the accounts, because signing in happens there and nowhere else — so a replica can say
/// what a person may do and cannot let them in. That is not an omission to fix later: it is the
/// difference between a compromised member being able to read what its tier allows and being able to
/// sign in as anyone in the cluster.
/// </para>
/// <para>
/// External identities <em>are</em> carried, because resolving authority needs them: a session
/// naming <c>discord:123</c> is matched to an account through its credential handle, and a member
/// with no such row would report a stranger. A handle proves nothing on its own — it is the name of
/// a fact, not the evidence for it.
/// </para>
/// <para>
/// The tier, provenance and status travel as their wire spellings rather than as enums, so a value
/// from a newer member parses fail-closed here — an unrecognised tier reads as
/// <see cref="KgsmTier.None"/> and an unrecognised status as disabled — instead of throwing and
/// wedging a queue.
/// </para>
/// </remarks>
public sealed record ReplicatedAccount(
    string UserId,
    string Username,
    string DisplayName,
    string Tier,
    string TierSource,
    string Status,
    DateTimeOffset Created,
    DateTimeOffset Updated,
    IReadOnlyList<ReplicatedIdentity> Identities)
{
    /// <summary>This record as the account store holds one.</summary>
    public KgsmUser ToUser() => new(
        UserId, Username, DisplayName,
        KgsmTiers.Parse(Tier), TierSources.Parse(TierSource), UserStatuses.Parse(Status),
        Created, Updated);

    /// <summary>An account as it should travel, with every credential secret left behind.</summary>
    public static ReplicatedAccount From(KgsmUser user, IReadOnlyList<UserCredential> credentials) =>
        new(
            user.UserId, user.Username, user.DisplayName,
            KgsmTiers.ToWire(user.Tier), TierSources.ToWire(user.TierSource),
            UserStatuses.ToWire(user.Status), user.Created, user.Updated,
            [.. credentials
                .Where(c => c.Kind == CredentialKind.Identity)
                .Select(c => new ReplicatedIdentity(c.Handle, c.Label))]);
}

/// <summary>One account, at one point in its life, as the member holding the accounts published it.</summary>
/// <param name="Account">The whole record, never a field of it.</param>
/// <param name="Version">The writer's counter for this account.</param>
/// <remarks>
/// The <b>whole</b> record rather than the field that changed, and that is the load-bearing part. Per-field
/// messages leave a replica holding a tier from one point in time beside a status from another — an
/// account that never existed in that combination on the writer. One record at one version means a
/// replica always holds a state the writer actually published.
/// </remarks>
public sealed record AccountChange(ReplicatedAccount Account, long Version);

/// <summary>An account that is gone, and the version that says so.</summary>
/// <param name="UserId">The account removed.</param>
/// <param name="Version">The writer's counter, so a change issued before this cannot undo it.</param>
public sealed record AccountRemoval(string UserId, long Version);

/// <summary>Every account a member holds, for one that is catching up from nothing.</summary>
public sealed record AccountSnapshot(IReadOnlyList<AccountChange> Accounts);

/// <summary>What applying a replicated change did.</summary>
public enum ReplicationOutcome
{
    /// <summary>The local copy now says what the writer said.</summary>
    Applied = 0,

    /// <summary>
    /// Older than, or equal to, what this member already holds. Dropped — the ordinary case under
    /// at-least-once delivery, and the case that stops a re-ordered change moving an account back.
    /// </summary>
    Stale = 1,

    /// <summary>
    /// A different local account already holds this username. Not applied and not retried: usernames
    /// are unique by database constraint, and merging two accounts because they share a name is the
    /// documented route to handing somebody another person's access.
    /// </summary>
    UsernameConflict = 2,
}

/// <summary>
/// Applies replicated account changes to this member's own store.
/// </summary>
/// <remarks>
/// <para>
/// The member does this itself, through this library, rather than gaining a process for it — a node
/// holding a replica runs no extra daemon.
/// </para>
/// <para>
/// <b>Idempotent by construction.</b> Delivery is at-least-once, so the same change arrives again as
/// a matter of course: an upsert of a whole record at a version already held is refused as
/// <see cref="ReplicationOutcome.Stale"/>, and applying the same state twice would be harmless
/// anyway.
/// </para>
/// <para>
/// <b>The version is advanced last, and only on success.</b> Advancing first would mark a change
/// applied that a username conflict then refused, and nothing would ever retry it — the account would
/// stay silently wrong until somebody rebuilt the replica. The cost is a window in which two
/// deliveries of one change both apply it, which an upsert makes indistinguishable from applying it
/// once.
/// </para>
/// </remarks>
public sealed class AccountReplica(IUserStore store, IAccountVersions versions)
{
    /// <summary>Apply one account's published state.</summary>
    public async Task<ReplicationOutcome> ApplyAsync(
        AccountChange change, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(change);

        if (change.Version <= await versions.CurrentAsync(change.Account.UserId, ct).ConfigureAwait(false))
            return ReplicationOutcome.Stale;

        KgsmUser user = change.Account.ToUser();
        KgsmUser? existing = await store.FindByIdAsync(user.UserId, ct).ConfigureAwait(false);

        try
        {
            if (existing is null)
                await store.CreateAsync(user, ct).ConfigureAwait(false);
            else
                await store.UpdateAsync(user, ct).ConfigureAwait(false);
        }
        catch (DuplicateUsernameException)
        {
            // Another account here already answers to this name. Reported rather than merged, and
            // acknowledged rather than retried: retrying cannot resolve it, and merging on a shared
            // username is how one person is handed another's access.
            return ReplicationOutcome.UsernameConflict;
        }

        await ReconcileIdentitiesAsync(change.Account, now, ct).ConfigureAwait(false);
        await versions.TryAdvanceAsync(user.UserId, change.Version, now, ct).ConfigureAwait(false);

        return ReplicationOutcome.Applied;
    }

    /// <summary>Apply an account's removal.</summary>
    /// <remarks>
    /// The version row survives the account, which is what makes the removal stick: a change issued
    /// before it carries a lower version and is refused, rather than re-creating somebody who was
    /// deliberately removed.
    /// </remarks>
    public async Task<ReplicationOutcome> RemoveAsync(
        AccountRemoval removal, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(removal);

        if (removal.Version <= await versions.CurrentAsync(removal.UserId, ct).ConfigureAwait(false))
            return ReplicationOutcome.Stale;

        // Not conditional on the account being here. A member that never saw it still has to record
        // that it is gone, or a change that predates the removal would land later and create it.
        await store.DeleteAsync(removal.UserId, ct).ConfigureAwait(false);
        await versions.TryAdvanceAsync(removal.UserId, removal.Version, now, ct).ConfigureAwait(false);

        return ReplicationOutcome.Applied;
    }

    /// <summary>
    /// Apply a full snapshot, and report what could not be taken.
    /// </summary>
    /// <remarks>
    /// A member joining an established cluster takes one of these before it follows the stream, so it
    /// is not missing what happened before it arrived. Anything that arrives while the snapshot is
    /// being applied is safe in either order: both paths carry versions and the newer one wins,
    /// whichever lands second.
    /// </remarks>
    public async Task<IReadOnlyList<AccountChange>> ApplySnapshotAsync(
        AccountSnapshot snapshot, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var refused = new List<AccountChange>();
        foreach (AccountChange change in snapshot.Accounts)
        {
            if (await ApplyAsync(change, now, ct).ConfigureAwait(false) == ReplicationOutcome.UsernameConflict)
                refused.Add(change);
        }
        return refused;
    }

    /// <summary>
    /// Make the account's external identities here match what the writer published.
    /// </summary>
    /// <remarks>
    /// Password credentials are never touched. They are not replicated, so a replica holds none for a
    /// replicated account — and one belonging to an account this machine had before it joined is
    /// this machine's own business, not something a change from elsewhere should erase.
    /// </remarks>
    private async Task ReconcileIdentitiesAsync(
        ReplicatedAccount account, DateTimeOffset now, CancellationToken ct)
    {
        IReadOnlyList<UserCredential> held =
            await store.ListCredentialsAsync(account.UserId, ct).ConfigureAwait(false);

        var wanted = account.Identities.ToDictionary(i => i.Handle, StringComparer.Ordinal);

        foreach (UserCredential credential in held.Where(c => c.Kind == CredentialKind.Identity))
        {
            if (!wanted.Remove(credential.Handle))
                await store.RemoveCredentialAsync(credential.CredentialId, ct).ConfigureAwait(false);
        }

        foreach (ReplicatedIdentity identity in wanted.Values)
        {
            try
            {
                await store.AddCredentialAsync(
                    new UserCredential(
                        UserIds.NewCredentialId(), account.UserId, CredentialKind.Identity,
                        identity.Handle, Secret: null, identity.Label, now, LastUsed: null),
                    ct).ConfigureAwait(false);
            }
            catch (DuplicateCredentialException)
            {
                // The handle is attached to a different account here. Left where it is: a credential
                // handle belongs to exactly one account by database constraint, and re-pointing one
                // is precisely the account-takeover route the constraint exists to close.
            }
        }
    }
}

/// <summary>
/// Serializer metadata for what travels between members.
/// </summary>
/// <remarks>
/// In this package because both ends need the identical shape: the member holding the accounts
/// writes it and every replica reads it, and a second declaration is a second thing to drift. It is
/// source-generated because every member other than the Control Panel API is Native AOT, where a
/// type nobody generated metadata for throws at runtime rather than failing a build.
/// </remarks>
[System.Text.Json.Serialization.JsonSourceGenerationOptions(
    PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase)]
[System.Text.Json.Serialization.JsonSerializable(typeof(ReplicatedIdentity))]
[System.Text.Json.Serialization.JsonSerializable(typeof(ReplicatedAccount))]
[System.Text.Json.Serialization.JsonSerializable(typeof(AccountChange))]
[System.Text.Json.Serialization.JsonSerializable(typeof(AccountRemoval))]
[System.Text.Json.Serialization.JsonSerializable(typeof(AccountSnapshot))]
public sealed partial class AccountReplicationJson : System.Text.Json.Serialization.JsonSerializerContext;
