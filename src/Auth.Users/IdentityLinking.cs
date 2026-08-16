namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>What happened when a verified external identity was brought to the account store.</summary>
public enum LinkOutcome
{
    /// <summary>The identity already proved an account here; nothing was written.</summary>
    Existing,

    /// <summary>No account claimed this identity, so one was created for it.</summary>
    Provisioned,

    /// <summary>
    /// No account claimed it and none was created, because this host is already holding as many
    /// unapproved accounts as it will.
    /// </summary>
    PendingCapReached,

    /// <summary>
    /// The identity is already attached to a <em>different</em> account. Only reachable when linking
    /// to a named account; re-pointing an identity is refused rather than performed.
    /// </summary>
    AlreadyLinked,
}

/// <summary>What happened when a credential was detached from an account.</summary>
public enum UnlinkOutcome
{
    /// <summary>The credential is gone; the account keeps another way in.</summary>
    Unlinked,

    /// <summary>No such credential on that account. Also the answer for one on somebody else's.</summary>
    NotFound,

    /// <summary>
    /// It was the only thing that could prove the account, and detaching it would leave an account
    /// nobody — including its holder — can ever sign in to.
    /// </summary>
    LastCredential,
}

/// <summary>The account an identity now proves, and how it came to.</summary>
public readonly record struct LinkResult(LinkOutcome Outcome, KgsmUser? User)
{
    /// <summary>Whether an account came out of this at all.</summary>
    public bool Succeeded => User is not null;
}

/// <summary>
/// How many unapproved accounts this host will hold, and for how long.
/// </summary>
/// <remarks>
/// <para>
/// Provisioning is reachable by anyone who can complete a login at a configured provider, which on a
/// publicly-exposed host is anyone at all. The account it creates holds
/// <see cref="KgsmTier.None"/> and so grants nothing — but rows are still rows, and an unbounded
/// table an unauthenticated caller can grow is a defect whatever each row can do.
/// </para>
/// <para>
/// <see cref="Ttl"/> is what keeps the cap from becoming a lockout: without it, one burst of
/// arrivals fills the cap permanently and the next real person is refused. Expiry only ever removes
/// an account that arrived on its own and is still unapproved — never one an admin created or
/// approved, which carries <see cref="TierSource.Granted"/> and is spared however long it waits.
/// </para>
/// </remarks>
/// <param name="Cap">The most unapproved accounts to hold at once.</param>
/// <param name="Ttl">How long an unapproved, self-provisioned account survives unattended.</param>
public readonly record struct PendingPolicy(int Cap, TimeSpan Ttl)
{
    /// <summary>Room for a small crew's worth of arrivals, kept for a fortnight.</summary>
    public static readonly PendingPolicy Default = new(32, TimeSpan.FromDays(14));
}

/// <summary>
/// Brings a verified external identity to the account store: finds the account it proves, or makes
/// one for it to prove.
/// </summary>
/// <remarks>
/// <para>
/// An external identity never <em>is</em> a user and never carries authority. What a login at a
/// provider establishes is one fact — that the caller holds subject X at provider P — and this is
/// where that fact is turned into an account, or found already attached to one. The account it
/// creates starts <see cref="UserStatus.Pending"/> at <see cref="KgsmTier.None"/>: proving who you
/// are is not the same as being let in, and an admin decides the second.
/// </para>
/// <para>
/// Never auto-links on a matching email or username. Providers disagree about what "verified" means
/// and Discord's <c>identify</c> scope returns no email at all, so matching on one is a documented
/// account-takeover route: register the address at a provider the host trusts, sign in, and inherit
/// somebody's tier. Linking an identity to an existing account is a deliberate act by the person who
/// already holds it.
/// </para>
/// </remarks>
public sealed class IdentityLinkService(IUserStore store)
{
    // A provisioned username collides only with another account's, and only the first few candidates
    // are worth trying before falling back to the form that cannot collide at all.
    private const int MaxUsernameAttempts = 8;

    /// <summary>
    /// The account this identity proves, provisioning an unapproved one if nothing claims it yet.
    /// </summary>
    /// <remarks>
    /// Idempotent: an identity already attached to an account resolves to it and writes nothing, so
    /// this is what a login path calls on every sign-in rather than only the first.
    /// </remarks>
    public async Task<LinkResult> ResolveOrProvisionAsync(
        KgsmIdentity identity, DateTimeOffset now, PendingPolicy policy, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(identity);

        KgsmUser? existing = await store.FindByCredentialAsync(identity.Handle, ct).ConfigureAwait(false);
        if (existing is not null)
            return new LinkResult(LinkOutcome.Existing, existing);

        await ExpirePendingAsync(policy, now, ct).ConfigureAwait(false);
        if (await CountPendingAsync(ct).ConfigureAwait(false) >= policy.Cap)
            return new LinkResult(LinkOutcome.PendingCapReached, null);

        return await ProvisionAsync(
            identity, KgsmTier.None, TierSource.Derived, UserStatus.Pending, now, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Create an account for a verified identity and attach it, at a tier and status the caller
    /// chooses. The seeding path, and the shape <see cref="ResolveOrProvisionAsync"/> uses for an
    /// arrival.
    /// </summary>
    /// <remarks>
    /// Two callers racing on the same identity end with one account, not two: the credential handle
    /// is unique in the database, so the loser's insert is refused and it returns the winner's
    /// account.
    /// </remarks>
    public async Task<LinkResult> ProvisionAsync(
        KgsmIdentity identity, KgsmTier tier, TierSource source, UserStatus status,
        DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(identity);

        string userId = UserIds.NewUserId();
        string username = await AvailableUsernameAsync(identity, ct).ConfigureAwait(false);
        KgsmUser user = new(
            userId, username,
            // The provider's own rendering of their name, kept verbatim: it is displayed, never
            // matched, so none of the username charset applies to it.
            string.IsNullOrWhiteSpace(identity.Display) ? username : identity.Display,
            tier, source, status, now, now);

        try
        {
            await store.CreateAsync(user, ct).ConfigureAwait(false);
        }
        catch (DuplicateUsernameException)
        {
            // Somebody took the name between the availability check and the insert. The unique form
            // cannot be taken by anyone but this identity's own account, which does not exist yet.
            user = user with { Username = FallbackUsername(identity) };
            await store.CreateAsync(user, ct).ConfigureAwait(false);
        }

        try
        {
            await store.AddCredentialAsync(new UserCredential(
                UserIds.NewCredentialId(), userId, CredentialKind.Identity, identity.Handle,
                Secret: null, Label: identity.Username, Created: now, LastUsed: now), ct).ConfigureAwait(false);
        }
        catch (DuplicateCredentialException)
        {
            // Another caller provisioned this same identity first. Drop the account just created —
            // it has no credentials, so nothing can ever sign in to it — and answer with theirs.
            await store.DeleteAsync(userId, ct).ConfigureAwait(false);
            KgsmUser? winner = await store.FindByCredentialAsync(identity.Handle, ct).ConfigureAwait(false);
            return new LinkResult(LinkOutcome.Existing, winner);
        }

        return new LinkResult(LinkOutcome.Provisioned, user);
    }

    /// <summary>
    /// Attach a verified identity to an account that already exists.
    /// </summary>
    /// <remarks>
    /// Refuses an identity already attached elsewhere rather than moving it: re-pointing a
    /// credential hands one person another's authority, and the database refuses it in any case.
    /// Attaching one that is already on <em>this</em> account is a no-op, so a repeated link is not
    /// an error.
    /// </remarks>
    public async Task<LinkResult> LinkAsync(
        string userId, KgsmIdentity identity, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(identity);

        KgsmUser? holder = await store.FindByCredentialAsync(identity.Handle, ct).ConfigureAwait(false);
        if (holder is not null)
            return holder.UserId == userId
                ? new LinkResult(LinkOutcome.Existing, holder)
                : new LinkResult(LinkOutcome.AlreadyLinked, holder);

        KgsmUser? user = await store.FindByIdAsync(userId, ct).ConfigureAwait(false);
        if (user is null)
            return new LinkResult(LinkOutcome.AlreadyLinked, null);

        try
        {
            await store.AddCredentialAsync(new UserCredential(
                UserIds.NewCredentialId(), userId, CredentialKind.Identity, identity.Handle,
                Secret: null, Label: identity.Username, Created: now, LastUsed: null), ct).ConfigureAwait(false);
        }
        catch (DuplicateCredentialException)
        {
            KgsmUser? winner = await store.FindByCredentialAsync(identity.Handle, ct).ConfigureAwait(false);
            return winner?.UserId == userId
                ? new LinkResult(LinkOutcome.Existing, user)
                : new LinkResult(LinkOutcome.AlreadyLinked, winner);
        }

        return new LinkResult(LinkOutcome.Provisioned, user);
    }

    /// <summary>
    /// Detach a credential from the account it belongs to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Scoped to one account on purpose: the credential id is the whole of what a caller supplies, and
    /// without the account to check it against, an id guessed or copied from somewhere else would
    /// unlink a stranger's identity. One that belongs to another account is
    /// <see cref="UnlinkOutcome.NotFound"/> — the same answer as one that does not exist, because
    /// telling those apart would say whether an id is real.
    /// </para>
    /// <para>
    /// The last credential is refused. The store itself does not refuse it (it reports what happened
    /// and nothing more), but an account with nothing attached is one its own holder cannot sign in to
    /// and only an admin can rescue, so the rule lives here where every caller gets it.
    /// </para>
    /// </remarks>
    public async Task<UnlinkOutcome> UnlinkAsync(
        string userId, string credentialId, CancellationToken ct = default)
    {
        IReadOnlyList<UserCredential> credentials =
            await store.ListCredentialsAsync(userId, ct).ConfigureAwait(false);

        if (!credentials.Any(c => c.CredentialId == credentialId))
            return UnlinkOutcome.NotFound;

        if (credentials.Count <= 1)
            return UnlinkOutcome.LastCredential;

        return await store.RemoveCredentialAsync(credentialId, ct).ConfigureAwait(false)
            ? UnlinkOutcome.Unlinked
            : UnlinkOutcome.NotFound;
    }

    /// <summary>How many unapproved accounts this host is holding.</summary>
    public async Task<int> CountPendingAsync(CancellationToken ct = default)
    {
        int pending = 0;
        foreach (KgsmUser user in await store.ListAsync(ct).ConfigureAwait(false))
        {
            if (user.Status == UserStatus.Pending)
                pending++;
        }
        return pending;
    }

    /// <summary>
    /// Remove unapproved accounts that arrived on their own and were never looked at. Returns how
    /// many went.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately narrow. An account is only swept when all three hold: it is still
    /// <see cref="UserStatus.Pending"/>, it is older than the policy's TTL, and its tier is
    /// <see cref="TierSource.Derived"/> — it arrived on its own rather than being made by hand. An
    /// account an admin created or approved carries <see cref="TierSource.Granted"/> and stays
    /// however long it waits, because deleting deliberate work is a different act from tidying up
    /// after someone who signed up and never came back.
    /// </para>
    /// <para>
    /// Provenance is the discriminator rather than whether the account holds a password, because a
    /// self-registered account has one and no admin has ever looked at it. Sparing every
    /// password-bearing account would let self-registrations accumulate against
    /// <see cref="PendingPolicy.Cap"/> until the host refuses every new arrival — a queue nobody
    /// can drain being indistinguishable, from outside, from a host that is simply closed.
    /// </para>
    /// </remarks>
    public async Task<int> ExpirePendingAsync(
        PendingPolicy policy, DateTimeOffset now, CancellationToken ct = default)
    {
        if (policy.Ttl <= TimeSpan.Zero)
            return 0;

        DateTimeOffset cutoff = now - policy.Ttl;
        int removed = 0;

        foreach (KgsmUser user in await store.ListAsync(ct).ConfigureAwait(false))
        {
            if (user.Status != UserStatus.Pending || user.Created > cutoff)
                continue;

            if (user.TierSource == TierSource.Granted)
                continue;

            if (await store.DeleteAsync(user.UserId, ct).ConfigureAwait(false))
                removed++;
        }

        return removed;
    }

    // The name a provisioned account gets: the provider's, reduced to this charset, plus a numeric
    // suffix if it is taken. The check is advisory — the insert is what actually decides — so a lost
    // race falls back to the form nobody else can hold.
    private async Task<string> AvailableUsernameAsync(KgsmIdentity identity, CancellationToken ct)
    {
        string? preferred = Usernames.Sanitize(identity.Username) ?? Usernames.Sanitize(identity.Display);
        if (preferred is null)
            return FallbackUsername(identity);

        if (await store.FindByUsernameAsync(preferred, ct).ConfigureAwait(false) is null)
            return preferred;

        for (int n = 2; n <= MaxUsernameAttempts; n++)
        {
            string suffix = n.ToString(System.Globalization.CultureInfo.InvariantCulture);
            string trimmed = preferred.Length + suffix.Length + 1 > Usernames.MaxLength
                ? preferred[..(Usernames.MaxLength - suffix.Length - 1)]
                : preferred;
            string candidate = $"{trimmed}-{suffix}";

            if (Usernames.IsValid(candidate)
                && await store.FindByUsernameAsync(candidate, ct).ConfigureAwait(false) is null)
                return candidate;
        }

        return FallbackUsername(identity);
    }

    // Unique by construction, because a subject is unique within its provider and the handle is
    // unique across the store. Ugly on purpose: it is what an admin renames.
    private static string FallbackUsername(KgsmIdentity identity)
    {
        string raw = $"{identity.Provider}-{identity.Subject}";
        return Usernames.Sanitize(raw) ?? raw[..Math.Min(raw.Length, Usernames.MaxLength)];
    }
}
