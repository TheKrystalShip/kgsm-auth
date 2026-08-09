using System.Collections.Concurrent;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// What an identity resolves to on this host, right now.
/// </summary>
/// <remarks>
/// Three answers, not one tier, because the surfaces above act differently on each. Only
/// <see cref="Disabled"/> is a reason to end a live session; <see cref="NoAccount"/> is an ordinary
/// stranger and <see cref="Ok"/> covers a pending account too — pending authenticates and holds
/// <see cref="KgsmTier.None"/>, which is what lets a panel say "awaiting approval" instead of
/// showing someone who just proved who they are a bare denial.
/// </remarks>
public enum AuthorityOutcome
{
    /// <summary>The identity proves an account that may be used. Its tier is on the answer.</summary>
    Ok,

    /// <summary>The identity proves no account here.</summary>
    NoAccount,

    /// <summary>The identity proves an account that has been switched off.</summary>
    Disabled,
}

/// <summary>
/// The account an identity resolves to, and what it may do.
/// </summary>
/// <param name="Outcome">Which of the three answers this is.</param>
/// <param name="Tier">
/// The tier to authorize on — <see cref="KgsmUser.EffectiveTier"/>, so a pending or disabled account
/// is <see cref="KgsmTier.None"/> here whatever tier its record carries.
/// </param>
/// <param name="User">The account, or <see langword="null"/> when there is none.</param>
public readonly record struct AuthorityAnswer(AuthorityOutcome Outcome, KgsmTier Tier, KgsmUser? User);

/// <summary>
/// Authority from the account store: what a verified identity may do here is whatever the KGSM
/// account it proves says, and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// This is the <see cref="IAuthorityProvider"/> half of the login, and it is deliberately the only
/// production answer to that question. An identity provider says who someone is; it contributes
/// nothing to what they may do. That separation is what lets a provider be added with no authority
/// story of its own — a Google account and a Discord account are both just proof that you are the
/// account they are attached to.
/// </para>
/// <para>
/// An identity attached to no account resolves to <see cref="KgsmTier.None"/>, not to an error and
/// not to a floor. That is the real, measured answer: a subject nobody has linked here is a
/// stranger, whatever group or guild they belong to elsewhere.
/// </para>
/// <para>
/// A store that cannot be read throws <see cref="KgsmAuthProviderException"/> instead of answering.
/// "We could not find out" is a different fact from "the answer is none", and reporting the first as
/// the second demotes an admin mid-incident.
/// </para>
/// <para>
/// <b>Answers are cached for <paramref name="ttl"/>.</b> Authority is resolved on every request
/// rather than read off a token claim, so without a cache a chatty panel would re-ask the same
/// question about the same person hundreds of times a minute. The TTL is therefore the staleness
/// bound on a demotion: it is how long after an admin lowers someone's tier that their next request
/// still passes at the old one. Keep it short — the read behind it is a local point query, so there
/// is little to buy by keeping it long.
/// </para>
/// </remarks>
public sealed class UserStoreAuthority(IUserStore store, TimeSpan ttl = default) : IAuthorityProvider
{
    private sealed record Cached(AuthorityAnswer Answer, DateTimeOffset At);

    private readonly ConcurrentDictionary<string, Cached> _cache = new(StringComparer.Ordinal);
    private readonly TimeSpan _ttl = ttl > TimeSpan.Zero ? ttl : TimeSpan.Zero;

    /// <inheritdoc />
    public async Task<KgsmTier> ResolveTierAsync(KgsmIdentity identity, CancellationToken ct) =>
        (await ResolveAsync(identity, ct).ConfigureAwait(false)).Tier;

    /// <summary>
    /// What this identity resolves to: the account it proves, whether that account may be used, and
    /// the tier to authorize on.
    /// </summary>
    /// <remarks>
    /// A read failure throws <see cref="KgsmAuthProviderException"/> and is never cached — caching an
    /// outage would turn a momentary one into a full-TTL lockout for someone who really does hold the
    /// role.
    /// </remarks>
    public async Task<AuthorityAnswer> ResolveAsync(KgsmIdentity identity, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (TryCached(identity.Handle, out AuthorityAnswer cached))
            return cached;

        KgsmUser? user = await FindAsync(identity, ct).ConfigureAwait(false);
        AuthorityAnswer answer = user is null
            ? new AuthorityAnswer(AuthorityOutcome.NoAccount, KgsmTier.None, null)
            : new AuthorityAnswer(
                user.Status == UserStatus.Disabled ? AuthorityOutcome.Disabled : AuthorityOutcome.Ok,
                user.EffectiveTier, user);

        if (_ttl > TimeSpan.Zero)
            _cache[identity.Handle] = new Cached(answer, DateTimeOffset.UtcNow);

        return answer;
    }

    /// <summary>
    /// Drop a cached answer, so this identity's next request re-reads the store.
    /// </summary>
    /// <remarks>
    /// What an admin changing someone's tier or status calls, so the change lands on the surface that
    /// made it without waiting out the TTL. It reaches only this process — another surface on the
    /// same host holds its own cache and picks the change up within its own TTL, which is the bound
    /// that actually matters.
    /// </remarks>
    public void Forget(string handle) => _cache.TryRemove(handle, out _);

    /// <summary>Drop every cached answer.</summary>
    public void ForgetAll() => _cache.Clear();

    /// <summary>
    /// The account an identity proves, or <see langword="null"/> when it proves none. Uncached.
    /// </summary>
    /// <remarks>
    /// A local identity's subject <em>is</em> the account id, so it resolves directly rather than
    /// through a credential row — an account whose password has been removed, or which never had
    /// one, still holds the tier it holds.
    /// </remarks>
    public async Task<KgsmUser?> FindAsync(KgsmIdentity identity, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(identity);

        try
        {
            return identity.Provider == KgsmActorProvider.Local
                ? await store.FindByIdAsync(identity.Subject, ct).ConfigureAwait(false)
                : await store.FindByCredentialAsync(identity.Handle, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not (OperationCanceledException or KgsmAuthProviderException))
        {
            throw new KgsmAuthProviderException(
                $"The KGSM user store could not be read while resolving '{identity.Handle}'.", e);
        }
    }

    private bool TryCached(string handle, out AuthorityAnswer answer)
    {
        answer = default;
        if (_ttl <= TimeSpan.Zero || !_cache.TryGetValue(handle, out Cached? entry))
            return false;

        if (DateTimeOffset.UtcNow - entry.At > _ttl)
        {
            _cache.TryRemove(handle, out _);
            return false;
        }

        answer = entry.Answer;
        return true;
    }
}
