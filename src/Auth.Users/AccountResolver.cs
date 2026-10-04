using System.Collections.Concurrent;

namespace TheKrystalShip.Auth.Users;

/// <summary>
/// Where the account an identity proves stands on this host, right now.
/// </summary>
/// <remarks>
/// Three answers, because the surfaces above act differently on each. Only <see cref="Disabled"/> is a
/// reason to end a live session; <see cref="NoAccount"/> is an ordinary stranger and <see cref="Ok"/>
/// covers a pending account too — pending authenticates and holds nothing, which is what lets a surface
/// say "awaiting approval" instead of showing someone who just proved who they are a bare denial.
/// </remarks>
public enum AccountOutcome
{
    /// <summary>The identity proves an account that may be used.</summary>
    Ok,

    /// <summary>The identity proves no account here.</summary>
    NoAccount,

    /// <summary>The identity proves an account that has been switched off.</summary>
    Disabled,
}

/// <summary>The account an identity resolves to, and where it stands.</summary>
/// <param name="Outcome">Which of the three answers this is.</param>
/// <param name="User">The account, or <see langword="null"/> when there is none.</param>
public readonly record struct AccountAnswer(AccountOutcome Outcome, KgsmUser? User);

/// <summary>
/// The account a verified identity proves, read from the account store.
/// </summary>
/// <remarks>
/// <para>
/// An identity provider says who someone is and contributes nothing else; this finds the KGSM account
/// that identity is a credential of. What the account may do is not answered here — it is the roles
/// assigned to it, evaluated by <c>TheKrystalShip.Auth.Access</c>.
/// </para>
/// <para>
/// An identity attached to no account is <see cref="AccountOutcome.NoAccount"/>, not an error. That is
/// the real, measured answer: a subject nobody has linked here is a stranger, whatever group or guild
/// they belong to elsewhere.
/// </para>
/// <para>
/// A store that cannot be read throws <see cref="KgsmAuthProviderException"/> instead of answering.
/// "We could not find out" is a different fact from "there is no account", and reporting the first as
/// the second signs an Owner out mid-incident.
/// </para>
/// <para>
/// <b>Answers are cached for <paramref name="ttl"/></b>, which is therefore how long after an account is
/// switched off that a request resolving it still finds it usable. Keep it short — the read behind it
/// is a local point query, so there is little to buy by keeping it long.
/// </para>
/// </remarks>
public sealed class AccountResolver(IUserStore store, TimeSpan ttl = default)
{
    private sealed record Cached(AccountAnswer Answer, DateTimeOffset At);

    private readonly ConcurrentDictionary<string, Cached> _cache = new(StringComparer.Ordinal);
    private readonly TimeSpan _ttl = ttl > TimeSpan.Zero ? ttl : TimeSpan.Zero;

    /// <summary>
    /// What this identity resolves to: the account it proves, and whether that account may be used.
    /// </summary>
    /// <remarks>
    /// A read failure throws <see cref="KgsmAuthProviderException"/> and is never cached — caching an
    /// outage would turn a momentary one into a full-TTL lockout for someone who really has an account.
    /// </remarks>
    public async Task<AccountAnswer> ResolveAsync(KgsmIdentity identity, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (TryCached(identity.Handle, out AccountAnswer cached))
            return cached;

        KgsmUser? user = await FindAsync(identity, ct).ConfigureAwait(false);
        AccountAnswer answer = user is null
            ? new AccountAnswer(AccountOutcome.NoAccount, null)
            : new AccountAnswer(user.Status == UserStatus.Disabled ? AccountOutcome.Disabled : AccountOutcome.Ok, user);

        if (_ttl > TimeSpan.Zero)
            _cache[identity.Handle] = new Cached(answer, DateTimeOffset.UtcNow);

        return answer;
    }

    /// <summary>
    /// Drop a cached answer, so this identity's next request re-reads the store.
    /// </summary>
    /// <remarks>
    /// What changing someone's status calls, so the change lands on the surface that made it without
    /// waiting out the TTL. It reaches only this process.
    /// </remarks>
    public void Forget(string handle) => _cache.TryRemove(handle, out _);

    /// <summary>Drop every cached answer.</summary>
    public void ForgetAll() => _cache.Clear();

    /// <summary>
    /// The account an identity proves, or <see langword="null"/> when it proves none. Uncached.
    /// </summary>
    /// <remarks>
    /// A local identity's subject <em>is</em> the account id, so it resolves directly rather than
    /// through a credential row — an account whose password has been removed, or which never had one,
    /// is still the account it is.
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

    private bool TryCached(string handle, out AccountAnswer answer)
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
