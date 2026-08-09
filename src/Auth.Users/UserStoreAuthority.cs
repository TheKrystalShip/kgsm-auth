namespace TheKrystalShip.KGSM.Auth.Users;

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
/// </remarks>
public sealed class UserStoreAuthority(IUserStore store) : IAuthorityProvider
{
    /// <inheritdoc />
    public async Task<KgsmTier> ResolveTierAsync(KgsmIdentity identity, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(identity);

        KgsmUser? user = await FindAsync(identity, ct).ConfigureAwait(false);
        return user?.EffectiveTier ?? KgsmTier.None;
    }

    /// <summary>
    /// The account an identity proves, or <see langword="null"/> when it proves none.
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
}
