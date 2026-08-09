namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// An identity provider could not be reached, or answered in a way that leaves the question
/// unanswered. A caller surfaces this as an upstream error and <b>never</b> as a denial or a default
/// grant: "we could not ask" is a different fact from "the answer is no", and collapsing them either
/// locks out a legitimate admin during an outage or, far worse, admits someone during one.
/// </summary>
public class KgsmAuthProviderException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>
/// Runs a login and says <em>who</em> someone is. One implementation per identity provider; the
/// provider it speaks for is its own <see cref="Provider"/>.
/// </summary>
/// <remarks>
/// This answers identity only. What that person may <em>do</em> is a separate question with a
/// separate answer — see <see cref="IAuthorityProvider"/> — because the two need not come from the
/// same place: a host can verify someone through one provider and grant them authority from
/// somewhere else entirely.
/// </remarks>
public interface IIdentityProvider
{
    /// <summary>The <see cref="KgsmActorProvider"/> value this provider issues identities under.</summary>
    string Provider { get; }

    /// <summary>
    /// The authorize URL to send the browser to. <paramref name="codeChallenge"/> is the PKCE
    /// challenge from <see cref="OAuthHandshake.CodeChallenge"/>; <paramref name="prompt"/> is
    /// <c>none</c> for silent SSO or <c>consent</c> for the interactive fallback.
    /// </summary>
    string BuildAuthorizeUrl(string state, string codeChallenge, string prompt);

    /// <summary>
    /// Exchange an authorization code for a verified identity.
    /// <para>
    /// Returns <see langword="null"/> when the code itself is bad — expired, replayed, or issued to
    /// another client — which is a client-recoverable problem, not a server one. Throws
    /// <see cref="KgsmAuthProviderException"/> when the provider is unreachable or answers unusably.
    /// </para>
    /// </summary>
    Task<KgsmIdentity?> VerifyAsync(string code, string codeVerifier, CancellationToken ct);
}

/// <summary>
/// Says what a verified identity may <em>do</em> on this host — the authorization half, kept apart
/// from the identity half so the source of authority can change without touching how anyone signs in.
/// </summary>
public interface IAuthorityProvider
{
    /// <summary>
    /// The tier this host grants <paramref name="identity"/>. <see cref="KgsmTier.None"/> is a real,
    /// measured denial; a failure to establish authority at all throws
    /// <see cref="KgsmAuthProviderException"/> rather than returning the denial, so an outage is never
    /// reported as "you have no access".
    /// </summary>
    Task<KgsmTier> ResolveTierAsync(KgsmIdentity identity, CancellationToken ct);
}

/// <summary>
/// A login, end to end: verify who someone is, then resolve what they may do.
/// </summary>
/// <remarks>
/// This is the seam a login path depends on, and it is an interface so a surface can stand the whole
/// authorization matrix — the callback verdict, the tier gate, the 401/403 split — up in-process
/// against a double, with no provider reachable. <see cref="SignInService"/> is the composition that
/// implements it in production.
/// </remarks>
public interface ISignInService
{
    /// <summary>The provider a sign-in through this service goes to.</summary>
    string Provider { get; }

    /// <inheritdoc cref="IIdentityProvider.BuildAuthorizeUrl"/>
    string BuildAuthorizeUrl(string state, string codeChallenge, string prompt);

    /// <summary>
    /// Verify the code and resolve the tier. <see langword="null"/> means the code was bad;
    /// <see cref="KgsmAuthProviderException"/> means the answer could not be established. A successful
    /// return may still carry <see cref="KgsmTier.None"/>: identity verified, no access here.
    /// </summary>
    Task<ResolvedPrincipal?> ResolveAsync(string code, string codeVerifier, CancellationToken ct);
}

/// <summary>
/// The production <see cref="ISignInService"/>: an identity provider and an authority provider run in
/// sequence. Composing the two halves here rather than inside a provider is what lets either be
/// replaced on its own — a host can change where authority comes from without touching how anyone
/// signs in, and the reverse.
/// </summary>
/// <remarks>
/// Holds no state and does no I/O of its own, and both halves it delegates to keep their own failure
/// semantics unchanged.
/// </remarks>
public sealed class SignInService(IIdentityProvider identity, IAuthorityProvider authority) : ISignInService
{
    public string Provider => identity.Provider;

    public string BuildAuthorizeUrl(string state, string codeChallenge, string prompt) =>
        identity.BuildAuthorizeUrl(state, codeChallenge, prompt);

    public async Task<ResolvedPrincipal?> ResolveAsync(string code, string codeVerifier, CancellationToken ct)
    {
        KgsmIdentity? verified = await identity.VerifyAsync(code, codeVerifier, ct).ConfigureAwait(false);
        if (verified is null)
            return null;

        return new ResolvedPrincipal(verified, await authority.ResolveTierAsync(verified, ct).ConfigureAwait(false));
    }
}
