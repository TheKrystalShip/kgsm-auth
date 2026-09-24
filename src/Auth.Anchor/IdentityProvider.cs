namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Runs a login and says <em>who</em> someone is. One implementation per identity provider; the
/// provider it speaks for is its own <see cref="Provider"/>.
/// </summary>
/// <remarks>
/// This answers identity only. What that person may <em>do</em> is a separate question with a
/// separate answer — see <see cref="IAuthorityProvider"/> — because the two need not come from the
/// same place: the anchor can verify someone through one provider and grant them authority from
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
