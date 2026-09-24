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
