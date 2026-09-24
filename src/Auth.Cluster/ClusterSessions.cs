using Microsoft.IdentityModel.Tokens;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// The keys a cluster's auth anchor states about itself, read by every member that accepts a session
/// it did not mint.
/// </summary>
/// <remarks>
/// Named here rather than at either end, because a publisher and a reader that spell a key
/// differently do not fail — the reader finds nothing and concludes the cluster has no anchor, with
/// nothing in any log saying otherwise. One constant is what makes that disagreement impossible.
/// <para>
/// Every one of these is read <b>through the capability's holder</b>. A fact taken off whichever
/// member happens to state it lets any member answer for an authority it does not hold, which for a
/// signing key means substituting the one sessions are verified against.
/// </para>
/// </remarks>
public static class ClusterAuthFacts
{
    /// <summary>The verification keys, as a JWK set — the JSON a <see cref="SessionJwks"/> serializes to.</summary>
    public const string PublicKey = "auth.publickey";

    /// <summary>The audience every session the anchor mints carries: the cluster it is valid on.</summary>
    public const string Audience = "auth.audience";

    /// <summary>The issuer stamped on every session it mints.</summary>
    public const string Issuer = "auth.issuer";

    /// <summary>The address a person's browser signs in at.</summary>
    public const string SignInUrl = "auth.url";

    /// <summary>
    /// The origins the provider's registered clients live at, as a JSON array of strings: where a browser
    /// holding one of its sessions is calling from, and so the only origins a member admits across
    /// origins.
    /// </summary>
    public const string ClientOrigins = "auth.origins";
}

/// <summary>
/// What a member currently knows about verifying sessions minted elsewhere in its cluster.
/// </summary>
/// <remarks>
/// Read on the request path, so an implementation answers from a snapshot rather than going to
/// storage. Both properties are allowed to say "nothing": a member that is not in a cluster, or has
/// not yet heard who holds its accounts, has no cluster session to accept and refuses every one it is
/// shown. That is the correct answer while it is true, and it repairs itself when gossip arrives.
/// </remarks>
public interface IClusterSessionKeys
{
    /// <summary>
    /// The audience a cluster session carries, or <see langword="null"/> when this member knows of no
    /// anchor. A session whose audience is anything else is not this cluster's.
    /// </summary>
    string? Audience { get; }

    /// <summary>
    /// The issuer a cluster session carries, or <see langword="null"/> when this member knows of no
    /// anchor. Stated by the anchor, because it is the provider's browser-facing URL and only the
    /// anchor is told it.
    /// </summary>
    string? Issuer { get; }

    /// <summary>
    /// Every key a cluster session may currently be signed with. More than one during a rotation
    /// overlap; empty when nothing has been published to this member.
    /// </summary>
    IReadOnlyList<SecurityKey> Keys { get; }
}

/// <summary>
/// What a member or a leaf accepts as a session: its cluster's, minted by the auth anchor, and nothing
/// else.
/// </summary>
/// <remarks>
/// <b>Nothing here lets a member mint what it verifies.</b> The keys it is handed are public points;
/// a verifier built from one cannot sign. That is the property a cluster-wide session depends on,
/// and it is why the algorithm is pinned — a public key offered as an HMAC secret makes the key
/// everybody holds the key everybody can sign with.
/// </remarks>
public static class ClusterSessionValidation
{
    /// <summary>
    /// How far a token's lifetime is stretched for clocks that disagree. One value for every session,
    /// at the mint and at every door, so a token is never alive at one door and expired at the next
    /// for a reason neither can see.
    /// </summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Validation rules that accept the sessions its cluster's auth anchor mints, and nothing else.
    /// </summary>
    /// <remarks>
    /// Every session is minted by the anchor, verified against the key it publishes, audienced to the
    /// cluster and stamped with the anchor's issuer. A member that has not heard from its anchor has
    /// nothing stated to match and refuses every token, which is the right answer until gossip arrives.
    /// </remarks>
    /// <param name="cluster">The anchor's published keys, re-read as gossip moves them.</param>
    public static TokenValidationParameters Accepting(IClusterSessionKeys cluster)
    {
        ArgumentNullException.ThrowIfNull(cluster);

        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            IssuerSigningKeyResolver = (_, _, kid, _) => AnchorKeys(cluster, kid),
            ValidateAudience = true,
            AudienceValidator = (audiences, _, _) => States(audiences, cluster.Audience),
            ValidateIssuer = true,
            IssuerValidator = (issuer, _, _) =>
                States([issuer], cluster.Issuer)
                    ? issuer
                    : throw new SecurityTokenInvalidIssuerException(
                        $"'{issuer}' is not the issuer this cluster's auth anchor states."),
            ValidateLifetime = true,
            ClockSkew = ClockSkew,
            NameClaimType = "sub",
        };
    }

    /// <summary>The published keys a token naming <paramref name="kid"/> may be verified with.</summary>
    /// <remarks>
    /// Exact on the key id, and empty when none matches. Falling back to every published key would
    /// make a rotation's overlap indistinguishable from a token signed with something this member has
    /// never been told about.
    /// </remarks>
    private static IEnumerable<SecurityKey> AnchorKeys(IClusterSessionKeys cluster, string? kid)
    {
        IReadOnlyList<SecurityKey> published = cluster.Keys;
        if (published.Count == 0 || string.IsNullOrEmpty(kid))
            return published;

        return [.. published.Where(k => string.Equals(k.KeyId, kid, StringComparison.Ordinal))];
    }

    /// <summary>
    /// Whether a token states <paramref name="required"/>. A value nothing has stated matches
    /// nothing, which is what makes a member that has not heard from its anchor refuse rather than
    /// assume.
    /// </summary>
    private static bool States(IEnumerable<string?>? stated, string? required) =>
        !string.IsNullOrEmpty(required)
        && stated is not null
        && stated.Any(v => string.Equals(v, required, StringComparison.Ordinal));
}
