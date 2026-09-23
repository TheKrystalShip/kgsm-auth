using System.Security.Claims;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace TheKrystalShip.KGSM.Auth.Sessions;

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
    /// anchor. Stated by the anchor rather than shared by convention, because a surface that mints its
    /// own sessions has an issuer of its own and the two are free to differ — and a member that
    /// assumed they matched would refuse every cluster session with nothing saying why.
    /// </summary>
    string? Issuer { get; }

    /// <summary>
    /// Every key a cluster session may currently be signed with. More than one during a rotation
    /// overlap; empty when nothing has been published to this member.
    /// </summary>
    IReadOnlyList<SecurityKey> Keys { get; }
}

/// <summary>
/// What a surface accepts as a session: its cluster's, minted by the auth anchor, and — for a surface
/// that also mints its own — those.
/// </summary>
/// <remarks>
/// <para>
/// A surface that signs nobody in takes <see cref="Accepting(IClusterSessionKeys)"/> and holds the
/// anchor's sessions alone. One that mints as well takes
/// <see cref="Accepting(TokenValidationParameters, IClusterSessionKeys)"/>, and the two kinds are kept
/// apart by the algorithm, which is the only part of a presented token that is
/// decided by who signed it rather than by who is presenting it. A symmetric token is this surface's
/// own and is audienced to this surface; an ECDSA one is the anchor's and is audienced to the
/// cluster. Pairing them explicitly means neither combination the cluster never mints — an anchor
/// signature over a host audience, or a host signature over a cluster audience — is accepted merely
/// because nobody happens to produce it today.
/// </para>
/// <para>
/// <b>Nothing here lets a member mint what it verifies.</b> The keys it is handed are public points;
/// a verifier built from one cannot sign. That is the property a cluster-wide session depends on,
/// and it is why the algorithm is pinned to a pair rather than left open — a public key offered as an
/// HMAC secret makes the key everybody holds the key everybody can sign with.
/// </para>
/// </remarks>
public static class ClusterSessionValidation
{
    /// <summary>
    /// Validation rules that accept the sessions its cluster's auth anchor mints, and nothing else.
    /// </summary>
    /// <remarks>
    /// For a surface that signs nobody in: every session it holds was minted by the anchor, verified
    /// against the key that member publishes, audienced to the cluster and stamped with the anchor's
    /// issuer. A member that has not heard from its anchor has nothing stated to match and refuses
    /// every token, which is the right answer until gossip arrives.
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
            ClockSkew = SessionTokenService.ClockSkew,
            NameClaimType = "sub",
        };
    }

    /// <summary>
    /// Validation rules that accept this surface's own sessions and its cluster's, and nothing else.
    /// </summary>
    /// <param name="local">
    /// What this surface mints and verifies for itself — the audience, the issuer, the lifetimes and
    /// the symmetric key. Taken whole, so the two paths cannot disagree about anything but the
    /// signature.
    /// </param>
    /// <param name="cluster">The anchor's published keys, re-read as gossip moves them.</param>
    /// <exception cref="ArgumentException">
    /// When this surface signs its own sessions with ECDSA. The two kinds would then be
    /// indistinguishable, and a member that cannot tell its own session from the cluster's cannot
    /// hold them to different rules.
    /// </exception>
    public static TokenValidationParameters Accepting(
        TokenValidationParameters local, IClusterSessionKeys cluster)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(cluster);

        string localAlgorithm = local.ValidAlgorithms?.FirstOrDefault() ?? SecurityAlgorithms.HmacSha256;
        if (string.Equals(localAlgorithm, SecurityAlgorithms.EcdsaSha256, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A surface that accepts its cluster's sessions must sign its own with a symmetric key. "
                + "Sharing ECDSA with the anchor makes the two kinds indistinguishable at validation.",
                nameof(local));
        }

        string localAudience = local.ValidAudience ?? "";
        string localIssuer = local.ValidIssuer ?? "";
        SecurityKey? localKey = local.IssuerSigningKey;

        TokenValidationParameters combined = local.Clone();
        combined.ValidAlgorithms = [localAlgorithm, SecurityAlgorithms.EcdsaSha256];

        // Cleared, because a resolver and a fixed key are not alternatives — a fixed key is tried
        // whatever the resolver returns, which would offer the symmetric secret against an anchor
        // signature.
        combined.IssuerSigningKey = null;
        combined.IssuerSigningKeys = null;
        combined.IssuerSigningKeyResolver =
            (_, token, kid, _) => KeysFor(token, kid, localAlgorithm, localKey, cluster);

        combined.ValidateAudience = true;
        combined.AudienceValidator =
            (audiences, token, _) => Matches(token, audiences, localAlgorithm, localAudience, cluster.Audience);

        // Paired the same way and for the same reason. The anchor stamps its own issuer and this
        // surface stamps its own, so validating both against one value refuses whichever it is not.
        combined.ValidateIssuer = true;
        combined.IssuerValidator = (issuer, token, _) =>
            Matches(token, [issuer], localAlgorithm, localIssuer, cluster.Issuer)
                ? issuer
                : throw new SecurityTokenInvalidIssuerException(
                    $"'{issuer}' is not an issuer this member accepts for the signature presented.");

        return combined;
    }

    /// <summary>
    /// Whether a validated session was minted by the cluster's anchor rather than by this surface.
    /// </summary>
    /// <remarks>
    /// Read off the <c>host</c> claim, which is inside the signature and therefore a statement the
    /// signer made rather than one the presenter chose. It carries the token's audience, so a session
    /// naming anything other than this surface came through the cluster door — and the two are held
    /// to different rules once past it, because only one of them has a row in this surface's own
    /// session registry.
    /// </remarks>
    public static bool IsClusterSession(ClaimsIdentity identity, string localHostId)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return identity.FindFirst(KgsmAuthClaims.Host)?.Value is { Length: > 0 } host
               && !string.Equals(host, localHostId, StringComparison.Ordinal);
    }

    private static IEnumerable<SecurityKey> KeysFor(
        SecurityToken token,
        string kid,
        string localAlgorithm,
        SecurityKey? localKey,
        IClusterSessionKeys cluster)
    {
        string? algorithm = (token as JsonWebToken)?.Alg;

        if (string.Equals(algorithm, SecurityAlgorithms.EcdsaSha256, StringComparison.Ordinal))
            return AnchorKeys(cluster, kid);

        if (string.Equals(algorithm, localAlgorithm, StringComparison.Ordinal) && localKey is not null)
            return [localKey];

        return [];
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

    /// <summary>
    /// Whether a token states the value its signature obliges it to state.
    /// </summary>
    /// <remarks>
    /// One rule for the audience and the issuer both: an ECDSA signature is the anchor's and has to
    /// carry the anchor's value, a symmetric one is this surface's and has to carry this surface's.
    /// </remarks>
    private static bool Matches(
        SecurityToken token,
        IEnumerable<string?> stated,
        string localAlgorithm,
        string localValue,
        string? clusterValue)
    {
        string? algorithm = (token as JsonWebToken)?.Alg;

        string? required = string.Equals(algorithm, SecurityAlgorithms.EcdsaSha256, StringComparison.Ordinal)
            ? clusterValue
            : string.Equals(algorithm, localAlgorithm, StringComparison.Ordinal) ? localValue : null;

        return States(stated, required);
    }
}
