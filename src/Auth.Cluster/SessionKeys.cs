using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.IdentityModel.Tokens;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// One public key as a JWK, in the shape a verifier consumes it.
/// </summary>
/// <remarks>
/// Only the fields an EC verification key needs. Serialized through a source-generated context, so a
/// surface publishing a key does not gain a reflective serializer to do it.
/// </remarks>
/// <param name="Kty">The key type. Always <c>EC</c> here.</param>
/// <param name="Crv">The curve. Always <c>P-256</c> here.</param>
/// <param name="X">The public point's x coordinate, base64url, fixed-width for the curve.</param>
/// <param name="Y">The public point's y coordinate, base64url, fixed-width for the curve.</param>
/// <param name="Alg">The algorithm this key signs with.</param>
/// <param name="Use">What the key is for. <c>sig</c>.</param>
/// <param name="Kid">
/// The RFC 7638 thumbprint of the key itself, so the id is derived from the key rather than assigned
/// beside it — two holders of the same key compute the same id, and a rotated key cannot reuse the
/// previous one's.
/// </param>
public sealed record SessionJwk(
    [property: JsonPropertyName("kty")] string Kty,
    [property: JsonPropertyName("crv")] string Crv,
    [property: JsonPropertyName("x")] string X,
    [property: JsonPropertyName("y")] string Y,
    [property: JsonPropertyName("alg")] string Alg,
    [property: JsonPropertyName("use")] string Use,
    [property: JsonPropertyName("kid")] string Kid);

/// <summary>
/// A set of verification keys.
/// </summary>
/// <remarks>
/// A set rather than a single key because rotation needs an overlap: a holder publishes the incoming
/// key beside the outgoing one, every verifier picks up both, and only then does the signer move.
/// Serving one key in a shape that can hold two means the overlap costs no change to the contract.
/// </remarks>
/// <param name="Keys">Every key a token may currently be signed with, newest first.</param>
public sealed record SessionJwks(
    [property: JsonPropertyName("keys")] IReadOnlyList<SessionJwk> Keys)
{
    /// <summary>The set as JSON, in the shape it is published and served in.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, SessionKeyJsonContext.Default.SessionJwks);
}

/// <summary>Serializer metadata for the published key set.</summary>
[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(SessionJwk))]
[JsonSerializable(typeof(SessionJwks))]
public sealed partial class SessionKeyJsonContext : JsonSerializerContext;

/// <summary>
/// Reading a published key set into keys a validation checks signatures against.
/// </summary>
/// <remarks>
/// Only the public point of each key is read, so nothing built here can sign: a member holds exactly
/// what verifies a session and nothing that mints one.
/// </remarks>
public static class SessionKeys
{
    /// <summary>The curve every session key is on.</summary>
    public const string Curve = "P-256";

    /// <summary>Read a published key set back out of its JSON.</summary>
    public static SessionJwks? Read(string json) =>
        JsonSerializer.Deserialize(json, SessionKeyJsonContext.Default.SessionJwks);

    /// <summary>The verification key a published JWK describes.</summary>
    /// <exception cref="NotSupportedException">When the JWK is not an EC key on <see cref="Curve"/>.</exception>
    public static ECDsaSecurityKey VerificationKeyFrom(SessionJwk jwk)
    {
        if (!string.Equals(jwk.Kty, "EC", StringComparison.Ordinal)
            || !string.Equals(jwk.Crv, Curve, StringComparison.Ordinal))
        {
            throw new NotSupportedException($"unsupported session key: kty={jwk.Kty} crv={jwk.Crv}");
        }

        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = Base64Url.DecodeFromChars(jwk.X),
                Y = Base64Url.DecodeFromChars(jwk.Y),
            },
        };

        ECDsa ecdsa = ECDsa.Create(parameters);
        return new ECDsaSecurityKey(ecdsa) { KeyId = jwk.Kid };
    }

    /// <summary>Every verification key in a published set.</summary>
    public static IReadOnlyList<ECDsaSecurityKey> VerificationKeysFrom(SessionJwks jwks) =>
        [.. jwks.Keys.Select(VerificationKeyFrom)];
}
