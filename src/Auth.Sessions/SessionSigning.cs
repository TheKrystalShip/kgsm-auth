using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.IdentityModel.Tokens;

namespace TheKrystalShip.KGSM.Auth.Sessions;

/// <summary>
/// How a surface signs its session tokens, and what verifies one.
/// </summary>
/// <remarks>
/// <para>
/// Two keys rather than one, because they are not always the same key. A surface that both mints and
/// verifies its own tokens holds one shared secret and the two properties return it; a surface that
/// mints for others to verify holds a private key and publishes only the public half.
/// </para>
/// <para>
/// The distinction is the whole reason this seam exists. Where a session is valid on a machine other
/// than the one that minted it, the verifying machine must be unable to mint what it checks —
/// otherwise it can issue itself any authority it can read.
/// </para>
/// </remarks>
public interface ISessionSigner
{
    /// <summary>What a mint signs with.</summary>
    SigningCredentials Credentials { get; }

    /// <summary>What a validation checks the signature against.</summary>
    SecurityKey VerificationKey { get; }

    /// <summary>The JWS algorithm, pinned on validation so no other one is accepted.</summary>
    string Algorithm { get; }
}

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
    [property: JsonPropertyName("keys")] IReadOnlyList<SessionJwk> Keys);

/// <summary>Serializer metadata for the published key set.</summary>
[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(SessionJwk))]
[JsonSerializable(typeof(SessionJwks))]
public sealed partial class SessionKeyJsonContext : JsonSerializerContext;

/// <summary>
/// ECDSA P-256 session signing: the holder mints with the private key, and anyone with the published
/// public key verifies without being able to mint.
/// </summary>
/// <remarks>
/// <para>
/// P-256 with SHA-256 rather than RSA: the private key is a few hundred bytes rather than a few
/// thousand, the public half fits in a gossip payload, and the signature is 64 bytes on every token
/// a browser carries.
/// </para>
/// <para>
/// The instance owns the <see cref="ECDsa"/> for its lifetime — the signing credentials hold it, so
/// disposing it while tokens are still being minted breaks the mint rather than tidying up.
/// </para>
/// </remarks>
public sealed class EcdsaSessionSigner : ISessionSigner, IDisposable
{
    private readonly ECDsa _ecdsa;

    /// <summary>The curve every key here is on.</summary>
    public const string Curve = "P-256";

    private EcdsaSessionSigner(ECDsa ecdsa)
    {
        _ecdsa = ecdsa;
        PublicKey = ToJwk(ecdsa);
        var key = new ECDsaSecurityKey(ecdsa) { KeyId = PublicKey.Kid };
        VerificationKey = key;
        Credentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
    }

    /// <inheritdoc />
    public SigningCredentials Credentials { get; }

    /// <inheritdoc />
    public SecurityKey VerificationKey { get; }

    /// <inheritdoc />
    public string Algorithm => SecurityAlgorithms.EcdsaSha256;

    /// <summary>The public half, in the form it is published in.</summary>
    public SessionJwk PublicKey { get; }

    /// <summary>The key set this signer publishes.</summary>
    public SessionJwks PublicKeys => new([PublicKey]);

    /// <summary>The published key set as JSON.</summary>
    public string PublicKeysJson =>
        JsonSerializer.Serialize(PublicKeys, SessionKeyJsonContext.Default.SessionJwks);

    /// <summary>A signer over a freshly generated key pair.</summary>
    public static EcdsaSessionSigner Generate() =>
        new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    /// <summary>
    /// A signer over an existing private key in PEM form. Throws when the PEM holds no readable
    /// private key, which is the only honest answer: a signer that silently generated a new key
    /// would invalidate every token already issued and report nothing.
    /// </summary>
    public static EcdsaSessionSigner FromPem(string pem)
    {
        ECDsa ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(pem);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
        return new EcdsaSessionSigner(ecdsa);
    }

    /// <summary>The private key in PKCS#8 PEM form, for writing to a file only its holder can read.</summary>
    public string ExportPrivatePem() => _ecdsa.ExportPkcs8PrivateKeyPem();

    /// <summary>
    /// The verification key a published JWK describes. Never yields something that can sign: only the
    /// public point is read, so a verifier built from this cannot mint.
    /// </summary>
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

    /// <summary>Read a published key set back out of its JSON.</summary>
    public static SessionJwks? ReadKeys(string json) =>
        JsonSerializer.Deserialize(json, SessionKeyJsonContext.Default.SessionJwks);

    public void Dispose() => _ecdsa.Dispose();

    private static SessionJwk ToJwk(ECDsa ecdsa)
    {
        ECParameters p = ecdsa.ExportParameters(includePrivateParameters: false);
        string x = Base64Url.EncodeToString(p.Q.X!);
        string y = Base64Url.EncodeToString(p.Q.Y!);

        return new SessionJwk(
            Kty: "EC",
            Crv: Curve,
            X: x,
            Y: y,
            Alg: SecurityAlgorithms.EcdsaSha256,
            Use: "sig",
            Kid: Thumbprint(x, y));
    }

    /// <summary>
    /// The RFC 7638 thumbprint: SHA-256 over the required members alone, spelled in lexicographic
    /// order with no whitespace.
    /// </summary>
    /// <remarks>
    /// Built as a string rather than serialized, because the canonical form is defined by the RFC and
    /// not by whatever a serializer happens to emit — member order, escaping and whitespace are all
    /// part of what is hashed, and a serializer is free to change any of them.
    /// </remarks>
    private static string Thumbprint(string x, string y)
    {
        string canonical = $"{{\"crv\":\"{Curve}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
