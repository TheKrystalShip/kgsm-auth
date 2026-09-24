using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

using Microsoft.IdentityModel.Tokens;

using TheKrystalShip.KGSM.Auth.Cluster;

namespace TheKrystalShip.KGSM.Auth.Minting;

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
public sealed class EcdsaSessionSigner : IDisposable
{
    private readonly ECDsa _ecdsa;

    private EcdsaSessionSigner(ECDsa ecdsa)
    {
        _ecdsa = ecdsa;
        PublicKey = ToJwk(ecdsa);
        var key = new ECDsaSecurityKey(ecdsa) { KeyId = PublicKey.Kid };
        VerificationKey = key;
        Credentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
    }

    /// <summary>What a mint signs with.</summary>
    public SigningCredentials Credentials { get; }

    /// <summary>The public half as a key a validation checks the signature against.</summary>
    public SecurityKey VerificationKey { get; }

    /// <summary>The JWS algorithm every token is signed with.</summary>
    public string Algorithm => SecurityAlgorithms.EcdsaSha256;

    /// <summary>The public half, in the form it is published in.</summary>
    public SessionJwk PublicKey { get; }

    /// <summary>The key set this signer publishes.</summary>
    public SessionJwks PublicKeys => new([PublicKey]);

    /// <summary>The published key set as JSON.</summary>
    public string PublicKeysJson =>
        PublicKeys.ToJson();

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

    public void Dispose() => _ecdsa.Dispose();

    private static SessionJwk ToJwk(ECDsa ecdsa)
    {
        ECParameters p = ecdsa.ExportParameters(includePrivateParameters: false);
        string x = Base64Url.EncodeToString(p.Q.X!);
        string y = Base64Url.EncodeToString(p.Q.Y!);

        return new SessionJwk(
            Kty: "EC",
            Crv: SessionKeys.Curve,
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
        string canonical = $"{{\"crv\":\"{SessionKeys.Curve}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
