using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Primitives;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// Who a request to <c>/token</c> says it is, and whether it proved it (RFC 6749 §2.3.1).
/// </summary>
/// <remarks>
/// <para>
/// <b>Two ways to prove it, and one at a time.</b> A confidential client sends its id and secret as HTTP
/// Basic (<c>client_secret_basic</c>) or as <c>client_id</c> and <c>client_secret</c> in the form
/// (<c>client_secret_post</c>). Both at once is a malformed request: two credentials that disagree would
/// have to be reconciled by a rule nobody wrote down.
/// </para>
/// <para>
/// <b>A public client proves nothing and names itself.</b> It has no secret to keep, so it sends its
/// <c>client_id</c> and is held to PKCE instead. A secret presented for a client that has none is refused
/// rather than ignored: something holding a secret for a public client is confused about what it is
/// talking to.
/// </para>
/// <para>
/// A refusal is <c>invalid_client</c> with <c>401</c>, carrying a <c>Basic</c> challenge when the client
/// tried Basic (RFC 6749 §5.2). Which half was wrong is never said.
/// </para>
/// </remarks>
internal sealed record ClientAuthentication(
    ClientAuthentication.Outcome Result,
    RegisteredClient? Client,
    string? NamedClientId,
    bool UsedBasic)
{
    /// <summary>What reading the request's client credentials came to.</summary>
    internal enum Outcome
    {
        /// <summary>No secret was presented. <see cref="NamedClientId"/> is the form's <c>client_id</c>, when it has one.</summary>
        Unauthenticated,

        /// <summary>A confidential client proved its secret. <see cref="Client"/> is it.</summary>
        Authenticated,

        /// <summary>A secret was presented and does not prove any client.</summary>
        Failed,

        /// <summary>The credentials are not readable, or arrived two ways at once.</summary>
        Malformed,
    }

    /// <summary>Read the client credentials a request to <c>/token</c> carries.</summary>
    public static ClientAuthentication Read(HttpRequest request, IFormCollection form, ClientRegistry clients)
    {
        string? formId = One(form["client_id"]);
        string? formSecret = One(form["client_secret"]);
        string header = request.Headers.Authorization.ToString();

        if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            if (formSecret is not null || form["client_secret"].Count > 1)
                return new ClientAuthentication(Outcome.Malformed, null, formId, UsedBasic: true);

            if (ReadBasic(header) is not ({ } id, { } secret))
                return new ClientAuthentication(Outcome.Malformed, null, formId, UsedBasic: true);

            // The form may repeat the id; it may not name another client.
            if (formId is not null && !string.Equals(formId, id, StringComparison.Ordinal))
                return new ClientAuthentication(Outcome.Malformed, null, formId, UsedBasic: true);

            return Prove(clients, id, secret, usedBasic: true);
        }

        if (form["client_secret"].Count > 1)
            return new ClientAuthentication(Outcome.Malformed, null, formId, UsedBasic: false);

        if (formSecret is not null)
        {
            return formId is null
                ? new ClientAuthentication(Outcome.Malformed, null, null, UsedBasic: false)
                : Prove(clients, formId, formSecret, usedBasic: false);
        }

        return new ClientAuthentication(Outcome.Unauthenticated, null, formId, UsedBasic: false);
    }

    /// <summary>
    /// Whether this request may act as <paramref name="client"/>: a confidential client has to have proved
    /// its secret, and a public one to have named nobody else.
    /// </summary>
    public bool Speaks(RegisteredClient client) =>
        Result switch
        {
            Outcome.Authenticated => string.Equals(Client!.ClientId, client.ClientId, StringComparison.Ordinal),
            Outcome.Unauthenticated => !client.Confidential
                                       && (NamedClientId is null
                                           || string.Equals(NamedClientId, client.ClientId, StringComparison.Ordinal)),
            _ => false,
        };

    /// <summary>The client id this request names, proved or not.</summary>
    public string? ClientId => Client?.ClientId ?? NamedClientId;

    /// <summary>Answer <c>invalid_client</c>, with the challenge Basic asks for when Basic was tried.</summary>
    public Task RefuseAsync(HttpContext ctx, string description)
    {
        if (UsedBasic)
            ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"tks-auth\", charset=\"UTF-8\"";
        return OidcEndpoints.OAuthErrorAsync(ctx, StatusCodes.Status401Unauthorized, "invalid_client", description);
    }

    private static ClientAuthentication Prove(ClientRegistry clients, string id, string secret, bool usedBasic)
    {
        RegisteredClient? client = clients.Find(id);

        // The hash is computed whether or not there is anything to compare it with, so an unknown client
        // and a wrong secret cost the same.
        byte[] presented = Encoding.ASCII.GetBytes(ProviderCookies.Hash(secret));
        byte[] expected = Encoding.ASCII.GetBytes(client?.SecretHash ?? new string('0', presented.Length));
        bool matches = CryptographicOperations.FixedTimeEquals(presented, expected);

        return client is { Confidential: true } && matches
            ? new ClientAuthentication(Outcome.Authenticated, client, id, usedBasic)
            : new ClientAuthentication(Outcome.Failed, null, id, usedBasic);
    }

    /// <summary>
    /// The id and secret in a Basic header, each form-urlencoded before it was joined (RFC 6749 §2.3.1),
    /// or null when the header is not readable as one.
    /// </summary>
    private static (string? Id, string? Secret) ReadBasic(string header)
    {
        string encoded = header["Basic ".Length..].Trim();
        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        }
        catch (FormatException)
        {
            return (null, null);
        }

        int colon = decoded.IndexOf(':');
        if (colon <= 0)
            return (null, null);

        string id = WebUtility.UrlDecode(decoded[..colon]);
        string secret = WebUtility.UrlDecode(decoded[(colon + 1)..]);
        return id.Length == 0 || secret.Length == 0 ? (null, null) : (id, secret);
    }

    private static string? One(StringValues values) =>
        values.Count == 1 && !string.IsNullOrEmpty(values[0]) ? values[0] : null;
}
