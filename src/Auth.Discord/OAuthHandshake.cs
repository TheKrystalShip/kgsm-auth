using System.Security.Cryptography;
using System.Text;

namespace TheKrystalShip.KGSM.Auth.Discord;

/// <summary>
/// The two secrets one in-flight Discord login carries between the authorize redirect and the
/// callback: a CSRF <c>state</c> and a PKCE <c>code_verifier</c>. Both live in a single HttpOnly
/// cookie on the browser doing the login, and nothing is stored server-side.
/// </summary>
/// <remarks>
/// <para>
/// <b>The two defend different attacks and neither substitutes for the other.</b> <c>state</c> stops
/// login CSRF: without it an attacker starts their own login, sends the victim a callback link
/// carrying the attacker's <c>code</c>, and the victim's browser is handed a session for the
/// <em>attacker's</em> identity — everything they then do lands in the attacker's account. PKCE stops
/// code interception: a <c>code</c> travels back through a URL, and a URL leaks.
/// </para>
/// <para>
/// <b>The state must be bound to the browser, and the cookie is what binds it.</b> Checking a
/// returned state against a server-side set of issued states proves only that <em>some</em> login
/// started on this host — which is true of the attacker's own login too, so it admits exactly the
/// request it was meant to refuse. Single-use consumption stops replay, not CSRF.
/// </para>
/// <para>
/// PKCE is defence in depth here rather than the load-bearing check: a KGSM surface exchanges the
/// code server-side holding a client secret, so it is a confidential client and the secret already
/// blocks a stolen code. It covers the residual cases, costs one hash, and OAuth 2.1 asks for it.
/// Carrying the verifier in the same cookie is what lets it be added with no server-side store.
/// </para>
/// </remarks>
public sealed class OAuthHandshake
{
    // '.' separates the two halves: both are base64url, whose alphabet excludes it.
    private const char Separator = '.';

    private OAuthHandshake(string state, string codeVerifier)
    {
        State = state;
        CodeVerifier = codeVerifier;
    }

    /// <summary>The CSRF nonce echoed back by Discord on the callback.</summary>
    public string State { get; }

    /// <summary>The PKCE secret, presented at the token exchange and never sent to the browser's URL.</summary>
    public string CodeVerifier { get; }

    /// <summary>
    /// The PKCE challenge sent on the authorize redirect — <c>S256</c>, the only method worth using
    /// (<c>plain</c> sends the verifier itself and protects nothing).
    /// </summary>
    public string CodeChallenge =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(CodeVerifier)));

    /// <summary>A fresh handshake: 128 bits of state, 256 bits of verifier, both from a CSPRNG.</summary>
    public static OAuthHandshake Create() => new(
        Base64Url(RandomNumberGenerator.GetBytes(16)),
        Base64Url(RandomNumberGenerator.GetBytes(32)));

    /// <summary>
    /// The single cookie value carrying both halves. The caller writes it <c>HttpOnly</c>,
    /// <c>Secure</c> under https, and <c>SameSite=Lax</c> — <b>not</b> <c>Strict</c>, which suppresses
    /// the cookie on the top-level redirect back from Discord and breaks every login.
    /// </summary>
    public string ToCookieValue() => $"{State}{Separator}{CodeVerifier}";

    /// <summary>
    /// Reads back what <see cref="ToCookieValue"/> wrote. Returns <see langword="false"/> for anything
    /// malformed — a truncated, tampered or absent cookie is a failed login, never a partial one.
    /// </summary>
    public static bool TryParse(string? cookieValue, out OAuthHandshake handshake)
    {
        handshake = null!;
        if (string.IsNullOrEmpty(cookieValue))
            return false;

        int split = cookieValue.IndexOf(Separator);
        if (split <= 0 || split == cookieValue.Length - 1)
            return false;

        string state = cookieValue[..split];
        string verifier = cookieValue[(split + 1)..];
        if (verifier.IndexOf(Separator) >= 0)
            return false;

        handshake = new OAuthHandshake(state, verifier);
        return true;
    }

    /// <summary>
    /// Whether the state Discord echoed back is the one this browser was issued. Compared in constant
    /// time: the comparison is against a value an attacker supplies and can vary at will, which is the
    /// shape a timing oracle needs.
    /// </summary>
    public bool MatchesState(string? returnedState)
    {
        if (string.IsNullOrEmpty(returnedState))
            return false;

        byte[] mine = Encoding.UTF8.GetBytes(State);
        byte[] theirs = Encoding.UTF8.GetBytes(returnedState);
        return CryptographicOperations.FixedTimeEquals(mine, theirs);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
