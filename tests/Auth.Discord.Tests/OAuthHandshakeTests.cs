using System.Security.Cryptography;
using System.Text;

using TheKrystalShip.KGSM.Auth.Discord;

namespace TheKrystalShip.KGSM.Auth.Discord.Tests;

/// <summary>
/// The handshake is what stands between a login and two different attacks, so each property is
/// pinned rather than assumed from the implementation.
/// </summary>
public class OAuthHandshakeTests
{
    [Fact]
    public void EachHandshakeIsUnique()
    {
        // Predictable state is no state at all — an attacker who can guess it can forge the callback.
        var states = new HashSet<string>(StringComparer.Ordinal);
        var verifiers = new HashSet<string>(StringComparer.Ordinal);

        for (int i = 0; i < 200; i++)
        {
            OAuthHandshake h = OAuthHandshake.Create();
            Assert.True(states.Add(h.State));
            Assert.True(verifiers.Add(h.CodeVerifier));
        }
    }

    [Fact]
    public void ChallengeIsTheSha256OfTheVerifier()
    {
        // Discord recomputes this; a wrong transform fails every exchange with an opaque error.
        OAuthHandshake h = OAuthHandshake.Create();

        string expected = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(h.CodeVerifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Assert.Equal(expected, h.CodeChallenge);
    }

    [Fact]
    public void ChallengeIsNotTheVerifier()
    {
        // The challenge goes in a URL; the verifier must not. If these were ever equal, PKCE would be
        // sending its own secret through the channel it exists to distrust.
        OAuthHandshake h = OAuthHandshake.Create();
        Assert.NotEqual(h.CodeVerifier, h.CodeChallenge);
    }

    [Fact]
    public void CookieValueRoundTrips()
    {
        OAuthHandshake original = OAuthHandshake.Create();

        Assert.True(OAuthHandshake.TryParse(original.ToCookieValue(), out OAuthHandshake parsed));
        Assert.Equal(original.State, parsed.State);
        Assert.Equal(original.CodeVerifier, parsed.CodeVerifier);
        Assert.Equal(original.CodeChallenge, parsed.CodeChallenge);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("nostatehere")]      // no separator
    [InlineData(".onlyverifier")]    // empty state
    [InlineData("onlystate.")]       // empty verifier
    [InlineData("a.b.c")]            // tampered: an extra segment
    public void MalformedCookieIsRefused(string? cookie)
    {
        // A partial handshake must fail the login outright. Recovering half of it would mean either a
        // verifier with no state to bind it, or a state with no verifier to redeem the code.
        Assert.False(OAuthHandshake.TryParse(cookie, out _));
    }

    [Fact]
    public void StateMatchesOnlyItself()
    {
        OAuthHandshake h = OAuthHandshake.Create();

        Assert.True(h.MatchesState(h.State));
        Assert.False(h.MatchesState(h.State + "x"));
        Assert.False(h.MatchesState(h.State[..^1]));
        Assert.False(h.MatchesState(OAuthHandshake.Create().State));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AbsentStateNeverMatches(string? returned)
    {
        // The CSRF attack arrives as a callback with no state at all. Treating absent as "nothing to
        // check" is exactly the hole.
        Assert.False(OAuthHandshake.Create().MatchesState(returned));
    }

    [Fact]
    public void OneBrowsersHandshakeDoesNotValidateAnothers()
    {
        // The whole point: an attacker's own legitimately-issued state must not pass against the
        // victim's cookie. A server-side set of issued states would admit this; a cookie cannot.
        OAuthHandshake victim = OAuthHandshake.Create();
        OAuthHandshake attacker = OAuthHandshake.Create();

        Assert.False(victim.MatchesState(attacker.State));
    }

    [Fact]
    public void CookieValueCarriesNoSeparatorAmbiguity()
    {
        // base64url excludes '.', so the split point is never in doubt.
        for (int i = 0; i < 200; i++)
        {
            OAuthHandshake h = OAuthHandshake.Create();
            Assert.Equal(1, h.ToCookieValue().Count(c => c == '.'));
        }
    }
}
