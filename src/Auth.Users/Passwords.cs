namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// What a KGSM password may be.
/// </summary>
/// <remarks>
/// <para>
/// The rule lives here, beside the store that holds the hash, because every door that sets a
/// password has to agree on it: somebody registering, an admin resetting one for a person locked
/// out, and that person changing their own. Three separate checks in three separate callers is
/// three places for the floor to drift, and the one that drifts low is the one an attacker finds.
/// </para>
/// <para>
/// Length is the whole of the rule. A composition requirement — a digit, a symbol, a capital —
/// measures a shape rather than an amount of guessing, and reliably produces the same handful of
/// substitutions on a short word. Twelve characters of anything is worth more than eight
/// characters of theatre, so this asks for length and nothing else.
/// </para>
/// </remarks>
public static class Passwords
{
    /// <summary>The shortest a password may be.</summary>
    public const int MinLength = 12;

    /// <summary>Whether <paramref name="password"/> is long enough to be set.</summary>
    public static bool IsAcceptable(string? password) =>
        !string.IsNullOrEmpty(password) && password.Length >= MinLength;
}
