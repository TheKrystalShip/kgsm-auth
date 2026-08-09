namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// What a KGSM username may be, and the key two of them are compared by.
/// </summary>
/// <remarks>
/// <para>
/// The charset is restricted on purpose. Usernames are compared case-insensitively — nobody expects
/// <c>Haru</c> and <c>haru</c> to be two people — and case-insensitive comparison over arbitrary
/// Unicode is a homoglyph and Turkish-dotless-I problem, not a formatting one. Restricting to ASCII
/// letters, digits and three separators makes <see cref="Key"/> exact rather than approximately
/// right, and it is the same choice GitHub, Slack and Discord all make.
/// </para>
/// <para>
/// The display name carries no such restriction: it is rendered, never matched.
/// </para>
/// </remarks>
public static class Usernames
{
    /// <summary>The shortest a username may be.</summary>
    public const int MinLength = 3;

    /// <summary>The longest a username may be.</summary>
    public const int MaxLength = 32;

    /// <summary>
    /// The value uniqueness is enforced on. Lower-cased over the invariant culture, which is exact
    /// here because <see cref="IsValid"/> has already ruled out every character whose casing is
    /// culture-dependent.
    /// </summary>
    public static string Key(string username) => username.Trim().ToLowerInvariant();

    /// <summary>
    /// Whether <paramref name="username"/> is a usable username: 3–32 characters of ASCII letters,
    /// digits, <c>.</c>, <c>_</c> or <c>-</c>, beginning with a letter or a digit.
    /// </summary>
    /// <remarks>
    /// The leading-character rule keeps a username from being mistaken for a flag or a hidden file
    /// wherever one is passed to a shell, and stops a name that is nothing but separators.
    /// </remarks>
    public static bool IsValid(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        string trimmed = username.Trim();
        if (trimmed.Length is < MinLength or > MaxLength)
            return false;

        if (!char.IsAsciiLetterOrDigit(trimmed[0]))
            return false;

        foreach (char c in trimmed)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))
                return false;
        }

        return true;
    }

    /// <summary>
    /// The nearest usable username to <paramref name="proposed"/>, or <see langword="null"/> when
    /// nothing usable survives.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For the one case where the name is not typed by a person: an account provisioned from an
    /// external identity starts with whatever that provider calls them, and a provider's charset is
    /// not this one. Characters this charset does not allow are dropped rather than transliterated —
    /// a guess at what a name "should" be in ASCII is worse than a short name, and the display name
    /// keeps the original untouched.
    /// </para>
    /// <para>
    /// Returns null rather than inventing a name when nothing is left, so the caller decides what to
    /// do about it instead of ending up with an account called <c>user</c>.
    /// </para>
    /// </remarks>
    public static string? Sanitize(string? proposed)
    {
        if (string.IsNullOrWhiteSpace(proposed))
            return null;

        var kept = new System.Text.StringBuilder(MaxLength);
        foreach (char c in proposed.Trim())
        {
            if (kept.Length == MaxLength)
                break;

            if (char.IsAsciiLetterOrDigit(c))
                kept.Append(c);
            // A separator is kept only after something it can separate, so a leading one never
            // survives to fail the first-character rule.
            else if (c is '.' or '_' or '-' or ' ' && kept.Length > 0)
                kept.Append(c == ' ' ? '-' : c);
        }

        // Trailing separators are legal but read as a typo; a name ending in a dot is also what a
        // path or a sentence would leave behind.
        while (kept.Length > 0 && !char.IsAsciiLetterOrDigit(kept[^1]))
            kept.Length--;

        string candidate = kept.ToString();
        return IsValid(candidate) ? candidate : null;
    }
}
