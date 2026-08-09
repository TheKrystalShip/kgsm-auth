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
}
