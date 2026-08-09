using System.Globalization;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// How instants are spelled on disk, and the parse back.
/// </summary>
/// <remarks>
/// The enums are spelled by <see cref="UserStatuses"/>, <see cref="TierSources"/> and
/// <see cref="CredentialKinds"/>, which are public because the surfaces above this store put the same
/// strings on the wire — one spelling for one fact, rather than a second that can drift from it.
/// Timestamps stay here: their format is the file's own, and nothing reads it back out of the store's
/// API.
/// </remarks>
internal static class UserWire
{
    /// <summary>
    /// An instant as a sortable ISO-8601 round-trip string in UTC, ending in <c>Z</c>.
    /// </summary>
    /// <remarks>
    /// Through <see cref="DateTimeOffset.UtcDateTime"/> rather than
    /// <see cref="DateTimeOffset.ToUniversalTime"/>, because the round-trip format renders an offset
    /// of zero as <c>+00:00</c> where a <see cref="DateTime"/> in UTC renders it as <c>Z</c>. Both
    /// parse back the same; only one sorts identically to every other UTC timestamp the ecosystem
    /// writes.
    /// </remarks>
    public static string ToWire(DateTimeOffset when) =>
        when.UtcDateTime.ToString("o", CultureInfo.InvariantCulture);

    /// <summary>An instant back off disk, always as UTC.</summary>
    public static DateTimeOffset ReadTime(string wire) =>
        DateTimeOffset.Parse(wire, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)
            .ToUniversalTime();
}
