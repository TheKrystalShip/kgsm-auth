namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// Wire and storage strings for <see cref="UserStatus"/>, and the parse back.
/// </summary>
/// <remarks>
/// <para>
/// One spelling serves both the file and the surfaces above it, exactly as
/// <see cref="KgsmTiers"/> does for tiers. Two spellings for one fact is how a panel comes to show a
/// status the store does not have.
/// </para>
/// <para>
/// Words, never ordinals: the file is opened with <c>sqlite3</c> by whoever is diagnosing a login,
/// and <c>status = 'disabled'</c> tells them what <c>status = 2</c> does not. It also removes the
/// class of bug where reordering an enum silently repoints every stored row.
/// </para>
/// </remarks>
public static class UserStatuses
{
    public const string Pending = "pending";
    public const string Active = "active";
    public const string Disabled = "disabled";

    /// <summary>The wire form of a status.</summary>
    public static string ToWire(UserStatus status) => status switch
    {
        UserStatus.Active => Active,
        UserStatus.Disabled => Disabled,
        _ => Pending,
    };

    /// <summary>
    /// The status a string names, with anything unrecognised — absent, misspelled, or written by a
    /// newer build — read as <see cref="UserStatus.Disabled"/>.
    /// </summary>
    /// <remarks>
    /// Fail-closed, the same rule as <see cref="KgsmTiers.Parse"/>. Of the three states only
    /// <see cref="UserStatus.Disabled"/> denies outright, so an unreadable account is one nobody can
    /// sign in to rather than one that defaults to working.
    /// </remarks>
    public static UserStatus Parse(string? wire) => wire?.Trim().ToLowerInvariant() switch
    {
        Active => UserStatus.Active,
        Pending => UserStatus.Pending,
        _ => UserStatus.Disabled,
    };
}

/// <summary>Wire and storage strings for <see cref="TierSource"/>.</summary>
public static class TierSources
{
    public const string Derived = "derived";
    public const string Granted = "granted";

    /// <summary>The wire form of a tier's provenance.</summary>
    public static string ToWire(TierSource source) =>
        source == TierSource.Granted ? Granted : Derived;

    /// <summary>
    /// The provenance a string names, with anything unrecognised read as
    /// <see cref="TierSource.Derived"/> — so it shows up in a drift report rather than passing for a
    /// tier an admin deliberately chose.
    /// </summary>
    public static TierSource Parse(string? wire) =>
        wire?.Trim().ToLowerInvariant() == Granted ? TierSource.Granted : TierSource.Derived;
}

/// <summary>Wire and storage strings for <see cref="CredentialKind"/>.</summary>
public static class CredentialKinds
{
    public const string Password = "password";
    public const string Identity = "identity";

    /// <summary>The wire form of a credential kind.</summary>
    public static string ToWire(CredentialKind kind) =>
        kind == CredentialKind.Password ? Password : Identity;

    /// <summary>
    /// The kind a string names, with anything unrecognised read as
    /// <see cref="CredentialKind.Identity"/> — the kind that carries no secret, and so can never be
    /// verified against one.
    /// </summary>
    public static CredentialKind Parse(string? wire) =>
        wire?.Trim().ToLowerInvariant() == Password ? CredentialKind.Password : CredentialKind.Identity;
}
