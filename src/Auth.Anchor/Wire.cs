using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>The error contract, the same shape every KGSM surface answers with.</summary>
/// <param name="Error">The body.</param>
internal sealed record ErrorEnvelope(ErrorBody Error);

/// <summary>
/// A refusal. <paramref name="Code"/> is stable and machine-matchable, <paramref name="Message"/> is
/// for a person.
/// </summary>
internal sealed record ErrorBody(string Code, string Message);

/// <summary>What a browser posts to sign in.</summary>
internal sealed record SignInRequest(string? Username, string? Password);

/// <summary>What a browser posts to rotate or end a session.</summary>
/// <param name="Refresh">The refresh token currently held.</param>
internal sealed record RefreshRequest(string? Refresh);

/// <summary>
/// A minted cluster session. The same shape kgsm-api answers a local sign-in with, so a client
/// adopts a session identically whichever door it came through.
/// </summary>
/// <param name="Token">The access bearer.</param>
/// <param name="Refresh">The refresh token. Rotated on every use.</param>
/// <param name="Tier">What this account may do, resolved now rather than read off the record.</param>
/// <param name="UserId">The opaque account id.</param>
/// <param name="Status">
/// <c>active</c> or <c>pending</c>. A pending account authenticates and holds <c>none</c>, which is
/// what lets a surface say "awaiting approval" rather than showing a bare denial to somebody who has
/// just proved who they are.
/// </param>
/// <param name="Cluster">The cluster this session is valid on — the token's audience, said plainly.</param>
/// <param name="AccessTokenExpiresAt">When the bearer dies.</param>
/// <param name="RefreshExpiresAt">The absolute cap on the session.</param>
internal sealed record SignInResult(
    string Token,
    string Refresh,
    string Tier,
    string UserId,
    string Status,
    string Cluster,
    DateTimeOffset AccessTokenExpiresAt,
    DateTimeOffset RefreshExpiresAt);

/// <summary>A rotated session. Both tokens are new and both must be adopted.</summary>
/// <param name="Token">The new access bearer.</param>
/// <param name="Refresh">The new refresh token. The previous one is dead.</param>
/// <param name="Tier">
/// Re-resolved against the store on every rotation, so a demotion takes effect at the next refresh
/// rather than at the end of the session.
/// </param>
/// <param name="ExpiresAt">When the new bearer dies.</param>
internal sealed record RefreshResult(
    string Token,
    string Refresh,
    string Tier,
    DateTimeOffset ExpiresAt);

/// <summary>Who the caller is, as this anchor currently understands them.</summary>
/// <param name="UserId">The opaque account id.</param>
/// <param name="Username">The login name. Renameable, never a key.</param>
/// <param name="DisplayName">What a person is shown.</param>
/// <param name="Tier">Resolved on this request, not read off the token.</param>
/// <param name="Status">The account's standing.</param>
/// <param name="Cluster">The cluster the session is scoped to.</param>
internal sealed record WhoAmI(
    string UserId,
    string Username,
    string DisplayName,
    string Tier,
    string Status,
    string Cluster);

/// <summary>An account, as an admin sees it. Never carries a secret in any form.</summary>
/// <param name="Id">The opaque <c>usr_…</c> id, stable across a rename.</param>
/// <param name="TierSource">
/// <c>granted</c> or <c>derived</c> — what an access review reads to tell a deliberate grant from one
/// nobody has looked at since it was seeded.
/// </param>
/// <param name="Username">The login name. Renameable, never a key.</param>
/// <param name="DisplayName">What a person is shown.</param>
/// <param name="Tier">What this account may do.</param>
/// <param name="Status">Whether it may be used at all.</param>
/// <param name="HasPassword">Whether a password can sign this account in at all.</param>
/// <param name="Identities">Linked external identities, as <c>provider:subject</c> handles.</param>
/// <param name="Created">When the account was made.</param>
/// <param name="Updated">When any field above last changed.</param>
internal sealed record AccountRecord(
    string Id,
    string Username,
    string DisplayName,
    string Tier,
    string TierSource,
    string Status,
    bool HasPassword,
    IReadOnlyList<string> Identities,
    DateTimeOffset Created,
    DateTimeOffset Updated);

/// <summary>The account list. A page shape with no paging, because the store's own list has none.</summary>
internal sealed record AccountsPage(IReadOnlyList<AccountRecord> Data);

/// <summary>
/// An admin's change to an account: its tier, its status, or both.
/// </summary>
/// <remarks>
/// Both fields are optional and an absent one is left alone, so changing a tier does not require
/// restating a status and cannot silently revert one somebody else just set.
/// </remarks>
/// <param name="Tier">The tier to grant, or null to leave it.</param>
/// <param name="Status">The standing to set, or null to leave it.</param>
internal sealed record AccountPatchRequest(string? Tier, string? Status);

/// <summary>
/// An account after a change, and the version the cluster will order that change by.
/// </summary>
/// <remarks>
/// The version is returned rather than left implicit because it is the whole guarantee: a caller that
/// sees it knows the change is the newest statement about this account, and every member that has not
/// applied it yet will refuse anything older.
/// </remarks>
internal sealed record AccountChanged(AccountRecord Account, long Version);

/// <summary>
/// Serializer metadata for everything this anchor puts on the wire.
/// </summary>
/// <remarks>
/// Every shape is registered here. There is no reflection fallback under AOT, so a type that is
/// missing throws when it is first serialized rather than failing the build.
/// </remarks>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ErrorEnvelope))]
[JsonSerializable(typeof(SignInRequest))]
[JsonSerializable(typeof(RefreshRequest))]
[JsonSerializable(typeof(SignInResult))]
[JsonSerializable(typeof(RefreshResult))]
[JsonSerializable(typeof(WhoAmI))]
[JsonSerializable(typeof(AccountsPage))]
[JsonSerializable(typeof(AccountPatchRequest))]
[JsonSerializable(typeof(AccountChanged))]
internal sealed partial class AnchorJsonContext : JsonSerializerContext;
