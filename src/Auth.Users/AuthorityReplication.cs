namespace TheKrystalShip.Auth.Users;

/// <summary>
/// An external identity attached to a replicated account: enough to resolve who somebody is, and
/// nothing that could prove it.
/// </summary>
/// <remarks>
/// A handle proves nothing on its own — it is the name of a fact, not the evidence for it — so it
/// travels where a password hash never does: a session naming <c>discord:123</c> is matched to an
/// account through it, and a member with no such row would report a stranger.
/// </remarks>
/// <param name="Handle">The <c>provider:subject</c> handle a session's subject is matched against.</param>
/// <param name="Label">What a person sees in "connected accounts". Never matched on.</param>
public sealed record ReplicatedIdentity(string Handle, string? Label);

/// <summary>The message types the authority travels between members as.</summary>
/// <remarks>
/// A changed record carries the whole record at the version it was last written at; a removal carries
/// the id and the version it was removed at. A replica applies either only when it is newer than what
/// it holds for that record, so a late change cannot undo a later removal.
/// </remarks>
public static class AuthorityMessageTypes
{
    public const string AccountChanged = "account.changed";
    public const string AccountRemoved = "account.removed";
    public const string RoleChanged = "role.changed";
    public const string RoleRemoved = "role.removed";
    public const string PermissionChanged = "permission.changed";
    public const string PermissionRemoved = "permission.removed";
    public const string AssignmentChanged = "assignment.changed";
    public const string AssignmentRemoved = "assignment.removed";
    public const string CatalogChanged = "catalog.changed";

    /// <summary>The anchor's latest version, the staleness bound and the minimum contract.</summary>
    public const string Current = "authority.current";
}

/// <summary>What kind of record a replicated change is about.</summary>
public enum AuthorityRecordKind
{
    Account,
    Role,
    Permission,
    Assignment,
    Catalog,
}

/// <summary>
/// One record's key: its kind and id, spelled <c>&lt;kind&gt;:&lt;id&gt;</c> in the outbox and the
/// tombstones. The catalog is one record, <c>catalog</c>.
/// </summary>
public readonly record struct AuthorityRecordKey(AuthorityRecordKind Kind, string Id)
{
    /// <summary>The catalog, which replicates whole.</summary>
    public static AuthorityRecordKey Catalog { get; } = new(AuthorityRecordKind.Catalog, "");

    public static AuthorityRecordKey Account(string id) => new(AuthorityRecordKind.Account, id);
    public static AuthorityRecordKey Role(string id) => new(AuthorityRecordKind.Role, id);
    public static AuthorityRecordKey Permission(string id) => new(AuthorityRecordKind.Permission, id);
    public static AuthorityRecordKey Assignment(string id) => new(AuthorityRecordKind.Assignment, id);

    /// <summary>The stored spelling.</summary>
    public override string ToString() => Kind switch
    {
        AuthorityRecordKind.Account => "account:" + Id,
        AuthorityRecordKind.Role => "role:" + Id,
        AuthorityRecordKind.Permission => "permission:" + Id,
        AuthorityRecordKind.Assignment => "assignment:" + Id,
        _ => "catalog",
    };

    /// <summary>The key a stored spelling names, or <see langword="null"/> for one this build does not know.</summary>
    public static AuthorityRecordKey? Parse(string key)
    {
        if (key == "catalog")
            return Catalog;

        int colon = key.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0 || colon == key.Length - 1)
            return null;

        string id = key[(colon + 1)..];
        return key[..colon] switch
        {
            "account" => Account(id),
            "role" => Role(id),
            "permission" => Permission(id),
            "assignment" => Assignment(id),
            _ => null,
        };
    }

    /// <summary>The message type that carries this record's current state.</summary>
    public string ChangedType => Kind switch
    {
        AuthorityRecordKind.Account => AuthorityMessageTypes.AccountChanged,
        AuthorityRecordKind.Role => AuthorityMessageTypes.RoleChanged,
        AuthorityRecordKind.Permission => AuthorityMessageTypes.PermissionChanged,
        AuthorityRecordKind.Assignment => AuthorityMessageTypes.AssignmentChanged,
        _ => AuthorityMessageTypes.CatalogChanged,
    };

    /// <summary>The message type that carries this record's removal. The catalog is never removed.</summary>
    public string RemovedType => Kind switch
    {
        AuthorityRecordKind.Account => AuthorityMessageTypes.AccountRemoved,
        AuthorityRecordKind.Role => AuthorityMessageTypes.RoleRemoved,
        AuthorityRecordKind.Permission => AuthorityMessageTypes.PermissionRemoved,
        AuthorityRecordKind.Assignment => AuthorityMessageTypes.AssignmentRemoved,
        _ => throw new InvalidOperationException("The catalog is replaced, never removed."),
    };
}

/// <summary>A service requirement as it travels with its service account.</summary>
public sealed record RequirementRecord(
    string Action, string ScopeKind, string? Why, string State, string? Grant, string? DecidedBy, bool Declared);

/// <summary>Which component on which member a service account acts for.</summary>
public sealed record ServiceRecord(string Component, string Member);

/// <summary>
/// An account as it travels: who it is, whether it may act, the handles that identify it, and for a
/// service account the component it acts for and everything it requires.
/// </summary>
/// <remarks>
/// <para>
/// <b>No credential that could authenticate anybody is here.</b> Handles travel, because a member
/// resolves a session's subject through them; secrets stay on the anchor, where signing in happens. A
/// password travels as its handle with no label, which a replica holds as an identity with nothing to
/// verify against.
/// </para>
/// <para>
/// Enums travel as their stored spellings, so a value from a newer anchor parses fail-closed here: an
/// unknown status as disabled, an unknown kind as a service.
/// </para>
/// </remarks>
public sealed record AccountRecord(
    string UserId,
    string Username,
    string DisplayName,
    string Origin,
    string Kind,
    string Status,
    DateTimeOffset Created,
    DateTimeOffset Updated,
    IReadOnlyList<ReplicatedIdentity> Identities,
    ServiceRecord? Service,
    IReadOnlyList<RequirementRecord> Requirements,
    long Version);

/// <summary>A role: its name, kind, rank and the permissions it holds.</summary>
public sealed record RoleRecord(string RoleId, string Name, string Kind, int Rank, IReadOnlyList<string> Permissions, long Version);

/// <summary>A permission: its name and the actions filed into it.</summary>
public sealed record PermissionRecord(string PermissionId, string Name, IReadOnlyList<string> Actions, long Version);

/// <summary>An assignment: an account holding a role within a scope.</summary>
public sealed record AssignmentRecord(
    string AssignmentId, string AccountId, string RoleId, string Scope, string? GrantedBy, DateTimeOffset Created, long Version);

/// <summary>One declared action, as the catalog carries it.</summary>
public sealed record CatalogActionRecord(string Action, string Title, string Effect, string Scope, bool Self);

/// <summary>The whole catalog, which replicates as one record.</summary>
public sealed record CatalogRecord(IReadOnlyList<CatalogActionRecord> Actions, long Version);

/// <summary>A record that is gone, and the version that says so.</summary>
public sealed record RecordRemoval(string Id, long Version);

/// <summary>
/// The anchor's heartbeat: its latest version, how long a member stays current on it, and the lowest
/// evaluation contract the cluster accepts.
/// </summary>
/// <param name="Version">The authority version the anchor holds.</param>
/// <param name="StalenessBoundSeconds">How long a member stays current after applying one of these.</param>
/// <param name="MinimumContractVersion">The lowest evaluation contract a member may evaluate by.</param>
/// <param name="Sent">
/// When the anchor sent it. A heartbeat the bus delivers late confirms the moment it was sent, never the
/// moment it arrived.
/// </param>
public sealed record AuthorityCurrent(long Version, int StalenessBoundSeconds, int MinimumContractVersion, DateTimeOffset Sent);

/// <summary>Everything the anchor holds that decides access, at one version, for a member building its replica.</summary>
public sealed record AuthorityReplicaSnapshot(
    long Version,
    IReadOnlyList<AccountRecord> Accounts,
    IReadOnlyList<RoleRecord> Roles,
    IReadOnlyList<PermissionRecord> Permissions,
    IReadOnlyList<AssignmentRecord> Assignments,
    CatalogRecord Catalog,
    AuthorityCurrent Current);

/// <summary>A record the anchor owes the cluster: its current state, or that it is gone.</summary>
/// <param name="Key">The record.</param>
/// <param name="Version">The version it is owed at — the highest written for it.</param>
/// <param name="Removed">Whether what is owed is its removal.</param>
public readonly record struct AuthorityAnnouncement(AuthorityRecordKey Key, long Version, bool Removed);

/// <summary>What applying a replicated record did.</summary>
public enum AuthorityApplyOutcome
{
    /// <summary>The replica now holds what the anchor sent.</summary>
    Applied,

    /// <summary>Not newer than what the replica holds for that record. Dropped.</summary>
    Stale,

    /// <summary>
    /// Newer, and blocked by another record's name or handle that a message still in flight will move.
    /// Not applied; the sender delivers it again.
    /// </summary>
    Deferred,
}

/// <summary>Serializer metadata for the authority as it travels between members.</summary>
[System.Text.Json.Serialization.JsonSourceGenerationOptions(
    PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase)]
[System.Text.Json.Serialization.JsonSerializable(typeof(AccountRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(RoleRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(PermissionRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(AssignmentRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(CatalogRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(RecordRemoval))]
[System.Text.Json.Serialization.JsonSerializable(typeof(AuthorityCurrent))]
[System.Text.Json.Serialization.JsonSerializable(typeof(AuthorityReplicaSnapshot))]
public sealed partial class AuthorityReplicationJson : System.Text.Json.Serialization.JsonSerializerContext;
