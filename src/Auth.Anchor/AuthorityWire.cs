using System.Text.Json.Serialization;

using TheKrystalShip.Api.Contracts;
using TheKrystalShip.KGSM.Auth.Access;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>Everything that decides access, as the pages that administer it read it.</summary>
/// <param name="Version">The authority version; every edit names it back.</param>
/// <param name="Roles">Every role, Owner first.</param>
/// <param name="Permissions">Every permission.</param>
/// <param name="Catalog">Every declared action.</param>
/// <param name="Assignments">Every assignment.</param>
/// <param name="Accounts">Every account, people and service accounts alike.</param>
internal sealed record AuthorityView(
    long Version,
    IReadOnlyList<AuthorityRoleView> Roles,
    IReadOnlyList<AuthorityPermissionView> Permissions,
    IReadOnlyList<AuthorityCatalogView> Catalog,
    IReadOnlyList<AuthorityAssignmentView> Assignments,
    IReadOnlyList<AuthorityAccountView> Accounts);

/// <summary>A role, in rank order, with the permissions it holds.</summary>
internal sealed record AuthorityRoleView(string Id, string Name, string Kind, int Rank, IReadOnlyList<string> Permissions);

/// <summary>A permission, the actions filed into it and the roles holding it.</summary>
internal sealed record AuthorityPermissionView(string Id, string Name, IReadOnlyList<string> Actions, IReadOnlyList<string> HeldBy);

/// <summary>A declared action: what it is, who declares it, and whether any permission holds it.</summary>
internal sealed record AuthorityCatalogView(
    string Action, string Title, string Effect, string Scope, bool Self, bool Unmapped,
    IReadOnlyList<AuthorityDeclarer> DeclaredBy);

/// <summary>A member declaring an action, at the version its component reported.</summary>
internal sealed record AuthorityDeclarer(string Member, string? Version);

/// <summary>An account holding a role within a scope.</summary>
internal sealed record AuthorityAssignmentView(string Id, string AccountId, string RoleId, string Scope, string? GrantedBy, DateTimeOffset Created);

/// <summary>An account as the authority pages list it: people and service accounts, apart by kind.</summary>
internal sealed record AuthorityAccountView(
    string Id, string Username, string DisplayName, string Kind, string Status,
    AuthorityServiceView? Service, IReadOnlyList<AuthorityRequirementView> Requirements);

/// <summary>The component and member a service account acts for.</summary>
internal sealed record AuthorityServiceView(string Component, string Member);

/// <summary>One thing a service account requires, and where it stands.</summary>
internal sealed record AuthorityRequirementView(
    string Action, string ScopeKind, string? Why, string State, string? Grant, string? DecidedBy, bool Declared);

/// <summary>
/// One change to who may do what, named against the version it was made at.
/// </summary>
/// <remarks>
/// One body for every kind of change, so a page posts what it edited and nothing chooses a route for
/// it. <see cref="Kind"/> names the change; the fields it needs are named per kind in
/// <see cref="AuthorityEndpoints"/>.
/// </remarks>
internal sealed record AuthorityEditRequest(
    long? Version,
    string? Kind,
    string? RoleId = null,
    string? PermissionId = null,
    string? AccountId = null,
    string? AssignmentId = null,
    string? Name = null,
    int? Rank = null,
    IReadOnlyList<string>? PermissionIds = null,
    IReadOnlyList<string>? Actions = null,
    string? Scope = null,
    string? Action = null);

/// <summary>What an edit did.</summary>
/// <param name="Version">The authority version it produced.</param>
/// <param name="CreatedId">The role, permission or assignment it created.</param>
/// <param name="Changes">How many records it changed, a cascade included.</param>
internal sealed record AuthorityEditResult(long Version, string? CreatedId, int Changes);

/// <summary>A refused edit: the reason, and for a subset refusal the actions not held.</summary>
internal sealed record AuthorityRefusalEnvelope(ErrorBody Error, IReadOnlyList<string>? Actions = null);

/// <summary>An edit made against an older version: the refusal, and the authority as it stands now.</summary>
internal sealed record StaleAuthorityEnvelope(ErrorBody Error, AuthorityView Authority);

/// <summary>Edits to judge without making them. Each is an edit request without its version.</summary>
internal sealed record AuthorityCheckRequest(IReadOnlyList<AuthorityEditRequest>? Edits);

/// <summary>Each edit's answer, in the order asked.</summary>
/// <param name="Version">The authority version every edit was judged against.</param>
/// <param name="Results">One answer per edit.</param>
internal sealed record AuthorityCheckResponse(long Version, IReadOnlyList<AuthorityCheckResult> Results);

/// <summary>Whether the rules allow one edit, and when not, the refusal an edit would get.</summary>
internal sealed record AuthorityCheckResult(
    bool Allowed, string? Code = null, string? Message = null, IReadOnlyList<string>? Actions = null);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AuthorityView))]
[JsonSerializable(typeof(AuthorityEditRequest))]
[JsonSerializable(typeof(AuthorityEditResult))]
[JsonSerializable(typeof(AuthorityRefusalEnvelope))]
[JsonSerializable(typeof(StaleAuthorityEnvelope))]
[JsonSerializable(typeof(AuthorityCheckRequest))]
[JsonSerializable(typeof(AuthorityCheckResponse))]
internal sealed partial class AuthorityWireJson : JsonSerializerContext;
