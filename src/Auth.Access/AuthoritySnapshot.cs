using System.Collections.Frozen;

namespace TheKrystalShip.KGSM.Auth.Access;

/// <summary>
/// Everything that decides access, at one authority version: accounts, the catalog, permissions,
/// roles, assignments and service requirements.
/// </summary>
/// <remarks>
/// <para>
/// Immutable, so one snapshot is shared by every concurrent evaluation and a new version is a new
/// snapshot rather than an edit under a reader's feet. The indexes an evaluation walks are built once,
/// here.
/// </para>
/// <para>
/// The anchor builds one from its own store; every other member builds one from its replica. Nothing
/// here reads a file: that is the store's job.
/// </para>
/// </remarks>
public sealed class AuthoritySnapshot
{
    private static readonly IReadOnlyList<Assignment> NoAssignments = [];
    private static readonly IReadOnlyList<ServiceRequirement> NoRequirements = [];

    private readonly FrozenDictionary<string, IReadOnlyList<Assignment>> _assignmentsByAccount;
    private readonly FrozenDictionary<string, IReadOnlyList<ServiceRequirement>> _requirementsByAccount;
    private readonly FrozenDictionary<string, FrozenSet<string>> _roleActions;

    /// <summary>Build a snapshot, and the indexes an evaluation walks.</summary>
    public AuthoritySnapshot(
        long version,
        IEnumerable<AccessAccount> accounts,
        IEnumerable<CatalogAction> catalog,
        IEnumerable<Permission> permissions,
        IEnumerable<Role> roles,
        IEnumerable<Assignment> assignments,
        IEnumerable<ServiceRequirement> requirements,
        AuthorityFreshness freshness,
        int minimumContractVersion = AccessContract.Version)
    {
        Version = version;
        Freshness = freshness;
        MinimumContractVersion = minimumContractVersion;

        Accounts = accounts.ToFrozenDictionary(a => a.AccountId, StringComparer.Ordinal);
        Catalog = catalog.ToFrozenDictionary(a => a.Id, StringComparer.Ordinal);
        Permissions = permissions.ToFrozenDictionary(p => p.PermissionId, StringComparer.Ordinal);
        Roles = roles.ToFrozenDictionary(r => r.RoleId, StringComparer.Ordinal);

        Assignment[] allAssignments = [.. assignments];
        Assignments = allAssignments;
        _assignmentsByAccount = allAssignments
            .GroupBy(a => a.AccountId, StringComparer.Ordinal)
            .ToFrozenDictionary(g => g.Key, g => (IReadOnlyList<Assignment>)[.. g], StringComparer.Ordinal);

        ServiceRequirement[] allRequirements = [.. requirements];
        Requirements = allRequirements;
        _requirementsByAccount = allRequirements
            .GroupBy(r => r.AccountId, StringComparer.Ordinal)
            .ToFrozenDictionary(g => g.Key, g => (IReadOnlyList<ServiceRequirement>)[.. g], StringComparer.Ordinal);

        _roleActions = Roles.Values.ToFrozenDictionary(
            r => r.RoleId,
            r => r.Permissions
                .Where(Permissions.ContainsKey)
                .SelectMany(p => Permissions[p].Actions)
                .ToFrozenSet(StringComparer.Ordinal),
            StringComparer.Ordinal);
    }

    /// <summary>The authority version this snapshot was read at.</summary>
    public long Version { get; }

    /// <summary>How recently this snapshot was confirmed current.</summary>
    public AuthorityFreshness Freshness { get; }

    /// <summary>The lowest evaluation contract the cluster accepts.</summary>
    public int MinimumContractVersion { get; }

    /// <summary>Every account, by id.</summary>
    public IReadOnlyDictionary<string, AccessAccount> Accounts { get; }

    /// <summary>Every declared action, by id.</summary>
    public IReadOnlyDictionary<string, CatalogAction> Catalog { get; }

    /// <summary>Every permission, by id.</summary>
    public IReadOnlyDictionary<string, Permission> Permissions { get; }

    /// <summary>Every role, by id, the built-ins included.</summary>
    public IReadOnlyDictionary<string, Role> Roles { get; }

    /// <summary>Every assignment.</summary>
    public IReadOnlyList<Assignment> Assignments { get; }

    /// <summary>Every service requirement.</summary>
    public IReadOnlyList<ServiceRequirement> Requirements { get; }

    /// <summary>The assignments an account holds.</summary>
    public IReadOnlyList<Assignment> AssignmentsOf(string accountId) =>
        _assignmentsByAccount.GetValueOrDefault(accountId, NoAssignments);

    /// <summary>The requirements a service account has declared or been decided on.</summary>
    public IReadOnlyList<ServiceRequirement> RequirementsOf(string accountId) =>
        _requirementsByAccount.GetValueOrDefault(accountId, NoRequirements);

    /// <summary>The actions a role grants through its permissions. Owner's are implicit and not listed.</summary>
    public IReadOnlySet<string> ActionsOf(string roleId) =>
        _roleActions.TryGetValue(roleId, out FrozenSet<string>? actions) ? actions : FrozenSet<string>.Empty;

    /// <summary>Whether the account holds Owner.</summary>
    public bool IsOwner(string accountId)
    {
        foreach (Assignment assignment in AssignmentsOf(accountId))
        {
            if (assignment.RoleId == BuiltInRoles.OwnerId)
                return true;
        }

        return false;
    }

    /// <summary>The accounts holding Owner that are active, and so can use it.</summary>
    public IEnumerable<string> ActiveOwners() =>
        Assignments
            .Where(a => a.RoleId == BuiltInRoles.OwnerId)
            .Select(a => a.AccountId)
            .Distinct(StringComparer.Ordinal)
            .Where(id => Accounts.TryGetValue(id, out AccessAccount? account) && account.Status == AccountStatus.Active);

    /// <summary>The roles holding a permission.</summary>
    public IEnumerable<Role> RolesHolding(string permissionId) =>
        Roles.Values.Where(r => r.Permissions.Contains(permissionId));

    /// <summary>A snapshot with nothing in it: no accounts, so everybody is refused.</summary>
    public static AuthoritySnapshot Empty { get; } =
        new(0, [], [], [], [], [], [], AuthorityFreshness.Authoritative);
}
