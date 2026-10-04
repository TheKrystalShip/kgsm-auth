using Microsoft.Extensions.Time.Testing;

namespace TheKrystalShip.Auth.Access.Tests;

/// <summary>
/// A cluster's authority, built up line by line, so a test states only what it is about.
/// </summary>
/// <remarks>
/// The catalog starts with the anchor's own actions and a handful of engine and leaf actions of each
/// scope kind and effect, which is what most tests need to have something to grant.
/// </remarks>
internal sealed class World
{
    public const string Start = "kgsm:server.start";
    public const string Console = "kgsm:server.console.read";
    public const string Library = "kgsm:library.read";
    public const string Metrics = "monitor:metrics.read";
    public const string Thresholds = "monitor:thresholds.write";
    public const string Prefs = "api:preferences.write";
    public const string Autorun = "assistant:autorun";

    public static readonly AccessScope Walter = AccessScope.ForNode("walter");
    public static readonly AccessScope Jessie = AccessScope.ForNode("jessie");
    public static readonly AccessScope Terraria = AccessScope.ForInstance("walter", "terraria", "9f3c");
    public static readonly AccessScope Factorio = AccessScope.ForInstance("walter", "factorio", "11aa");
    public static readonly AccessScope JessieTerraria = AccessScope.ForInstance("jessie", "terraria", "77bb");

    private readonly List<AccessAccount> _accounts = [];
    private readonly List<CatalogAction> _catalog =
    [
        .. AuthActions.Declared,
        new(Start, "Start servers", ActionEffect.Execute, ScopeKind.Instance),
        new(Console, "Read consoles", ActionEffect.Read, ScopeKind.Instance),
        new(Library, "Read the library", ActionEffect.Read, ScopeKind.Cluster),
        new(Metrics, "Read metrics", ActionEffect.Read, ScopeKind.Node),
        new(Thresholds, "Change thresholds", ActionEffect.Write, ScopeKind.Node),
        new(Prefs, "Change own preferences", ActionEffect.Write, ScopeKind.Cluster, Self: true),
        new(Autorun, "Skip confirmation", ActionEffect.Execute, ScopeKind.Cluster),
    ];
    private readonly List<Permission> _permissions = [];
    private readonly List<Role> _roles =
    [
        new(BuiltInRoles.OwnerId, BuiltInRoles.OwnerName, RoleKind.Owner, RoleRanks.Owner, new HashSet<string>()),
        new(BuiltInRoles.EveryoneId, BuiltInRoles.EveryoneName, RoleKind.Everyone, RoleRanks.Everyone, new HashSet<string>()),
    ];
    private readonly List<Assignment> _assignments = [];
    private readonly List<ServiceRequirement> _requirements = [];
    private int _next;

    public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 9, 25, 12, 0, 0, TimeSpan.Zero));

    public AuthorityFreshness Freshness { get; set; } = AuthorityFreshness.Authoritative;

    public int MinimumContract { get; set; } = AccessContract.Version;

    public string Person(string name, AccountStatus status = AccountStatus.Active)
    {
        string id = "usr_" + name;
        _accounts.Add(new AccessAccount(id, name, AccountKind.Person, status));
        return id;
    }

    public string Service(string component, string member, AccountStatus status = AccountStatus.Active)
    {
        ServiceIdentity service = new(component, member);
        string id = "usr_svc_" + component + "_" + member;
        _accounts.Add(new AccessAccount(id, service.Name, AccountKind.Service, status, service));
        return id;
    }

    public string Owner(string name = "owner")
    {
        string id = Person(name);
        Assign(id, BuiltInRoles.OwnerId, AccessScope.Cluster);
        return id;
    }

    public World Declare(CatalogAction action)
    {
        _catalog.Add(action);
        return this;
    }

    public string Permission(string name, params string[] actions)
    {
        string id = "prm_" + name.Replace(' ', '_');
        _permissions.Add(new Permission(id, name, actions.ToHashSet()));
        return id;
    }

    /// <summary>A custom role at <paramref name="rank"/>, holding one permission per action given.</summary>
    public string Role(string name, int rank, params string[] actions)
    {
        string id = "role_" + name.Replace(' ', '_');
        string permission = Permission(name + " actions", actions);
        _roles.Add(new Role(id, name, RoleKind.Custom, rank, new HashSet<string> { permission }));
        return id;
    }

    public void Everyone(params string[] actions)
    {
        string permission = Permission("everyone actions", actions);
        int at = _roles.FindIndex(r => r.RoleId == BuiltInRoles.EveryoneId);
        _roles[at] = _roles[at] with { Permissions = new HashSet<string> { permission } };
    }

    public string Assign(string account, string role, AccessScope scope)
    {
        string id = "asg_" + _next++;
        _assignments.Add(new Assignment(id, account, role, scope));
        return id;
    }

    public void Require(
        string service, string action, AccessScope? grant, RequirementState state = RequirementState.Approved,
        bool declared = true, ScopeKind kind = ScopeKind.Instance, string? decidedBy = null) =>
        _requirements.Add(new ServiceRequirement(service, action, kind, "because", state, grant, decidedBy, declared));

    public AuthoritySnapshot Snapshot() =>
        new(7, _accounts, _catalog, _permissions, _roles, _assignments, _requirements, Freshness, MinimumContract);

    public AccessEvaluator Evaluator() => new(Snapshot(), Clock);

    public AuthorityRefusal? Check(string actor, AuthorityEdit edit) =>
        AuthorityRules.Check(Snapshot(), actor, edit, Clock);
}
