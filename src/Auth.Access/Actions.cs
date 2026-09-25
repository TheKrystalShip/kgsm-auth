using System.Diagnostics.CodeAnalysis;

namespace TheKrystalShip.KGSM.Auth.Access;

/// <summary>What performing an action does. Grants nothing on its own.</summary>
/// <remarks>
/// It decides what a member whose replica has gone stale still serves — reads only — and how the role
/// editor groups the catalog.
/// </remarks>
public enum ActionEffect
{
    /// <summary>Observes and changes nothing.</summary>
    Read = 0,

    /// <summary>Changes stored state.</summary>
    Write = 1,

    /// <summary>Makes something happen.</summary>
    Execute = 2,
}

/// <summary>Wire strings for <see cref="ActionEffect"/>, and the parse back.</summary>
public static class ActionEffects
{
    public const string Read = "read";
    public const string Write = "write";
    public const string Execute = "execute";

    /// <summary>The wire form of an effect.</summary>
    public static string ToWire(ActionEffect effect) => effect switch
    {
        ActionEffect.Read => Read,
        ActionEffect.Execute => Execute,
        _ => Write,
    };

    /// <summary>
    /// The effect a string names, with anything unrecognised read as <see cref="ActionEffect.Write"/>.
    /// </summary>
    /// <remarks>
    /// Fail-closed: only <see cref="ActionEffect.Read"/> is served by a stale member, so an unreadable
    /// effect is one a stale member refuses.
    /// </remarks>
    public static ActionEffect Parse(string? wire) => wire?.Trim().ToLowerInvariant() switch
    {
        Read => ActionEffect.Read,
        Execute => ActionEffect.Execute,
        _ => ActionEffect.Write,
    };
}

/// <summary>
/// One action a component performs, as the catalog holds it.
/// </summary>
/// <param name="Id">The wire id, <c>&lt;component&gt;:&lt;id&gt;</c>. Immutable in meaning.</param>
/// <param name="Title">What the role editor shows.</param>
/// <param name="Effect">What performing it does.</param>
/// <param name="Scope">The narrowest scope at which granting it means something.</param>
/// <param name="Self">
/// Whether it only ever reads or changes the caller's own records. Every active person holds every
/// self action; they are never filed into a permission.
/// </param>
public sealed record CatalogAction(string Id, string Title, ActionEffect Effect, ScopeKind Scope, bool Self = false);

/// <summary>
/// The action id convention: <c>&lt;component&gt;:&lt;id&gt;</c>, both halves lower-case.
/// </summary>
/// <remarks>
/// The component half comes from the manifest that declares the action, so a component declares
/// actions only in its own namespace. A component is <c>[a-z0-9-]</c>, starting with a letter or digit;
/// an id is <c>[a-z0-9._-]</c>, starting with a letter or digit.
/// </remarks>
public static class ActionIds
{
    /// <summary>The component every <c>auth:*</c> action belongs to.</summary>
    public const string AuthComponent = "auth";

    /// <summary>Compose an action id from its halves.</summary>
    public static string Format(string component, string id)
    {
        string action = $"{component}:{id}";
        if (!IsValid(action))
            throw new ArgumentException($"'{action}' is not an action id.");

        return action;
    }

    /// <summary>Whether <paramref name="action"/> is a well-formed action id.</summary>
    public static bool IsValid([NotNullWhen(true)] string? action) => TryParse(action, out _, out _);

    /// <summary>Split an action id into its component and its id.</summary>
    public static bool TryParse(string? action, out string component, out string id)
    {
        component = string.Empty;
        id = string.Empty;

        if (string.IsNullOrEmpty(action))
            return false;

        int separator = action.IndexOf(':');
        if (separator <= 0 || separator == action.Length - 1)
            return false;

        string c = action[..separator];
        string i = action[(separator + 1)..];
        if (!IsComponent(c) || !IsName(i))
            return false;

        component = c;
        id = i;
        return true;
    }

    /// <summary>
    /// Whether an action administers access itself. An <c>auth:*</c> action is never approved for a
    /// service automatically, and always requires a recent sign-in.
    /// </summary>
    public static bool IsAuth(string action) =>
        TryParse(action, out string component, out _) && component == AuthComponent;

    private static bool IsComponent(string s)
    {
        if (!char.IsAsciiLetterLower(s[0]) && !char.IsAsciiDigit(s[0]))
            return false;

        foreach (char c in s)
        {
            if (!char.IsAsciiLetterLower(c) && !char.IsAsciiDigit(c) && c != '-')
                return false;
        }

        return true;
    }

    private static bool IsName(string s)
    {
        if (!char.IsAsciiLetterLower(s[0]) && !char.IsAsciiDigit(s[0]))
            return false;

        foreach (char c in s)
        {
            if (!char.IsAsciiLetterLower(c) && !char.IsAsciiDigit(c) && c is not ('.' or '-' or '_'))
                return false;
        }

        return true;
    }
}

/// <summary>
/// The auth anchor's own actions: the ones that administer access.
/// </summary>
/// <remarks>
/// Performed by the anchor and declared in its manifest. Every one of them requires the caller's
/// session to have proved a credential within the anchor's re-authentication window.
/// </remarks>
public static class AuthActions
{
    /// <summary>Create, rename, rank and delete roles; change a role's permissions. Cluster scope.</summary>
    public const string RolesEdit = "auth:roles.edit";

    /// <summary>Create, rename and delete permissions; file actions into them. Cluster scope.</summary>
    public const string PermissionsEdit = "auth:permissions.edit";

    /// <summary>Create and delete assignments. Meaningful at any scope.</summary>
    public const string RolesAssign = "auth:roles.assign";

    /// <summary>Approve a pending account. Cluster scope.</summary>
    public const string AccountsApprove = "auth:accounts.approve";

    /// <summary>Disable and re-enable an account. Cluster scope.</summary>
    public const string AccountsDisable = "auth:accounts.disable";

    /// <summary>Delete an account, and every assignment it holds. Cluster scope.</summary>
    public const string AccountsDelete = "auth:accounts.delete";

    /// <summary>Create an account by hand. Cluster scope.</summary>
    public const string AccountsCreate = "auth:accounts.create";

    /// <summary>Approve, narrow and revoke service requirements. Cluster scope.</summary>
    public const string ServicesManage = "auth:services.manage";

    /// <summary>Every action above, as the anchor declares it.</summary>
    public static IReadOnlyList<CatalogAction> Declared { get; } =
    [
        new(RolesEdit, "Edit roles", ActionEffect.Write, ScopeKind.Cluster),
        new(PermissionsEdit, "Edit permissions", ActionEffect.Write, ScopeKind.Cluster),
        new(RolesAssign, "Assign roles", ActionEffect.Write, ScopeKind.Instance),
        new(AccountsApprove, "Approve accounts", ActionEffect.Write, ScopeKind.Cluster),
        new(AccountsDisable, "Disable accounts", ActionEffect.Write, ScopeKind.Cluster),
        new(AccountsDelete, "Delete accounts", ActionEffect.Write, ScopeKind.Cluster),
        new(AccountsCreate, "Create accounts", ActionEffect.Write, ScopeKind.Cluster),
        new(ServicesManage, "Manage service requirements", ActionEffect.Write, ScopeKind.Cluster),
    ];
}
