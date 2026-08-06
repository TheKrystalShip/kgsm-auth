namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// A host's Discord role → <see cref="KgsmTier"/> map, and the resolution that turns a caller's
/// guild roles into the tier they hold. This is the single definition of "who may do what" in the
/// ecosystem: the Control Panel API, the assistant and the Discord bot all answer the question here,
/// so the same person gets the same answer whichever surface they reach KGSM through.
/// <para>
/// Role ids are Discord snowflakes held as <b>strings</b> and compared ordinally — the member object
/// Discord returns carries them as strings, so comparing as strings never risks a parse.
/// </para>
/// </summary>
public sealed class KgsmRoleMap
{
    private readonly string[] _adminRoleIds;
    private readonly string[] _operatorRoleIds;

    /// <summary>An empty map: every guild member resolves to <see cref="KgsmTier.Viewer"/>, nobody elevates.</summary>
    public static readonly KgsmRoleMap Empty = new([], []);

    public KgsmRoleMap(IEnumerable<string> adminRoleIds, IEnumerable<string> operatorRoleIds)
    {
        _adminRoleIds = Clean(adminRoleIds);
        _operatorRoleIds = Clean(operatorRoleIds);
    }

    /// <summary>The role ids granting <see cref="KgsmTier.Admin"/>.</summary>
    public IReadOnlyList<string> AdminRoleIds => _adminRoleIds;

    /// <summary>The role ids granting <see cref="KgsmTier.Operator"/>.</summary>
    public IReadOnlyList<string> OperatorRoleIds => _operatorRoleIds;

    /// <summary>
    /// Whether this map elevates anyone at all. A host that configured no role ids grants every guild
    /// member <see cref="KgsmTier.Viewer"/> and nothing more — readable, but nobody can act. Surfacing
    /// that as a startup warning is the host's job; resolution itself stays silent.
    /// </summary>
    public bool IsEmpty => _adminRoleIds.Length == 0 && _operatorRoleIds.Length == 0;

    /// <summary>
    /// The tier a caller holds, given the guild roles they carry.
    /// <para>
    /// <paramref name="roleIds"/> is <see langword="null"/> when the caller is <b>not a member of the
    /// guild</b> — the 404 from a member lookup, or a Discord user with no member object here. That is
    /// the access gate: a non-member gets <see cref="KgsmTier.None"/>. It is deliberately distinct from
    /// an <em>empty</em> collection, which is a real member who holds only <c>@everyone</c> and floors
    /// at <see cref="KgsmTier.Viewer"/>.
    /// </para>
    /// A role id this map does not name contributes nothing, so an unknown or deleted role leaves the
    /// caller at the viewer floor rather than elevating or denying.
    /// </summary>
    /// <remarks>
    /// A failed role lookup must never be passed here as an empty collection to "fail soft" — that
    /// would turn an outage into a silent grant. The caller reports the failure and denies; this
    /// method only ever sees a measured answer. It is the security analog of the ecosystem's
    /// never-fabricate-a-status rule: authorize on measured membership and roles, or deny.
    /// </remarks>
    public KgsmTier Resolve(IReadOnlyCollection<string>? roleIds)
    {
        if (roleIds is null)
            return KgsmTier.None;

        if (Holds(roleIds, _adminRoleIds))
            return KgsmTier.Admin;
        if (Holds(roleIds, _operatorRoleIds))
            return KgsmTier.Operator;

        return KgsmTier.Viewer;
    }

    /// <summary>
    /// <see cref="Resolve(IReadOnlyCollection{string})"/> for a caller whose roles arrive as numeric
    /// snowflakes — the shape a Discord gateway client hands back, where the bot already holds the
    /// member object and needs no REST lookup. <see langword="null"/> still means "not a member".
    /// </summary>
    /// <remarks>
    /// Named apart from <see cref="Resolve(IReadOnlyCollection{string})"/> rather than overloading it:
    /// as an overload, an empty collection expression would bind to neither and fail to compile at
    /// every call site that passes one.
    /// </remarks>
    public KgsmTier ResolveSnowflakes(IEnumerable<ulong>? roleIds)
    {
        if (roleIds is null)
            return KgsmTier.None;

        List<string> ids = [];
        foreach (ulong id in roleIds)
            ids.Add(id.ToString(System.Globalization.CultureInfo.InvariantCulture));

        return Resolve(ids);
    }

    private static bool Holds(IReadOnlyCollection<string> roleIds, string[] granting)
    {
        foreach (string granted in granting)
            foreach (string held in roleIds)
                if (string.Equals(held, granted, StringComparison.Ordinal))
                    return true;

        return false;
    }

    // Configured ids arrive from a comma-separated environment variable, so blanks and stray
    // whitespace are normal input rather than a misconfiguration. An empty entry would match no
    // snowflake anyway; dropping it here keeps IsEmpty honest.
    private static string[] Clean(IEnumerable<string> ids)
    {
        List<string> cleaned = [];
        foreach (string id in ids)
        {
            string trimmed = id?.Trim() ?? "";
            if (trimmed.Length > 0)
                cleaned.Add(trimmed);
        }
        return [.. cleaned];
    }
}
