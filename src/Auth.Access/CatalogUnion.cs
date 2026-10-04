namespace TheKrystalShip.Auth.Access;

/// <summary>One member declaring an action, at the version of the component that declares it.</summary>
public sealed record ActionDeclaration(string Member, string? Version);

/// <summary>An action in the catalog, and every member declaring it.</summary>
public sealed record CatalogEntry(CatalogAction Action, IReadOnlyList<ActionDeclaration> DeclaredBy);

/// <summary>
/// The catalog: the union of every reporting member's manifests.
/// </summary>
/// <remarks>
/// <para>
/// Members run different builds, so two members may declare one action at two versions of its
/// component. The union holds the action once, with every member and version declaring it; an action
/// runs only where a member declaring it runs.
/// </para>
/// <para>
/// An id is immutable in meaning, so two declarations of one id agree on what it does. Its title may
/// be reworded between versions, and the declaration from the highest version wins — then the member id
/// that sorts first, so the answer never depends on the order reports arrived in.
/// </para>
/// </remarks>
public static class CatalogUnion
{
    /// <summary>The catalog the reports of <paramref name="members"/> add up to, sorted by action id.</summary>
    public static IReadOnlyList<CatalogEntry> Of(IReadOnlyDictionary<string, MemberCatalogReport> members)
    {
        Dictionary<string, List<(CatalogAction Action, ActionDeclaration By)>> found = new(StringComparer.Ordinal);

        foreach ((string member, MemberCatalogReport report) in members)
        {
            foreach (ActionManifest manifest in report.Manifests)
            {
                foreach (CatalogAction action in manifest.CatalogActions())
                {
                    if (!found.TryGetValue(action.Id, out var declarations))
                        found[action.Id] = declarations = [];

                    declarations.Add((action, new ActionDeclaration(member, manifest.Version)));
                }
            }
        }

        return [.. found
            .OrderBy(f => f.Key, StringComparer.Ordinal)
            .Select(f =>
            {
                var chosen = f.Value
                    .OrderByDescending(d => d.By.Version, VersionOrder.Instance)
                    .ThenBy(d => d.By.Member, StringComparer.Ordinal)
                    .First();

                return new CatalogEntry(
                    chosen.Action,
                    [.. f.Value.Select(d => d.By).Distinct().OrderBy(d => d.Member, StringComparer.Ordinal)]);
            })];
    }

    /// <summary>
    /// Semantic-version order, lenient: numeric parts compare as numbers, a prerelease sorts below its
    /// release, and a version that does not parse sorts below every one that does.
    /// </summary>
    private sealed class VersionOrder : IComparer<string?>
    {
        public static VersionOrder Instance { get; } = new();

        public int Compare(string? x, string? y)
        {
            (int[]? xs, string? xp) = Split(x);
            (int[]? ys, string? yp) = Split(y);

            if (xs is null || ys is null)
                return (xs is null ? 0 : 1) - (ys is null ? 0 : 1);

            for (int i = 0; i < Math.Max(xs.Length, ys.Length); i++)
            {
                int a = i < xs.Length ? xs[i] : 0;
                int b = i < ys.Length ? ys[i] : 0;
                if (a != b)
                    return a.CompareTo(b);
            }

            if (xp is null || yp is null)
                return (xp is null ? 1 : 0) - (yp is null ? 1 : 0);

            return string.CompareOrdinal(xp, yp);
        }

        private static (int[]? Numbers, string? Prerelease) Split(string? version)
        {
            if (string.IsNullOrWhiteSpace(version))
                return (null, null);

            string core = version.Split('+')[0];
            int dash = core.IndexOf('-');
            string numbers = dash < 0 ? core : core[..dash];
            string? prerelease = dash < 0 ? null : core[(dash + 1)..];

            string[] parts = numbers.Split('.');
            int[] parsed = new int[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                if (!int.TryParse(parts[i], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out parsed[i]))
                    return (null, null);
            }

            return (parsed, prerelease);
        }
    }
}
