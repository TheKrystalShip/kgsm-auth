using System.Globalization;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Reads and changes this anchor's own configuration.
/// </summary>
/// <remarks>
/// <para>
/// <b>An apply here is not a leaf's apply, and the difference is not a missing feature.</b> When
/// kgsm-api changes a leaf, it restarts a process it is not, watches that process come back and puts
/// the old values back if it does not. An anchor changing itself has nobody to do the watching: the
/// process that would poll for health is the process being restarted. So a value that stops this
/// daemon starting stops it starting, and recovery is removing the override file on the machine —
/// the path is reported in the log line written before the restart, for exactly that moment.
/// </para>
/// <para>
/// Which is why the checking happens BEFORE anything is written. Every value is validated against the
/// descriptor's own type, enum and bounds — the same declarations the daemon's own parser clamps to,
/// so the panel cannot accept a value this daemon would refuse or silently move.
/// </para>
/// </remarks>
internal sealed class AnchorConfigService(
    ConfigDescriptorStore descriptors,
    ConfigOverrideStore overrides,
    ConfigFloorReader floors,
    SelfRestart restart,
    ILogger<AnchorConfigService> logger)
{
    /// <summary>The current surface, or null when this host installed no descriptor.</summary>
    public AnchorConfig? Read()
    {
        ConfigDescriptor? descriptor = descriptors.Current();
        if (descriptor is null)
            return null;

        IReadOnlyDictionary<string, string> over = overrides.Read();
        IReadOnlyDictionary<string, string> floor = floors.Read(descriptor.FloorSources);

        var fields = new List<AnchorConfigField>(descriptor.Fields.Count);
        foreach (ConfigFieldDef f in descriptor.Fields)
        {
            over.TryGetValue(f.Env, out string? overridden);
            floor.TryGetValue(f.Env, out string? floored);

            // A secret is never echoed, whatever tier it came from. That a value is SET is reported;
            // what it is, is not.
            bool isSecret = f.IsSecret;
            string source =
                overridden is not null ? ConfigSource.Override
                : floored is not null ? ConfigSource.Floor
                : f.Default is not null ? ConfigSource.Default
                : ConfigSource.Unknown;

            fields.Add(new AnchorConfigField(
                Key: f.Key,
                EnvName: f.Env,
                Label: f.Label,
                Description: f.Description,
                Type: f.Type,
                Enum: f.Values,
                IsSecret: isSecret,
                Overridden: overridden is not null,
                Value: isSecret ? null : overridden,
                Default: isSecret ? null : f.Default,
                Floor: isSecret ? null : floored,
                Source: source,
                Group: f.Group,
                Min: f.Min,
                Max: f.Max,
                Unit: f.Unit,
                Risk: f.Risk));
        }

        bool writable = restart.Available(descriptor.Unit, out string? why);

        return new AnchorConfig(
            Leaf: descriptor.Id,
            DisplayName: descriptor.DisplayName,
            Unit: descriptor.Unit,
            Fields: fields,
            Groups: [.. descriptor.Groups.Select(g => new AnchorConfigGroup(g.Id, g.Label, g.Order))],
            Editable: writable,
            EditableReason: writable ? null : why,
            ApplyMode: descriptor.ApplyMode,
            FromDescriptor: true);
    }

    /// <summary>
    /// Apply a change: validate, write, answer, then restart. Returns null when there is no
    /// descriptor, or an error string naming the first thing wrong with the request.
    /// </summary>
    public (AnchorConfigApplyResult? Result, string? Error) Apply(AnchorConfigUpdate update)
    {
        ConfigDescriptor? descriptor = descriptors.Current();
        if (descriptor is null)
            return (null, null);

        IReadOnlyList<string> reset = update.Reset ?? [];
        IReadOnlyDictionary<string, string> values =
            update.Values ?? new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (string key in reset)
        {
            if (values.ContainsKey(key))
                return (null, $"'{key}' is in both values and reset, and those ask for opposite things");
        }

        // Everything is checked before anything is written: a half-applied change would leave the
        // daemon running on a set nobody asked for.
        foreach ((string key, string value) in values)
        {
            if (descriptor.Field(key) is not { } field)
                return (null, $"'{key}' is not a key this anchor declares");

            if (Invalid(field, value) is { } why)
                return (null, why);
        }

        foreach (string key in reset)
        {
            if (descriptor.Field(key) is null)
                return (null, $"'{key}' is not a key this anchor declares");
        }

        var rows = new Dictionary<string, string>(overrides.Read(), StringComparer.Ordinal);
        var before = new Dictionary<string, string>(rows, StringComparer.Ordinal);

        foreach ((string key, string value) in values)
            rows[descriptor.Field(key)!.Env] = value;

        foreach (string key in reset)
            rows.Remove(descriptor.Field(key)!.Env);

        if (Same(before, rows))
        {
            // Nothing to write, so nothing to bounce. Restarting to apply a change that is not one
            // would drop every browser signed in through here for no reason at all.
            AnchorConfig? unchanged = Read();
            return (unchanged is null ? null : new AnchorConfigApplyResult(
                ConfigOutcome.Unchanged, Restarting: false, unchanged), null);
        }

        overrides.Write(rows);

        // Written before the restart is asked for, because after it there is nobody here to write it:
        // this names the file to remove if the daemon does not come back.
        logger.LogWarning(
            "configuration changed ({Count} override(s)) — restarting. If this anchor does not come " +
            "back, remove {Path} and start it again.", rows.Count, overrides.Path);

        AnchorConfig? after = Read();
        if (after is null)
            return (null, null);

        bool restarting = restart.Schedule(descriptor.Unit);
        return (new AnchorConfigApplyResult(ConfigOutcome.Applied, restarting, after), null);
    }

    /// <summary>
    /// Why a value is not acceptable, or null when it is. The checks are the descriptor's own
    /// declarations, which are generated from the settings type — so what the panel refuses and what
    /// the daemon would refuse are one statement, made once.
    /// </summary>
    private static string? Invalid(ConfigFieldDef field, string value) => field.Type switch
    {
        "int" when !long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _)
            => $"'{field.Key}' takes a whole number",

        "int" => Bounds(field, value),

        "bool" when !IsBool(value)
            => $"'{field.Key}' takes true or false",

        "enum" when field.Values is { Count: > 0 } allowed
                    && !allowed.Contains(value, StringComparer.Ordinal)
            => $"'{field.Key}' takes one of: {string.Join(", ", allowed)}",

        // A path is a string this daemon resolves; whether it exists is not this surface's claim to
        // make, since a directory can be created between the check and the restart.
        _ => null,
    };

    private static string? Bounds(ConfigFieldDef field, string value)
    {
        double n = double.Parse(value, CultureInfo.InvariantCulture);
        if (field.Min is { } min && n < min)
            return $"'{field.Key}' is at least {min.ToString(CultureInfo.InvariantCulture)}";
        if (field.Max is { } max && n > max)
            return $"'{field.Key}' is at most {max.ToString(CultureInfo.InvariantCulture)}";
        return null;
    }

    private static bool IsBool(string value) =>
        bool.TryParse(value, out _)
        || value is "1" or "0";

    private static bool Same(IReadOnlyDictionary<string, string> a, IReadOnlyDictionary<string, string> b)
    {
        if (a.Count != b.Count)
            return false;

        foreach ((string k, string v) in a)
        {
            if (!b.TryGetValue(k, out string? other) || !string.Equals(v, other, StringComparison.Ordinal))
                return false;
        }

        return true;
    }
}
