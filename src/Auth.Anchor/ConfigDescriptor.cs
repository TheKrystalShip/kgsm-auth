using System.Text.Json;
using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// What this anchor can be configured with, read back from the descriptor its own build generated.
/// </summary>
/// <remarks>
/// <para>
/// The daemon reads its descriptor for one reason: it serves its own configuration surface. A leaf is
/// administered through the node that runs it, which scans that node's disk for descriptors — an
/// anchor is reached by address, from a browser that is usually nowhere near the machine it runs on,
/// so nothing next door can offer this on its behalf.
/// </para>
/// <para>
/// The file is the one the deploy installed, not one compiled in: a descriptor beside the binary
/// could describe a different build than the one running, and this way the surface and the file every
/// other reader sees are the same bytes. Absent, the surface reports that it has none rather than
/// inventing a shape.
/// </para>
/// </remarks>
internal sealed record ConfigDescriptor(
    string Id,
    string DisplayName,
    string Unit,
    string ApplyMode,
    IReadOnlyList<ConfigFloorSource> FloorSources,
    IReadOnlyList<ConfigGroupDef> Groups,
    IReadOnlyList<ConfigFieldDef> Fields)
{
    /// <summary>The one schema version this reader understands. Another is skipped rather than
    /// guessed at — the format's own forward-compatibility contract.</summary>
    public const int SupportedSchemaVersion = 1;

    public ConfigFieldDef? Field(string key) =>
        Fields.FirstOrDefault(f => string.Equals(f.Key, key, StringComparison.Ordinal));
}

internal sealed record ConfigGroupDef(string Id, string Label, int Order);

/// <summary>
/// One settable key. <see cref="Env"/> is the variable an override writes, which is what makes this
/// schema-agnostic: the surface never knows what the value means, only the name it binds through.
/// </summary>
internal sealed record ConfigFieldDef(
    string Key,
    string Env,
    string Label,
    string Description,
    string? Group,
    string Type,
    string? Default,
    IReadOnlyList<string>? Values,
    double? Min,
    double? Max,
    string? Unit,
    string Risk)
{
    public bool IsSecret => string.Equals(Type, "secret", StringComparison.Ordinal);
}

/// <summary>The descriptor as it sits on disk, all-nullable so a missing key is a named refusal
/// rather than a deserialization exception. Unknown properties are ignored: the format is additive.</summary>
internal sealed record RawConfigDescriptor(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("id")] string? Id,
    [property: JsonPropertyName("displayName")] string? DisplayName,
    [property: JsonPropertyName("unit")] string? Unit,
    [property: JsonPropertyName("applyMode")] string? ApplyMode,
    [property: JsonPropertyName("floorSources")] IReadOnlyList<RawFloorSource>? FloorSources,
    [property: JsonPropertyName("groups")] IReadOnlyList<RawConfigGroup>? Groups,
    [property: JsonPropertyName("fields")] IReadOnlyList<RawConfigField>? Fields);

internal sealed record RawFloorSource(
    [property: JsonPropertyName("kind")] string? Kind,
    [property: JsonPropertyName("path")] string? Path);

internal sealed record RawConfigGroup(
    [property: JsonPropertyName("id")] string? Id,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("order")] int Order);

internal sealed record RawConfigField(
    [property: JsonPropertyName("key")] string? Key,
    [property: JsonPropertyName("env")] string? Env,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("group")] string? Group,
    [property: JsonPropertyName("type")] string? Type,
    [property: JsonPropertyName("default")] string? Default,
    [property: JsonPropertyName("values")] IReadOnlyList<string>? Values,
    [property: JsonPropertyName("min")] double? Min,
    [property: JsonPropertyName("max")] double? Max,
    [property: JsonPropertyName("unit")] string? Unit,
    [property: JsonPropertyName("risk")] string? Risk);

/// <summary>
/// Reads the descriptor from disk, cached for a short while so a page view costs one read rather than
/// one per field. The deploy rewrites the file, so the cache expiring is how a redeploy's new surface
/// arrives without a restart.
/// </summary>
internal sealed class ConfigDescriptorStore(AnchorOptions options, ILogger<ConfigDescriptorStore> logger)
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(30);

    private readonly Lock _gate = new();
    private ConfigDescriptor? _cached;
    private DateTime _readUtc = DateTime.MinValue;
    private bool _reported;

    /// <summary>The descriptor, or null when this host has none installed.</summary>
    public ConfigDescriptor? Current()
    {
        lock (_gate)
        {
            if ((DateTime.UtcNow - _readUtc) < Ttl)
                return _cached;

            _cached = Load();
            _readUtc = DateTime.UtcNow;
            return _cached;
        }
    }

    private ConfigDescriptor? Load()
    {
        string path = options.ConfigDescriptorPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return Miss($"no config descriptor at {path} — this anchor serves no configuration surface");

        RawConfigDescriptor? raw;
        try
        {
            raw = JsonSerializer.Deserialize(File.ReadAllText(path), AnchorJsonContext.Default.RawConfigDescriptor);
        }
        catch (Exception ex)
        {
            return Miss($"the config descriptor at {path} is not readable: {ex.Message}");
        }

        if (raw is null)
            return Miss($"the config descriptor at {path} is empty");

        if (raw.SchemaVersion != ConfigDescriptor.SupportedSchemaVersion)
            return Miss($"the config descriptor at {path} declares schemaVersion {raw.SchemaVersion}, " +
                        $"and this build reads {ConfigDescriptor.SupportedSchemaVersion}");

        if (raw.Id is not { Length: > 0 } id || raw.Unit is not { Length: > 0 } unit)
            return Miss($"the config descriptor at {path} is missing its id or unit");

        var fields = new List<ConfigFieldDef>();
        foreach (RawConfigField f in raw.Fields ?? [])
        {
            if (f.Key is not { Length: > 0 } key || f.Env is not { Length: > 0 } env)
                continue;

            fields.Add(new ConfigFieldDef(
                key, env, f.Label ?? key, f.Description ?? "", f.Group,
                f.Type ?? "string", f.Default, f.Values, f.Min, f.Max, f.Unit, f.Risk ?? "safe"));
        }

        var groups = (raw.Groups ?? [])
            .Where(g => g.Id is { Length: > 0 })
            .Select(g => new ConfigGroupDef(g.Id!, g.Label ?? g.Id!, g.Order))
            .OrderBy(g => g.Order)
            .ToList();

        var floors = (raw.FloorSources ?? [])
            .Where(f => f.Kind is { Length: > 0 } && f.Path is { Length: > 0 })
            .Select(f => new ConfigFloorSource(f.Kind!, f.Path!))
            .ToList();

        _reported = false;
        return new ConfigDescriptor(
            id, raw.DisplayName ?? id, unit, raw.ApplyMode ?? "restart", floors, groups, fields);
    }

    /// <summary>Reported once per reason rather than on every read, since this is polled.</summary>
    private ConfigDescriptor? Miss(string why)
    {
        if (!_reported)
        {
            logger.LogWarning("{Why}", why);
            _reported = true;
        }
        return null;
    }
}
