using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// This anchor's configuration surface on the wire.
/// </summary>
/// <remarks>
/// The shape is kgsm-api's <c>LeafConfig</c>, key for key, and deliberately so: the Control Panel
/// renders a component's configuration from one set of components, and a second shape would mean a
/// second renderer that drifts from the first. What differs is who answers — a leaf's surface comes
/// from the node that runs it, an anchor's from the anchor.
/// </remarks>
internal sealed record AnchorConfig(
    [property: JsonPropertyName("leaf")] string Leaf,
    [property: JsonPropertyName("displayName")] string DisplayName,
    [property: JsonPropertyName("unit")] string Unit,
    [property: JsonPropertyName("fields")] IReadOnlyList<AnchorConfigField> Fields,
    [property: JsonPropertyName("groups")] IReadOnlyList<AnchorConfigGroup> Groups,
    [property: JsonPropertyName("editable")] bool Editable,
    [property: JsonPropertyName("editableReason")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? EditableReason,
    [property: JsonPropertyName("applyMode")] string ApplyMode,
    [property: JsonPropertyName("fromDescriptor")] bool FromDescriptor);

internal sealed record AnchorConfigGroup(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("order")] int Order);

/// <summary>
/// One settable key and what it is currently running on, in three honest tiers: the coded
/// <see cref="Default"/> the build ships, the <see cref="Floor"/> this host's deploy files set, and
/// the <see cref="Value"/> an administrator overrode it with. Any of them is null when there is
/// genuinely none — <see cref="Source"/> says which tier is in force and says <c>unknown</c> rather
/// than picking a plausible one.
/// </summary>
/// <remarks>
/// <see cref="Value"/>, <see cref="Default"/> and <see cref="Floor"/> are written even when null,
/// against this context's default: a client binds one shape whichever tier a field is on, and a key
/// that vanishes when it has no value is a key a renderer has to guess the absence of.
/// </remarks>
internal sealed record AnchorConfigField(
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("envName")] string EnvName,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("enum")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<string>? Enum,
    [property: JsonPropertyName("isSecret")] bool IsSecret,
    [property: JsonPropertyName("overridden")] bool Overridden,
    [property: JsonPropertyName("value")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? Value,
    [property: JsonPropertyName("default")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? Default,
    [property: JsonPropertyName("floor")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? Floor,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("group")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Group,
    [property: JsonPropertyName("min")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] double? Min,
    [property: JsonPropertyName("max")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] double? Max,
    [property: JsonPropertyName("unit")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Unit,
    [property: JsonPropertyName("risk")] string Risk);

/// <summary>Which tier a field's current value comes from.</summary>
internal static class ConfigSource
{
    public const string Override = "override";
    public const string Floor = "floor";
    public const string Default = "default";
    public const string Unknown = "unknown";
}

/// <summary>
/// A configuration change. <see cref="Values"/> sets or replaces; <see cref="Reset"/> names keys to
/// return to the deploy floor. A key in both is a contradiction and is refused rather than resolved.
/// </summary>
internal sealed record AnchorConfigUpdate(
    [property: JsonPropertyName("values")] IReadOnlyDictionary<string, string>? Values,
    [property: JsonPropertyName("reset")] IReadOnlyList<string>? Reset);

/// <summary>
/// What happened. <c>applied</c> means written and the restart is under way; <c>unchanged</c> means
/// the request asked for what was already in force, so nothing was written and nothing was bounced.
/// </summary>
internal sealed record AnchorConfigApplyResult(
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("restarting")] bool Restarting,
    [property: JsonPropertyName("config")] AnchorConfig Config);

internal static class ConfigOutcome
{
    public const string Applied = "applied";
    public const string Unchanged = "unchanged";
}
