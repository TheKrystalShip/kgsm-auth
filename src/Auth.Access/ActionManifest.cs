using System.Text.Json;
using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Access;

/// <summary>
/// One component's action manifest, as its build writes it and a member reports it.
/// </summary>
/// <remarks>
/// The format's authority is <c>kgsm-docs/reference/action-manifest.md</c>. Ids here are local; the
/// wire id is <c>&lt;Component&gt;:&lt;id&gt;</c>.
/// </remarks>
public sealed record ActionManifest(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("component")] string Component,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("actions")] IReadOnlyList<ManifestAction>? Actions,
    [property: JsonPropertyName("requires")] IReadOnlyList<ManifestRequirement>? Requires)
{
    /// <summary>The one schema version this build reads.</summary>
    public const int SupportedSchemaVersion = 1;

    /// <summary>The actions this manifest declares, as catalog actions with their full ids.</summary>
    /// <remarks>An entry that is not a well-formed action is left out rather than guessed at.</remarks>
    public IEnumerable<CatalogAction> CatalogActions()
    {
        foreach (ManifestAction action in Actions ?? [])
        {
            string id = $"{Component}:{action.Id}";
            if (!ActionIds.IsValid(id) || string.IsNullOrWhiteSpace(action.Title))
                continue;

            yield return new CatalogAction(
                id, action.Title.Trim(), ActionEffects.Parse(action.Effect), ScopeKinds.Parse(action.Scope), action.Self ?? false);
        }
    }
}

/// <summary>One action a manifest declares.</summary>
public sealed record ManifestAction(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("effect")] string? Effect,
    [property: JsonPropertyName("scope")] string? Scope,
    [property: JsonPropertyName("self")] bool? Self);

/// <summary>Another component's action a manifest's component performs as its own service account.</summary>
public sealed record ManifestRequirement(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("scope")] string? Scope,
    [property: JsonPropertyName("why")] string? Why);

/// <summary>
/// What one member reports it is responsible for: every manifest it holds.
/// </summary>
/// <remarks>
/// An anchor reports its own manifest; a node reports its engine's and every leaf's. A report replaces
/// the member's previous one wholesale, so a component missing from it is a component that member no
/// longer runs.
/// </remarks>
/// <param name="Anchor">
/// Whether the member is an anchor. A service's requirements are approved automatically at the member's
/// own scope — the cluster for an anchor, the node for a node.
/// </param>
/// <param name="Manifests">Every manifest the member holds.</param>
/// <param name="Sequence">
/// When the member read its manifests, in Unix milliseconds. The bus does not order delivery, so a
/// report older than the one the anchor holds is ignored rather than rolling the catalog back.
/// </param>
public sealed record MemberCatalogReport(
    [property: JsonPropertyName("anchor")] bool Anchor,
    [property: JsonPropertyName("manifests")] IReadOnlyList<ActionManifest> Manifests,
    [property: JsonPropertyName("sequence")] long Sequence = 0);

/// <summary>
/// A node's word that one install of an instance is gone, so every grant naming it goes too.
/// </summary>
/// <param name="Instance">The instance's name.</param>
/// <param name="Nonce">The install nonce of the install that went.</param>
public sealed record InstanceUninstalledReport(
    [property: JsonPropertyName("instance")] string Instance,
    [property: JsonPropertyName("nonce")] string Nonce);

/// <summary>The bus message types the catalog and instance lifetimes travel as.</summary>
public static class AuthorityMessages
{
    /// <summary>A member's <see cref="MemberCatalogReport"/>, sent to the auth anchor.</summary>
    public const string CatalogDeclared = "catalog.declared";

    /// <summary>A node's <see cref="InstanceUninstalledReport"/>, sent to the auth anchor.</summary>
    public const string InstanceUninstalled = "instance.uninstalled";
}

/// <summary>Reads an action manifest from disk.</summary>
public static class ActionManifests
{
    /// <summary>
    /// The manifest at <paramref name="path"/>, or <see langword="null"/> with the reason when it cannot
    /// be read, does not parse, or is a schema version this build does not know.
    /// </summary>
    public static ActionManifest? TryRead(string path, out string? problem)
    {
        problem = null;
        try
        {
            ActionManifest? manifest = JsonSerializer.Deserialize(
                File.ReadAllText(path), AccessJsonContext.Default.ActionManifest);

            if (manifest is null)
                problem = "empty";
            else if (manifest.SchemaVersion != ActionManifest.SupportedSchemaVersion)
                problem = $"schema version {manifest.SchemaVersion}, and this build reads {ActionManifest.SupportedSchemaVersion}";
            else if (!ActionIds.IsValid(manifest.Component + ":x"))
                problem = $"'{manifest.Component}' is not a component namespace";
            else
                return manifest;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            problem = e.Message;
        }

        return null;
    }
}

/// <summary>Source-generated JSON for everything a member reports about actions.</summary>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = false)]
[JsonSerializable(typeof(ActionManifest))]
[JsonSerializable(typeof(MemberCatalogReport))]
[JsonSerializable(typeof(InstanceUninstalledReport))]
public sealed partial class AccessJsonContext : JsonSerializerContext;
