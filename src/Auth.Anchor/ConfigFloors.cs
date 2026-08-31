using System.Text.Json;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// What this host's deploy files set, before any override — the tier between the coded default and
/// what an administrator has changed.
/// </summary>
/// <remarks>
/// <para>
/// Reported so a person reading the page can tell three things apart that look identical when only
/// the value is shown: a knob left at what the code ships with, one the host's own deploy set, and
/// one somebody changed here. Without the middle tier, resetting an override looks like it will
/// restore the coded default when it will restore something else entirely.
/// </para>
/// <para>
/// The sources are the ones the descriptor declares, read in the order it declares them — lowest
/// precedence first, so the last writer wins, which is the order the daemon itself resolves them in.
/// A source that cannot be read contributes nothing and is not guessed at.
/// </para>
/// </remarks>
internal sealed class ConfigFloorReader(AnchorOptions options, ILogger<ConfigFloorReader> logger)
{
    private static readonly string[] UnitDirs =
    [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ];

    /// <summary>
    /// Env name → the value this host's deploy files set it to. Keys absent from the result are on
    /// their coded default.
    /// </summary>
    public IReadOnlyDictionary<string, string> Read(IReadOnlyList<ConfigFloorSource> sources)
    {
        var floor = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (ConfigFloorSource source in sources)
        {
            try
            {
                switch (source.Kind)
                {
                    case "appsettings": ReadJsonSettings(source.Path, floor); break;
                    case "env-file": ReadEnvFile(source.Path, floor); break;
                    case "systemd-unit": ReadUnit(source.Path, floor); break;
                    default: break;   // a kind this build does not know contributes nothing
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "floor source {Kind} at {Path} could not be read", source.Kind, source.Path);
            }
        }

        return floor;
    }

    /// <summary>
    /// The settings file, flattened to env names. <c>{"Anchor":{"ListenAddress":"x"}}</c> is what
    /// <c>Anchor__ListenAddress</c> binds from, so the two are the same fact spelled two ways and the
    /// flattening is what lets one table hold both.
    /// </summary>
    private static void ReadJsonSettings(string path, Dictionary<string, string> into)
    {
        if (!File.Exists(path))
            return;

        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
        Walk(doc.RootElement, "", into);
    }

    private static void Walk(JsonElement element, string prefix, Dictionary<string, string> into)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (JsonProperty p in element.EnumerateObject())
                    Walk(p.Value, prefix.Length == 0 ? p.Name : prefix + "__" + p.Name, into);
                break;

            // A list binds by index, which no descriptor field names — so it contributes nothing
            // rather than a key nothing could override.
            case JsonValueKind.Array:
                break;

            case JsonValueKind.Null:
                break;

            default:
                if (prefix.Length > 0)
                    into[prefix] = element.ToString();
                break;
        }
    }

    /// <summary>
    /// An env file, in systemd's own reading of one: <c>KEY=value</c>, blanks and <c>#</c> comments
    /// skipped. The override file is passed over wherever it appears — it is the tier ABOVE this one,
    /// and counting it here would report every override as something the host's deploy had set.
    /// </summary>
    private void ReadEnvFile(string path, Dictionary<string, string> into)
    {
        if (!File.Exists(path) || SameFile(path, options.ConfigOverridePath))
            return;

        foreach (string line in File.ReadAllLines(path))
        {
            string trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] == '#')
                continue;

            int eq = trimmed.IndexOf('=');
            if (eq <= 0)
                continue;

            into[trimmed[..eq].Trim()] = Unquote(trimmed[(eq + 1)..].Trim());
        }
    }

    /// <summary>
    /// The unit, read the way systemd reads it: <c>Environment=</c> sets a value directly and
    /// <c>EnvironmentFile=</c> pulls one in, both in file order, and a drop-in is appended after the
    /// unit itself. Following the referenced files is what makes the reported floor the real one —
    /// this unit sets several of its keys through the shared files under <c>/etc/kgsm</c>, and a
    /// reader that stopped at <c>Environment=</c> would report a coded default that is not in force.
    /// </summary>
    private void ReadUnit(string unitName, Dictionary<string, string> into)
    {
        foreach (string dir in UnitDirs)
        {
            string unit = Path.Combine(dir, unitName);
            if (File.Exists(unit))
                ReadUnitFile(unit, into);

            string dropInDir = Path.Combine(dir, unitName + ".d");
            if (!Directory.Exists(dropInDir))
                continue;

            foreach (string conf in Directory.GetFiles(dropInDir, "*.conf").OrderBy(f => f, StringComparer.Ordinal))
                ReadUnitFile(conf, into);
        }
    }

    private void ReadUnitFile(string path, Dictionary<string, string> into)
    {
        foreach (string line in File.ReadAllLines(path))
        {
            string trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] == '#' || trimmed[0] == ';')
                continue;

            if (trimmed.StartsWith("Environment=", StringComparison.Ordinal))
            {
                string assignment = trimmed["Environment=".Length..].Trim();
                int eq = assignment.IndexOf('=');
                if (eq > 0)
                    into[assignment[..eq].Trim()] = Unquote(assignment[(eq + 1)..].Trim());
                continue;
            }

            if (trimmed.StartsWith("EnvironmentFile=", StringComparison.Ordinal))
            {
                string file = trimmed["EnvironmentFile=".Length..].Trim();
                // A leading '-' means "absent is fine", which is a statement about the file rather
                // than about its contents.
                ReadEnvFile(file.TrimStart('-'), into);
            }
        }
    }

    private static bool SameFile(string a, string b)
    {
        if (string.IsNullOrWhiteSpace(b))
            return false;
        try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.Ordinal); }
        catch { return false; }
    }

    private static string Unquote(string value) =>
        value.Length >= 2 && ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\''))
            ? value[1..^1]
            : value;
}

/// <summary>Where one tier of this anchor's configuration comes from, as its descriptor declares it.</summary>
internal sealed record ConfigFloorSource(string Kind, string Path);
