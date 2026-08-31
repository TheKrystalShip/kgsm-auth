using System.Text;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The overrides an administrator has set through the Control Panel, and the file that delivers them
/// back to this daemon.
/// </summary>
/// <remarks>
/// <para>
/// The file IS the store. A leaf's overrides live in kgsm-api's database because the API holds them
/// on the leaf's behalf and the leaf never sees them; here the writer and the reader are the same
/// process, so a second copy would only be a second thing to disagree with the first. Reset to the
/// deploy floor is the file going away.
/// </para>
/// <para>
/// It is read back into the daemon by a systemd drop-in carrying <c>EnvironmentFile=-</c>, which is
/// why it is written as <c>Env=value</c> lines and why it wins: the drop-in is ordered after every
/// file the unit already loads. The daemon never reads it directly — it reads its configuration, and
/// this is one of the places that comes from.
/// </para>
/// <para>
/// <b>Atomic, and 0600.</b> Each render writes a temp file in the same directory and renames it over
/// the target, so a restart never reads half a file; the mode is tight because a descriptor may
/// declare a secret. A value's CR and LF are stripped, so an override can never inject a second line
/// and set a variable nobody asked for.
/// </para>
/// </remarks>
internal sealed class ConfigOverrideStore(AnchorOptions options, ILogger<ConfigOverrideStore> logger)
{
    private const UnixFileMode File0600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode Dir0700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    private static readonly char[] Newlines = ['\r', '\n'];

    public string Path => options.ConfigOverridePath;

    /// <summary>
    /// What is currently overridden, by ENV NAME. Read from the file on every call: it is small, it
    /// is read on a page view and after a write, and a cache here would answer with what this process
    /// last wrote rather than with what the file says.
    /// </summary>
    public IReadOnlyDictionary<string, string> Read()
    {
        var rows = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!File.Exists(Path))
            return rows;

        try
        {
            foreach (string line in File.ReadAllLines(Path))
            {
                string trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed[0] == '#')
                    continue;

                int eq = trimmed.IndexOf('=');
                if (eq <= 0)
                    continue;

                rows[trimmed[..eq].Trim()] = trimmed[(eq + 1)..];
            }
        }
        catch (Exception ex)
        {
            // An unreadable override file is reported and treated as none: the daemon is running on
            // whatever it loaded at start, and claiming rows we cannot read would describe a state
            // that is not this one.
            logger.LogWarning(ex, "could not read the config overrides at {Path}", Path);
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        return rows;
    }

    /// <summary>
    /// Write the whole override set. An empty set deletes the file, which is what returning every key
    /// to the deploy floor means — an empty file would be an override set that overrides nothing, and
    /// the two read differently to anybody looking at the disk.
    /// </summary>
    public void Write(IReadOnlyDictionary<string, string> rows)
    {
        string? dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path));
        if (dir is not null && !Directory.Exists(dir))
        {
            // The permission bits are the point of creating it here rather than letting the write do
            // it: this holds whatever an administrator typed, and a descriptor may declare a secret.
            if (OperatingSystem.IsLinux())
                Directory.CreateDirectory(dir, Dir0700);
            else
                Directory.CreateDirectory(dir);
        }

        if (rows.Count == 0)
        {
            try { File.Delete(Path); }
            catch (Exception ex) { logger.LogWarning(ex, "could not remove the config overrides at {Path}", Path); }
            return;
        }

        var text = new StringBuilder();
        text.Append("# Written by this anchor's own configuration surface. Edited by hand, it is\n");
        text.Append("# overwritten by the next change made through the panel.\n");
        foreach ((string env, string value) in rows.OrderBy(r => r.Key, StringComparer.Ordinal))
        {
            text.Append(env).Append('=');
            foreach (char c in value)
            {
                if (Array.IndexOf(Newlines, c) < 0)
                    text.Append(c);
            }
            text.Append('\n');
        }

        string temp = Path + ".tmp";
        File.WriteAllText(temp, text.ToString());
        if (OperatingSystem.IsLinux())
            File.SetUnixFileMode(temp, File0600);
        File.Move(temp, Path, overwrite: true);
    }
}
