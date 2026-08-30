using TheKrystalShip.KGSM.Auth.Sessions;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The anchor's session signing key on disk: loaded if it is there, generated once if it is not, and
/// never replaced silently.
/// </summary>
/// <remarks>
/// <para>
/// The key is the anchor's whole claim to be the anchor. Every member verifies sessions against the
/// public half, so a key that changed would invalidate every session in the cluster at once and leave
/// every member checking against something nothing signs with any more. Generation therefore happens
/// exactly once, on a machine that has no key at all.
/// </para>
/// <para>
/// A file that exists and cannot be read is an error, never a reason to generate. The difference
/// between "this anchor has no key yet" and "this anchor's key is unreadable" is the difference
/// between a first start and a broken one.
/// </para>
/// </remarks>
internal static class SigningKeyStore
{
    /// <summary>The mode the private key is written with, and required of one already there.</summary>
    private const UnixFileMode PrivateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>What <see cref="LoadOrCreate"/> did.</summary>
    internal enum Origin
    {
        /// <summary>The key on disk was read.</summary>
        Loaded,

        /// <summary>There was no key, and one was generated and written.</summary>
        Generated,
    }

    /// <summary>
    /// The signer for the key at <paramref name="path"/>, generating and writing one if the file does
    /// not exist.
    /// </summary>
    internal static (EcdsaSessionSigner Signer, Origin Origin) LoadOrCreate(string path)
    {
        string full = Path.GetFullPath(path);

        if (File.Exists(full))
            return (EcdsaSessionSigner.FromPem(File.ReadAllText(full)), Origin.Loaded);

        string? directory = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        EcdsaSessionSigner signer = EcdsaSessionSigner.Generate();

        // Created with the restricted mode rather than chmod'd after: between the write and the chmod
        // the private key would be readable by anyone on the machine, and that window is the whole
        // thing this mode exists to close.
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
        };
        if (OperatingSystem.IsLinux())
            options.UnixCreateMode = PrivateMode;

        using (var writer = new StreamWriter(new FileStream(full, options)))
            writer.Write(signer.ExportPrivatePem());

        return (signer, Origin.Generated);
    }

    /// <summary>
    /// Write the public half where members on this machine read it, and report whether the file now
    /// says what the key says.
    /// </summary>
    /// <remarks>
    /// World-readable on purpose: it is a verification key, and every member on the machine has to be
    /// able to read it. Written only when the content differs, so a restart that changes nothing
    /// leaves the file's timestamp alone and a member watching it is not woken for nothing.
    /// </remarks>
    internal static bool Publish(string path, string keysJson)
    {
        string full = Path.GetFullPath(path);
        string? directory = Path.GetDirectoryName(full);

        // The directory is scaffolded by kgsm-base for what several members on one machine share.
        // Absent, there is no member here to read the file and nothing to do about it.
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
            return false;

        if (File.Exists(full) && File.ReadAllText(full) == keysJson)
            return true;

        File.WriteAllText(full, keysJson);
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(full,
                UnixFileMode.UserRead | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }
        return true;
    }
}
