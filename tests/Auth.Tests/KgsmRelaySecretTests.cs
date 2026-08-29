namespace TheKrystalShip.KGSM.Auth.Tests;

/// <summary>
/// The host's relay secret. Every case here is about a node nobody configured: the point of the
/// mechanism is that three co-located surfaces end up holding the same string with no operator
/// involved, and that a failure to reach one leaves the relay off rather than open.
/// </summary>
public class KgsmRelaySecretTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "kgsm-relay-" + Guid.NewGuid().ToString("N"));

    private string File_ => Path.Combine(_dir, "relay-secret");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void AConfiguredSecretIsUsedVerbatimAndMintsNothing()
    {
        Assert.Equal("pinned", KgsmRelaySecret.Resolve("  pinned  ", File_));
        Assert.False(File.Exists(File_));
    }

    [Fact]
    public void AnUnconfiguredHostMintsOne()
    {
        string secret = KgsmRelaySecret.Resolve(null, File_);

        Assert.NotEqual("", secret);
        Assert.Equal(secret, File.ReadAllText(File_).Trim());
    }

    [Fact]
    public void TheMintedSecretIsOwnerOnly()
    {
        KgsmRelaySecret.Resolve(null, File_);

#pragma warning disable CA1416 // every KGSM host is Linux; see KgsmRelaySecret
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(File_));
#pragma warning restore CA1416
    }

    [Fact]
    public void EverySurfaceOnTheHostResolvesTheSameSecret()
    {
        // The whole point: the assistant, the api and the bot each call this and must agree.
        string first = KgsmRelaySecret.Resolve(null, File_);
        string second = KgsmRelaySecret.Resolve(null, File_);
        string third = KgsmRelaySecret.Resolve("", File_);

        Assert.Equal(first, second);
        Assert.Equal(first, third);
    }

    [Fact]
    public void ConcurrentFirstStartsAgreeOnOneSecret()
    {
        // Three units starting together on a fresh node. Exclusive create means one writes and the
        // others read it, so no surface ends up holding a secret the others never saw.
        string[] resolved = new string[8];
        Parallel.For(0, resolved.Length, i => resolved[i] = KgsmRelaySecret.Resolve(null, File_));

        Assert.All(resolved, s => Assert.Equal(resolved[0], s));
        Assert.NotEqual("", resolved[0]);
    }

    [Fact]
    public void AnUnwritableLocationLeavesTheRelayOff()
    {
        // Fail-closed: an empty secret is "the relay path is off" everywhere it is read, never
        // "no secret required".
        Assert.Equal("", KgsmRelaySecret.Resolve(null, "/proc/kgsm-relay-secret-cannot-exist/secret"));
    }

    [Fact]
    public void TheDefaultLocationIsOneTheServiceAccountOwns()
    {
        // /var/lib/kgsm is root-owned on a host provisioned from a checkout, so a secret directly in
        // it could be read and never created — the surfaces would fail into "the relay is off" and
        // say nothing. auth/ is owned by the account all three run as, on every host.
        Assert.Equal("/var/lib/kgsm/auth/relay-secret", KgsmRelaySecret.DefaultPath);
    }

    [Fact]
    public void AnEmptyFileIsNotASecret()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(File_, "   \n");

        // A truncated file would otherwise authenticate every caller presenting an empty header.
        Assert.Equal("", KgsmRelaySecret.Resolve(null, File_));
    }
}
