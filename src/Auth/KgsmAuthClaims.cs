namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// The claim names a KGSM session token carries, and the relay headers a trusted caller forwards an
/// already-resolved identity with. Both are named here so a token minted by one surface reads
/// identically in another, and so a relay's headers cannot drift apart between the sender and the
/// receiver.
/// </summary>
public static class KgsmAuthClaims
{
    /// <summary>The authorization tier, as a <see cref="KgsmTiers"/> wire string.</summary>
    public const string Tier = "tier";

    /// <summary>The host id this bearer is scoped to (mirrors the token audience).</summary>
    public const string Host = "host";

    /// <summary>
    /// Token kind — <see cref="KgsmTokenKind"/>. Keeps a refresh token from being accepted as an
    /// access bearer on a protected endpoint.
    /// </summary>
    public const string TokenKind = "tkn";

    /// <summary>The provider's username, a login-time profile snapshot.</summary>
    public const string Username = "uname";

    /// <summary>The provider's display name, a login-time profile snapshot.</summary>
    public const string Display = "disp";

    /// <summary>The provider's avatar URL, a login-time profile snapshot. Optional.</summary>
    public const string Avatar = "avatar";

    /// <summary>
    /// The session id, stable across a session's lifetime and carried by both the access and the
    /// refresh token. It is the key a session registry answers "is this session still alive" with —
    /// the one fact a stateless JWT cannot answer on its own.
    /// </summary>
    public const string SessionId = "sid";

    /// <summary>
    /// The per-token id, fresh on every mint. The session row stores the current refresh token's
    /// value, so a refresh presenting a stale one is a replay and is refused.
    /// </summary>
    public const string Jti = "jti";
}

/// <summary>The two kinds of token carried in the <see cref="KgsmAuthClaims.TokenKind"/> claim.</summary>
public static class KgsmTokenKind
{
    public const string Access = "access";
    public const string Refresh = "refresh";
}

/// <summary>
/// Headers a trusted, co-located caller forwards a verified end-user with, instead of that user
/// logging in a second time. The receiving service authenticates the <em>relay</em> by the shared
/// secret and then acts as the forwarded identity.
/// </summary>
/// <remarks>
/// Authority rides as one tier rather than a set of booleans, so the relay cannot express a
/// permission shape the rest of the ecosystem does not have. Parsing is fail-closed: an absent or
/// unrecognised <see cref="Tier"/> is <see cref="KgsmTier.None"/>, so a relay that does not speak
/// this header can never silently grant anything.
/// </remarks>
public static class KgsmRelayHeaders
{
    /// <summary>The shared secret proving the caller is the trusted relay.</summary>
    public const string Secret = "X-Relay-Secret";

    /// <summary>
    /// The subject the relay is acting on behalf of — the identity provider's own id for that person,
    /// unqualified. The receiver knows which provider its relay speaks for; the value is what that
    /// surface already keys a user by.
    /// </summary>
    public const string User = "X-Relay-User";

    /// <summary>That user's display name, for rendering only.</summary>
    public const string UserName = "X-Relay-User-Name";

    /// <summary>The tier the relay resolved for that user, as a <see cref="KgsmTiers"/> wire string.</summary>
    public const string Tier = "X-Relay-Tier";
}

/// <summary>
/// The host-local secret a trusted relay proves itself with, and where every surface on a host finds
/// it. The value authenticates the <em>relay</em>, never a person: the identity and authority a relay
/// forwards are always the asking person's, carried in <see cref="KgsmRelayHeaders"/>.
/// </summary>
/// <remarks>
/// <para><b>The host mints it, not a person.</b> It is shared between processes that already run as
/// the same account on the same machine, so there is nothing for an operator to obtain, transcribe or
/// keep in step across three files. The first surface to look for it creates it; the rest read what
/// it wrote. Creation is <c>O_CREAT|O_EXCL</c>, so two services starting at once cannot mint two
/// different secrets — the loser reads the winner's.</para>
/// <para><b>Fail-closed.</b> Any failure to read or create yields an empty secret, which every
/// consumer already treats as "the relay path is off" rather than as "no secret required".</para>
/// </remarks>
public static class KgsmRelaySecret
{
    /// <summary>
    /// The file the host's relay secret lives in. In the shared KGSM state tree rather than one
    /// surface's own directory, because no single surface owns it: the assistant checks it, and the
    /// Control Panel API and the Discord bot present it.
    /// </summary>
    /// <remarks>
    /// Beside the account store rather than one level up, for the reason the account store is a
    /// directory: <c>/var/lib/kgsm</c> itself is root-owned on a host provisioned from a checkout, so
    /// a service account can read it and create nothing in it. <c>auth/</c> is owned by that account
    /// on every host — a package's tmpfiles declares it, a deploy script creates it — which makes it
    /// the one place in the shared tree these surfaces can actually mint into.
    /// </remarks>
    public const string DefaultPath = "/var/lib/kgsm/auth/relay-secret";

    /// <summary>
    /// The secret this host's relays use: <paramref name="configured"/> when a host pinned one
    /// deliberately, otherwise the file's contents, minting it if it is not there yet. Returns an
    /// empty string when the secret can be neither read nor created — the relay path stays off.
    /// </summary>
    public static string Resolve(string? configured, string? path = null)
    {
        if (!string.IsNullOrWhiteSpace(configured))
            return configured.Trim();

        string file = string.IsNullOrWhiteSpace(path) ? DefaultPath : path.Trim();

        // Read before minting: on every start after the first this is the whole of it.
        if (TryRead(file, out string existing))
            return existing;

        return TryMint(file, out string minted) ? minted : "";
    }

    private static bool TryRead(string file, out string secret)
    {
        secret = "";
        try
        {
            if (!File.Exists(file))
                return false;
            string value = File.ReadAllText(file).Trim();
            if (value.Length == 0)
                return false;
            secret = value;
            return true;
        }
        catch
        {
            // Unreadable is not empty: the caller falls through to minting, which fails the same way
            // and lands on the fail-closed empty secret.
            return false;
        }
    }

    private static bool TryMint(string file, out string secret)
    {
        secret = "";
        string value = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

        try
        {
            string? dir = Path.GetDirectoryName(file);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            // Exclusive create is what makes concurrent starts safe: exactly one process writes.
            // The mode is set AT creation rather than after it: a chmod on the following line leaves
            // a window in which the secret is world-readable, and a secret is only ever as private as
            // its least private instant. Owner-only is the whole of it — the surfaces sharing this run
            // as the same account, and nothing else on the host has any business presenting it.
            // CA1416 flags UnixCreateMode as unsupported on Windows. Every KGSM host is Linux — the
            // path above is a Linux one and each surface sharing this secret is a systemd unit — so
            // the platform the analyzer is guarding against is not one this ever runs on.
#pragma warning disable CA1416
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            };
#pragma warning restore CA1416

            using (var writer = new StreamWriter(new FileStream(file, options)))
            {
                writer.Write(value);
            }

            secret = value;
            return true;
        }
        catch (IOException)
        {
            // Lost the create race — the winner's secret is the host's.
            return TryRead(file, out secret);
        }
        catch
        {
            return false;
        }
    }
}
