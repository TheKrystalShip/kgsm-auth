using TheKrystalShip.KGSM.ComponentConfig;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The anchor's configurable surface, shaped 1:1 with the <c>"Anchor"</c> section of
/// <c>kgsm-auth-anchor.settings.json</c>. That file is the floor: every knob is declared there with
/// its default, and an environment variable may only override a key that exists in it
/// (<c>Anchor__ListenAddress</c>, <c>Anchor__ClusterId</c>). A variable naming a key this class does
/// not declare sets nothing.
/// </summary>
/// <remarks>
/// This type holds what was <em>written</em>, not what the daemon runs on. <see cref="AnchorOptions"/>
/// is the validated form, so the raw configuration and the runtime view stay separable.
/// <para>
/// Every number is <b>nullable</b>, and null means "not written" — the coded default in
/// <see cref="AnchorOptions"/> applies. Two binder behaviours make that load-bearing: a blank value
/// (<c>Anchor__AccessLifetimeMinutes=</c>, one stray line in an env file) binds to a non-nullable
/// <see cref="int"/> by throwing, taking the daemon down at startup; and a JSON null binds to
/// <c>0</c>, silently discarding a property initializer's default. Nullable turns both into "unset",
/// while a value that is present and is not a number still fails loudly.
/// </para>
/// </remarks>
[ConfigSection(Section)]
internal sealed class AnchorSettings
{
    /// <summary>The configuration section this binds from.</summary>
    public const string Section = "Anchor";

    /// <summary>
    /// The lowest value each lifetime may take. Declared once and read by both
    /// <see cref="AnchorOptions.FromSettings"/>, which raises anything lower, and the config
    /// descriptor, which is what the Control Panel rejects against — so the panel can never accept a
    /// value the daemon would silently move.
    /// </summary>
    public static class Floors
    {
        /// <summary>A one-minute access token is already short enough to be a refresh loop.</summary>
        public const int AccessLifetimeMinutes = 1;

        /// <summary>A session shorter than a day is a sign-in prompt, not a session.</summary>
        public const int RefreshLifetimeDays = 1;

        /// <summary>A sweep faster than a minute is a busy loop over rows nothing is reading.</summary>
        public const int SessionCleanupMinutes = 1;
    }

    /// <summary>
    /// Where the browser is sent back to after signing in with a provider. Blank answers the callback
    /// as JSON instead, which is what a client that is not a browser wants.
    /// </summary>
    /// <panel>The Control Panel address a person lands back on after signing in with an external
    /// account. Blank means the sign-in answers with the session directly instead of sending a
    /// browser anywhere.</panel>
    [ConfigField("frontendUrl", "Panel address", Group = "network", Risk = ConfigRisk.Wiring)]
    public string? FrontendUrl { get; set; }

    /// <summary>Whether somebody with no account may make one.</summary>
    /// <panel>Whether a person with no account can create one from the sign-in page. The account they
    /// get holds nothing until an administrator grants it something, and the limit below bounds how
    /// many can be waiting at once.</panel>
    [ConfigField("allowSelfRegistration", "Let people register", Group = "sessions", Risk = ConfigRisk.Wiring)]
    public bool? AllowSelfRegistration { get; set; }

    /// <summary>How many accounts may be awaiting approval at once.</summary>
    /// <panel>How many accounts that arrived on their own may be waiting for approval at one time.
    /// Signing in with an external account nobody has approved creates one, so this bounds what a
    /// stranger can fill up.</panel>
    [ConfigField("pendingCap", "Unapproved account limit", Group = "sessions", Risk = ConfigRisk.Safe,
        Min = 0)]
    public int? PendingCap { get; set; }

    /// <summary>How long an unapproved account survives before it is removed.</summary>
    /// <panel>How long an account that arrived on its own and was never approved is kept before it is
    /// removed. It only ever removes an account nobody granted anything to.</panel>
    [ConfigField("pendingTtlDays", "Unapproved account lifetime", Group = "sessions",
        Risk = ConfigRisk.Safe, Min = 1, Unit = "days")]
    public int? PendingTtlDays { get; set; }

    /// <summary>How long a proved credential lets somebody keep changing what proves their account.</summary>
    /// <panel>How long after proving your password you may keep attaching or detaching sign-in
    /// methods. Holding a session is not the same as having proved you own it, and attaching an
    /// identity outlives the session — afterwards whoever holds that account can sign in as yours.</panel>
    [ConfigField("reauthWindowMinutes", "Re-authentication window", Group = "sessions",
        Risk = ConfigRisk.Safe, Min = 1, Unit = "minutes")]
    public int? ReauthWindowMinutes { get; set; }

    /// <summary>Where Kestrel listens. TCP, because a browser signs in here directly.</summary>
    /// <panel>The address a person's browser reaches this anchor at. Sign-in happens here directly,
    /// once, for the whole cluster.</panel>
    [ConfigField("listenAddress", "Listen address", Group = "network", Risk = ConfigRisk.Wiring)]
    public string ListenAddress { get; set; } = "http://0.0.0.0:8098";

    /// <summary>
    /// This anchor's identity as a cluster member. Blank derives one from the machine name.
    /// </summary>
    /// <panel>The name other members of the cluster know this anchor by. A machine can run more than
    /// one member — a node and an anchor are two members with two names — so this is not the machine's
    /// name. Blank derives one from it.</panel>
    [ConfigField("memberId", "Cluster member id", Group = "network", Risk = ConfigRisk.Wiring,
        NoDefault = true)]
    public string MemberId { get; set; } = "";

    /// <summary>
    /// The address other members reach this anchor at, when it has one a person can state. Blank
    /// leaves it to the addresses the join exchange reflects back.
    /// </summary>
    /// <panel>The address other members of the cluster reach this anchor at. Set it when this machine
    /// sits behind a reverse proxy and cannot see its own public address; otherwise leave it blank and
    /// the addresses are learned when a member joins.</panel>
    [ConfigField("publicBaseUrl", "Public address", Group = "network", Risk = ConfigRisk.Wiring)]
    public string PublicBaseUrl { get; set; } = "";

    /// <summary>
    /// Where this anchor is reached from the internet, for the cluster's DNS anchor to point the
    /// capability's name at.
    /// </summary>
    /// <panel>Where this machine is reached from the internet — normally the dynamic-DNS name its network
    /// keeps pointed at a changing home address, such as example.ddns.net. In a cluster with a DNS anchor,
    /// the accounts capability's name points at it while this anchor holds it, and this anchor serves that
    /// name on a certificate the DNS anchor issues. A fixed public address works too. Empty means the name
    /// is not published.</panel>
    [ConfigField("publicHost", "Public host", Group = "network", Risk = ConfigRisk.Wiring, NoDefault = true)]
    public string PublicHost { get; set; } = "";

    /// <summary>The cluster a session is scoped to, and the token audience.</summary>
    /// <panel>The cluster this anchor holds the accounts for. A session it mints is valid on every
    /// member of this cluster and on nothing else. Changing it signs everybody out.</panel>
    [ConfigField("clusterId", "Cluster id", Group = "network", Risk = ConfigRisk.Destructive)]
    public string ClusterId { get; set; } = "kgsm-cluster";

    /// <summary>The <c>iss</c> claim, and what validation requires.</summary>
    /// <panel>The issuer name stamped on every session. It is checked when a session is presented, so
    /// changing it signs everybody out.</panel>
    [ConfigField("issuer", "Token issuer", Group = "network", Risk = ConfigRisk.Destructive)]
    public string Issuer { get; set; } = "kgsm";

    /// <summary>The account store this anchor is the writer of.</summary>
    /// <panel>The file the accounts live in. It is the same file every other KGSM surface on this
    /// machine reads.</panel>
    [ConfigField("userStorePath", "Account store", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Destructive)]
    public string UserStorePath { get; set; } = "/var/lib/kgsm/auth/users.db";

    /// <summary>Where live sessions are recorded.</summary>
    /// <panel>Where live sign-ins are recorded, so a sign-out outlives the process that issued the
    /// session and a restart does not sign everybody out.</panel>
    [ConfigField("sessionStorePath", "Session store", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Destructive)]
    public string SessionStorePath { get; set; } = "/var/lib/kgsm-auth-anchor/sessions.db";

    /// <summary>The private key sessions are signed with.</summary>
    /// <panel>The private key every session is signed with. It is generated on first start and never
    /// leaves this machine. Replacing it invalidates every session that exists.</panel>
    [ConfigField("signingKeyPath", "Session signing key", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Destructive)]
    public string SigningKeyPath { get; set; } = "/var/lib/kgsm-auth-anchor/session-signing.pem";

    /// <summary>Where the public half is written for members on this machine.</summary>
    /// <panel>Where the public half of the signing key is published, for other members on this machine
    /// to verify sessions against. Blank publishes no file; the key is still served over HTTP.</panel>
    [ConfigField("publishedKeyPath", "Published public key", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Wiring)]
    public string PublishedKeyPath { get; set; } = "/var/lib/kgsm/cluster/auth-public-key.json";

    /// <summary>The descriptor this anchor serves its own configuration surface from.</summary>
    /// <panel>The file describing what this anchor can be configured with, written by its own build
    /// and installed by its deploy. It is read to render this page; absent, there is no page.</panel>
    [ConfigField("configDescriptorPath", "Config descriptor", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Wiring)]
    public string ConfigDescriptorPath { get; set; } = "/var/lib/kgsm/anchors/auth-anchor.json";

    /// <summary>Where changes made through the Control Panel are written.</summary>
    /// <panel>Where a change made on this page is written. A systemd drop-in feeds the file back to
    /// this daemon, so it wins over everything the deploy set. Deleting it returns every knob to
    /// what the deploy set, which is how this anchor is recovered if a change stops it starting.</panel>
    [ConfigField("configOverridePath", "Config overrides", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Destructive)]
    public string ConfigOverridePath { get; set; } = "/var/lib/kgsm-auth-anchor/config-override.env";

    /// <summary>Access-token lifetime in minutes. Raised to <see cref="Floors.AccessLifetimeMinutes"/> if lower.</summary>
    /// <panel>How long a session's bearer lasts before it is refreshed. Short bounds how long a stolen
    /// one is worth anything; it does not affect how long somebody stays signed in.</panel>
    [ConfigField("accessLifetimeMin", "Access token lifetime", Group = "sessions",
        Min = Floors.AccessLifetimeMinutes, Unit = "min")]
    public int? AccessLifetimeMinutes { get; set; }

    /// <summary>The absolute session cap in days. Raised to <see cref="Floors.RefreshLifetimeDays"/> if lower.</summary>
    /// <panel>How long somebody stays signed in before a fresh sign-in is required.</panel>
    [ConfigField("refreshLifetimeDays", "Session lifetime", Group = "sessions",
        Min = Floors.RefreshLifetimeDays, Unit = "days")]
    public int? RefreshLifetimeDays { get; set; }

    /// <summary>Browser origins allowed to call this anchor, comma-separated.</summary>
    /// <panel>The browser origins allowed to sign in against this anchor, comma-separated. The Control
    /// Panel is served from a different origin, so without an entry for it the browser refuses the
    /// response before this daemon's answer is read.</panel>
    [ConfigField("allowedOrigins", "Allowed browser origins", Group = "network", Type = ConfigType.Csv,
        Risk = ConfigRisk.Wiring)]
    public string AllowedOrigins { get; set; } = "";

    /// <summary>Sweep cadence for expired session rows. Raised to <see cref="Floors.SessionCleanupMinutes"/> if lower.</summary>
    /// <panel>How often session rows that are already past their cap are deleted. Housekeeping — it
    /// ends no session that is still alive.</panel>
    [ConfigField("sessionCleanupMin", "Session sweep interval", Group = "sessions",
        Min = Floors.SessionCleanupMinutes, Unit = "min")]
    public int? SessionCleanupMinutes { get; set; }
}
