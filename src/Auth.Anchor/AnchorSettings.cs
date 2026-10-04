using TheKrystalShip.KGSM.ComponentConfig;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// The anchor's configurable surface, shaped 1:1 with the <c>"Anchor"</c> section of
/// <c>tks-auth.settings.json</c>. That file is the floor: every knob is declared there with
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

        /// <summary>A heartbeat more often than this is a message per member for nothing new.</summary>
        public const int AuthorityHeartbeatSeconds = 10;

        /// <summary>A bound shorter than a minute turns one late heartbeat into a read-only cluster.</summary>
        public const int StalenessBoundSeconds = 60;
    }

    /// <summary>Whether somebody with no account may make one.</summary>
    /// <panel>Whether a person with no account can create one from the sign-in page. The account they
    /// get holds nothing until somebody grants it something, and the limit below bounds how
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

    /// <summary>How often every member is told the authority's current version.</summary>
    /// <panel>How often this anchor tells every member which version of roles and permissions is
    /// current. Each one it applies keeps that member able to do more than read.</panel>
    [ConfigField("authorityHeartbeatSeconds", "Access heartbeat", Group = "access", Risk = ConfigRisk.Safe,
        Min = Floors.AuthorityHeartbeatSeconds, Unit = "seconds")]
    public int? AuthorityHeartbeatSeconds { get; set; }

    /// <summary>How long a member stays current without hearing the heartbeat.</summary>
    /// <panel>How long a member keeps serving changes after it last heard from this anchor. Past it, the
    /// member serves reads only — to everyone, owners included — until it hears again, so a member cut
    /// off from this anchor never acts on roles that may since have been taken away.</panel>
    [ConfigField("stalenessBoundSeconds", "Staleness bound", Group = "access", Risk = ConfigRisk.Safe,
        Min = Floors.StalenessBoundSeconds, Unit = "seconds")]
    public int? StalenessBoundSeconds { get; set; }

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
    /// The address browsers and other members reach this anchor at, and the origin its provider callbacks
    /// are built on. Blank uses the accounts capability's name while this anchor serves it, in a cluster
    /// with a DNS anchor.
    /// </summary>
    /// <panel>The address people and other members of the cluster reach this anchor at, and where a
    /// sign-in provider sends people back to. In a cluster with a DNS anchor leave it blank: the accounts
    /// capability's own name is used. Set it only for an anchor with no DNS anchor to name it.</panel>
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

    /// <summary>
    /// The <c>iss</c> claim, and what validation requires. The OpenID Connect doors are served only when
    /// it is the provider's browser-facing URL, which they are served under.
    /// </summary>
    /// <panel>The address this anchor signs people in at, stamped on every session as its issuer, such as
    /// https://auth.anchors.example.com. Sign-in for every surface of the cluster is served only when this
    /// is a URL. It is checked when a session is presented, so changing it signs everybody out.</panel>
    [ConfigField("issuer", "Token issuer", Group = "network", Risk = ConfigRisk.Destructive)]
    public string Issuer { get; set; } = "kgsm";

    /// <summary>The account store this anchor is the writer of.</summary>
    /// <panel>The file the cluster's accounts and access live in — this anchor's alone. Every other
    /// member, this machine's node included, holds a replica in a file of its own.</panel>
    [ConfigField("userStorePath", "Account store", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Destructive)]
    public string UserStorePath { get; set; } = "/var/lib/tks-auth/accounts.db";

    /// <summary>Where live sessions are recorded.</summary>
    /// <panel>Where live sign-ins are recorded, so a sign-out outlives the process that issued the
    /// session and a restart does not sign everybody out.</panel>
    [ConfigField("sessionStorePath", "Session store", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Destructive)]
    public string SessionStorePath { get; set; } = "/var/lib/tks-auth/sessions.db";

    /// <summary>The private key sessions are signed with.</summary>
    /// <panel>The private key every session is signed with. It is generated on first start and never
    /// leaves this machine. Replacing it invalidates every session that exists.</panel>
    [ConfigField("signingKeyPath", "Session signing key", Group = "storage", Type = ConfigType.Path,
        Risk = ConfigRisk.Destructive)]
    public string SigningKeyPath { get; set; } = "/var/lib/tks-auth/session-signing.pem";

    /// <summary>
    /// Where the provider's pages are installed: the <c>kgsm-web-auth</c> bundle, served at <c>/ui/</c>.
    /// </summary>
    /// <panel>The folder holding the sign-in, approval and account pages. Absent, people still sign in
    /// through a plain form, and registration and the account page are unavailable.</panel>
    [ConfigField("uiPath", "Sign-in pages", Group = "storage", Type = ConfigType.Path, Risk = ConfigRisk.Wiring)]
    public string UiPath { get; set; } = "/usr/share/kgsm-web-auth";

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
    public string ConfigOverridePath { get; set; } = "/var/lib/tks-auth/config-override.env";

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

    /// <summary>Origins a Control Panel is served from with no member behind it, comma-separated.</summary>
    /// <panel>Where a Control Panel is served from a plain web server rather than by a node — a static
    /// host, one origin each, comma-separated. Each becomes a client of this sign-in: people are sent
    /// back to it after signing in. A panel a node serves needs no entry here; the node announces it.</panel>
    [ConfigField("panelOrigins", "Panels on static hosts", Group = "network", Type = ConfigType.Csv,
        Risk = ConfigRisk.Wiring)]
    public string PanelOrigins { get; set; } = "";

    /// <summary>Sweep cadence for expired session rows. Raised to <see cref="Floors.SessionCleanupMinutes"/> if lower.</summary>
    /// <panel>How often session rows that are already past their cap are deleted. Housekeeping — it
    /// ends no session that is still alive.</panel>
    [ConfigField("sessionCleanupMin", "Session sweep interval", Group = "sessions",
        Min = Floors.SessionCleanupMinutes, Unit = "min")]
    public int? SessionCleanupMinutes { get; set; }
}
