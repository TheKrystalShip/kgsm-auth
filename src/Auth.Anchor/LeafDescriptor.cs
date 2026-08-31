using TheKrystalShip.KGSM.ComponentConfig;

// What this daemon can be configured with, declared beside the configuration it describes. The
// generator reads this out of the built assembly and writes deploy/kgsm-auth-anchor.anchor.json;
// deploy.sh installs that into /var/lib/kgsm/anchors/auth-anchor.json. The daemon itself never reads
// any of this.

// An anchor, not a leaf. This daemon serves one capability to the whole cluster and is a PEER of
// every node in it — sharing a machine with one is a deployment coincidence, and the ordinary
// topology puts it on its own. So it is described in /var/lib/kgsm/anchors/ rather than where a
// node's leaves are scanned for, and the Control Panel reaches it as the member it is: the anchor's
// own page, off the cluster's Anchors card.
[assembly: Anchor(
    id: "auth-anchor",
    displayName: "Auth anchor",
    unit: "kgsm-auth-anchor.service",
    role: "Holds the cluster's accounts, and is the one place a person signs in to reach every member of it.")]

// Panel sections, in the order they render. Fields land in one by naming its id, and follow the
// order they are declared in AnchorSettings.
[assembly: ConfigGroup("network", "Network", 1)]
[assembly: ConfigGroup("storage", "Storage", 2)]
[assembly: ConfigGroup("sessions", "Sessions", 3)]
[assembly: ConfigGroup("general", "General", 4)]

// Where this daemon's own configuration comes from, lowest precedence first — the same order
// Program.cs resolves them in. The settings file is the base the other two override one key of.
[assembly: ConfigFloorSource("appsettings", "/opt/kgsm-auth-anchor/kgsm-auth-anchor.settings.json")]
[assembly: ConfigFloorSource("systemd-unit", "kgsm-auth-anchor.service")]
[assembly: ConfigFloorSource("env-file", "/etc/kgsm-auth-anchor/kgsm-auth-anchor.env")]

// Per-category log filtering can name any category there is, so the namespace cannot be enumerated.
// Every other key in the settings file has to be described or the build fails.
[assembly: ConfigFrameworkNamespace("Logging__",
    "per-category filtering is open-ended: any category name is a valid key")]

// The ecosystem logging level. It has no AnchorSettings property because
// Microsoft.Extensions.Logging owns it, so it is the one key nothing in this daemon's own types can
// be read to discover.
[assembly: ConfigFrameworkField("logLevel", "Logging__LogLevel__Default", "Log level",
    Description = "Minimum severity this anchor logs.",
    Group = "general",
    Type = ConfigType.Enum,
    Values = ["Trace", "Debug", "Information", "Warning", "Error", "Critical"])]
