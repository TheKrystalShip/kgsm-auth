using TheKrystalShip.KGSM.LeafConfig;

// What the Control Panel shows about this daemon, declared beside the configuration it describes.
// The generator reads this out of the built assembly and writes deploy/kgsm-auth-anchor.leaf.json;
// deploy.sh installs that into /var/lib/kgsm/leaves/auth-anchor.json, where kgsm-api scans for it.
// The daemon itself never reads any of this.

[assembly: Leaf(
    id: "auth-anchor",
    displayName: "Auth anchor",
    unit: "kgsm-auth-anchor.service",
    role: "Holds the cluster's accounts, and is the one place a person signs in to reach every member of it.")]

// Panel sections, in the order they render. Fields land in one by naming its id, and follow the
// order they are declared in AnchorSettings.
[assembly: LeafGroup("network", "Network", 1)]
[assembly: LeafGroup("storage", "Storage", 2)]
[assembly: LeafGroup("sessions", "Sessions", 3)]
[assembly: LeafGroup("general", "General", 4)]

// Where this daemon's own configuration comes from, lowest precedence first — the same order
// Program.cs resolves them in. The settings file is the base the other two override one key of.
[assembly: LeafFloorSource("appsettings", "/opt/kgsm-auth-anchor/kgsm-auth-anchor.settings.json")]
[assembly: LeafFloorSource("systemd-unit", "kgsm-auth-anchor.service")]
[assembly: LeafFloorSource("env-file", "/etc/kgsm-auth-anchor/kgsm-auth-anchor.env")]

// Per-category log filtering can name any category there is, so the namespace cannot be enumerated.
// Every other key in the settings file has to be described or the build fails.
[assembly: LeafFrameworkNamespace("Logging__",
    "per-category filtering is open-ended: any category name is a valid key")]

// The ecosystem logging level. It has no AnchorSettings property because
// Microsoft.Extensions.Logging owns it, so it is the one key nothing in this daemon's own types can
// be read to discover.
[assembly: LeafFrameworkField("logLevel", "Logging__LogLevel__Default", "Log level",
    Description = "Minimum severity this anchor logs.",
    Group = "general",
    Type = LeafType.Enum,
    Values = ["Trace", "Debug", "Information", "Warning", "Error", "Critical"])]
