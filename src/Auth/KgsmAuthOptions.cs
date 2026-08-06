namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// The Discord identity block every KGSM surface authorizes against, bound from the <c>KgsmAuth</c>
/// configuration section. The library owns the section name and the property names, so the API, the
/// assistant and the bot bind the <em>same</em> keys by construction rather than by convention —
/// which is what lets one file configure all of them and keeps a host from granting different
/// authority depending on which surface a person reaches it through.
/// <para>
/// A plain POCO with no framework attributes: any host binds it however it already binds
/// configuration, and the package itself takes no dependency to make that work.
/// </para>
/// </summary>
public sealed class KgsmAuthOptions
{
    /// <summary>The configuration section these bind from.</summary>
    public const string Section = "KgsmAuth";

    /// <summary>The Discord guild whose membership and roles authorize this host.</summary>
    public string GuildId { get; set; } = string.Empty;

    /// <summary>The Discord application users sign in through — the same application as the host's bot.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>The application's OAuth secret. Set in the environment, never in a settings file.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// The bot token roles are read with (<c>GET /guilds/{guild}/members/{user}</c>). This is the only
    /// path to a caller's roles — the <c>identify guilds</c> user scopes do not carry them — so a
    /// surface that resolves authority needs it even when it runs no bot of its own. Set in the
    /// environment, never in a settings file.
    /// </summary>
    public string BotToken { get; set; } = string.Empty;

    /// <summary>Comma-separated Discord role ids granting <see cref="KgsmTier.Admin"/>.</summary>
    public string RoleAdminIds { get; set; } = string.Empty;

    /// <summary>Comma-separated Discord role ids granting <see cref="KgsmTier.Operator"/>.</summary>
    public string RoleOperatorIds { get; set; } = string.Empty;

    /// <summary>
    /// The role map these options describe. There is no viewer role list: guild membership is the gate
    /// and a member floors at <see cref="KgsmTier.Viewer"/>, so a list of ids granting viewer would
    /// grant what everyone already has.
    /// </summary>
    public KgsmRoleMap ToRoleMap() => new(Split(RoleAdminIds), Split(RoleOperatorIds));

    /// <summary>
    /// Whether enough is configured to resolve a caller's tier at all — a guild to look them up in and
    /// a bot token to look them up with. A surface that also runs the OAuth login needs
    /// <see cref="ClientId"/> and <see cref="ClientSecret"/> on top; a gateway client that already
    /// holds the member object needs neither.
    /// </summary>
    public bool CanResolveRoles =>
        !string.IsNullOrWhiteSpace(GuildId) && !string.IsNullOrWhiteSpace(BotToken);

    private static IEnumerable<string> Split(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
