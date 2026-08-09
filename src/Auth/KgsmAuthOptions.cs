namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// The Discord application a KGSM surface signs people in through, bound from the <c>KgsmAuth</c>
/// configuration section. The library owns the section name and the property names, so every surface
/// binds the <em>same</em> keys by construction rather than by convention — which is what lets one
/// file point a whole host at one application.
/// <para>
/// It carries the application and nothing else. What a person may do is the account store's answer
/// (<c>TheKrystalShip.KGSM.Auth.Users</c>), so a login proves one fact — that the caller holds this
/// subject at Discord — and contributes nothing to their authority.
/// </para>
/// <para>
/// A plain POCO with no framework attributes: any host binds it however it already binds
/// configuration, and the package itself takes no dependency to make that work.
/// </para>
/// </summary>
public sealed class KgsmAuthOptions
{
    /// <summary>The configuration section these bind from.</summary>
    public const string Section = "KgsmAuth";

    /// <summary>The Discord application users sign in through — the same application as the host's bot.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>The application's OAuth secret. Set in the environment, never in a settings file.</summary>
    public string ClientSecret { get; set; } = string.Empty;
}
