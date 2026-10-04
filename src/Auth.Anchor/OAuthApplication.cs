namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// One OAuth application, at one identity provider.
/// <para>
/// It carries the application and nothing else. What a person may do is the account store's answer
/// (<c>TheKrystalShip.Auth.Users</c>), so a login proves one fact — that the caller holds a
/// subject at this provider — and contributes nothing to their authority. That is what lets a
/// provider be wired up with no authority story of its own.
/// </para>
/// </summary>
public sealed class KgsmOAuthApplication
{
    /// <summary>The application users sign in through.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>The application's OAuth secret. Set in the environment, never in a settings file.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Whether this anchor is wired to the provider at all. An unwired provider is not an error and not
    /// a failure to report later — the sign-in page simply does not offer it.
    /// </summary>
    public bool Configured =>
        !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}
