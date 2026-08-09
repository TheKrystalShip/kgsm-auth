namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// One OAuth application, at one identity provider.
/// <para>
/// It carries the application and nothing else. What a person may do is the account store's answer
/// (<c>TheKrystalShip.KGSM.Auth.Users</c>), so a login proves one fact — that the caller holds a
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
    /// Whether this host is wired to the provider at all. An unwired provider is not an error and not
    /// a failure to report later — a surface simply does not offer it.
    /// </summary>
    public bool Configured =>
        !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}

/// <summary>
/// The identity providers a KGSM host can sign people in through, bound from the <c>KgsmAuth</c>
/// configuration section. The library owns the section name and the property names, so every surface
/// binds the <em>same</em> keys by construction rather than by convention — which is what lets one
/// file point a whole host at the same set of applications.
/// <para>
/// Keyed by provider name (<see cref="KgsmActorProvider"/>), so adding a provider to a host is a pair
/// of environment keys and no code anywhere: <c>KgsmAuth__Providers__github__ClientId</c>. Nothing
/// above this type names a provider.
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

    /// <summary>
    /// The applications this host holds, by provider name.
    /// <para>
    /// Case-insensitive, because the key arrives from an environment variable and a provider name is
    /// also a route value and a credential handle prefix — three places a person writes it, and the
    /// answer must not depend on which one they capitalised.
    /// </para>
    /// </summary>
    public Dictionary<string, KgsmOAuthApplication> Providers { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The application for <paramref name="provider"/>, or an empty one when this host holds none.
    /// <para>
    /// Never null: a provider nobody wired up and a provider nobody has heard of are one answer, so a
    /// caller asks <see cref="KgsmOAuthApplication.Configured"/> and needs no separate existence
    /// check. "This host does not offer that" is one fact whichever way it came about.
    /// </para>
    /// </summary>
    public KgsmOAuthApplication For(string provider) =>
        Providers.TryGetValue(provider, out KgsmOAuthApplication? application)
            ? application
            : new KgsmOAuthApplication();

    /// <summary>The providers this host is wired to, in the order a configuration binder produced them.</summary>
    public IReadOnlyList<string> ConfiguredProviders() =>
        [.. Providers.Where(p => p.Value.Configured).Select(p => p.Key)];
}
