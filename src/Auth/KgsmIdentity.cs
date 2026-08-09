namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// A person, as an identity provider verified them at login. The provider is named alongside the
/// subject because a subject is only unique <em>within</em> its provider — two providers can hand out
/// the same string for two different people, so neither half identifies anyone on its own.
/// </summary>
/// <remarks>
/// The profile fields are a snapshot taken at login, not a live read: no KGSM surface retains a
/// provider's access token, so there is nothing to re-fetch with. A display name that changed at the
/// provider after login stays stale until the next one, which is the honest consequence of not
/// holding a token and is preferable to holding one.
/// </remarks>
/// <param name="Provider">Which identity provider verified this person — a <see cref="KgsmActorProvider"/> value.</param>
/// <param name="Subject">That provider's own stable id for them. Opaque here; never parsed.</param>
/// <param name="Username">The provider's handle, for display and for the audit actor.</param>
/// <param name="Display">The provider's display name. For rendering only, never authority.</param>
/// <param name="AvatarUrl">A picture, when the provider gave one.</param>
/// <param name="Scopes">What the login was granted, as the provider reported it.</param>
public sealed record KgsmIdentity(
    string Provider,
    string Subject,
    string Username,
    string Display,
    string? AvatarUrl,
    IReadOnlyList<string> Scopes)
{
    /// <summary>
    /// The provider-qualified handle, <c>provider:subject</c> — the one string that names this person
    /// across the ecosystem. It is what a session token carries as its subject and what a session row
    /// is keyed by, so those never have to reconstruct it from two fields and never disagree about
    /// the format.
    /// </summary>
    public string Handle => KgsmActor.Format(Provider, Subject);

    /// <summary>
    /// The audit actor string, <c>provider:username</c> — the human-readable handle, falling back to
    /// the subject when the provider gave no username. Deliberately not <see cref="Handle"/>: an audit
    /// log is read by people, and an opaque subject tells them nothing about who acted.
    /// </summary>
    public string ActorString =>
        KgsmActor.Format(Provider, string.IsNullOrWhiteSpace(Username) ? Subject : Username);
}

/// <summary>
/// The outcome of a login: the verified identity plus the tier this host grants it.
/// <see cref="KgsmTier.None"/> means "we know who you are, and you have no access here" — a terminal
/// denial, distinct from a failure to find out.
/// </summary>
public sealed record ResolvedPrincipal(KgsmIdentity Identity, KgsmTier Tier);
