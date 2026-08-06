namespace TheKrystalShip.KGSM.Auth;

/// <summary>
/// The identity-provider prefix in an actor string. An actor is written <c>provider:name</c> — the
/// form the engine stamps on an event, the audit log parses back into a structured actor, and the
/// conversation corpus keys a conversation's owner by.
/// </summary>
public static class KgsmActorProvider
{
    /// <summary>A Discord identity, whether it arrived through a login, a gateway, or a relay.</summary>
    public const string Discord = "discord";

    /// <summary>A caller with no external identity — a local CLI run on the host itself.</summary>
    public const string Local = "local";

    /// <summary>The host's own scheduled or supervisory action, with no human behind it.</summary>
    public const string System = "system";
}

/// <summary>
/// Builds and reads the <c>provider:name</c> actor string. Keeping the format in one place is what
/// lets an action taken in Discord and the same action taken in the Control Panel land in the audit
/// log as the same person.
/// </summary>
public static class KgsmActor
{
    /// <summary>
    /// <c>discord:&lt;name&gt;</c> for a Discord identity, preferring the human-readable handle and
    /// falling back to the user id when there is no handle to use.
    /// </summary>
    public static string Discord(string? username, string userId) =>
        Format(KgsmActorProvider.Discord, string.IsNullOrWhiteSpace(username) ? userId : username);

    /// <summary>An actor string for an arbitrary provider.</summary>
    public static string Format(string provider, string name) => $"{provider}:{name}";

    /// <summary>
    /// Splits an actor string into its provider and name. Returns <see langword="false"/> for anything
    /// that is not <c>provider:name</c> with both halves present — the caller then treats the actor as
    /// unknown rather than inventing one. A name may itself contain <c>:</c>; only the first separates.
    /// </summary>
    public static bool TryParse(string? actor, out string provider, out string name)
    {
        provider = string.Empty;
        name = string.Empty;

        if (string.IsNullOrWhiteSpace(actor))
            return false;

        int separator = actor.IndexOf(':');
        if (separator <= 0 || separator == actor.Length - 1)
            return false;

        provider = actor[..separator];
        name = actor[(separator + 1)..];
        return true;
    }
}
