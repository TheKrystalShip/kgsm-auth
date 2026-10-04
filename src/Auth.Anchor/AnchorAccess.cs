using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Users;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>The anchor's answer to one of its own actions: allowed, refused, or allowed once the person proves themselves again.</summary>
/// <param name="Decision">The evaluator's answer.</param>
/// <param name="ReauthRequired">
/// Allowed by the evaluator, and an <c>auth:*</c> action whose session has not proved a credential within
/// the re-authentication window. Answered with <c>reauth_required</c>, so the page sends the person to
/// prove one and brings them back.
/// </param>
internal readonly record struct AnchorAccessResult(AccessDecision Decision, bool ReauthRequired)
{
    public bool Allowed => Decision.Allowed && !ReauthRequired;
}

/// <summary>
/// Decides the anchor's own actions for a signed-in person: the evaluator first, then, for every
/// <c>auth:*</c> action, a recent sign-in.
/// </summary>
/// <remarks>
/// <para>
/// <b>The anchor serves every <c>auth:*</c> action itself and reads its own session registry</b>, so no
/// token carries when somebody last proved a credential. The window is the one changing one's own
/// sign-in methods already requires.
/// </para>
/// <para>
/// The evaluator is asked first. A person who may not do something is told so, not sent to type their
/// password for an action that would be refused anyway.
/// </para>
/// </remarks>
internal sealed class AnchorAccess(
    AnchorAuthority authority,
    SqliteSessionRegistry sessions,
    AnchorOptions options,
    TimeProvider clock)
{
    /// <summary>Whether <paramref name="accountId"/>, holding session <paramref name="sessionId"/>, may perform <paramref name="action"/> at <paramref name="target"/>.</summary>
    /// <exception cref="InvalidOperationException">The store holds no authority.</exception>
    public async Task<AnchorAccessResult> AllowsAsync(
        string accountId, string sessionId, string action, AccessScope target, CancellationToken ct = default)
    {
        AuthoritySource source = authority.Source
            ?? throw new InvalidOperationException(authority.UnavailableReason ?? "The account store holds no authority.");

        AccessEvaluator evaluator = new(await source.CurrentAsync(ct).ConfigureAwait(false), clock);
        AccessDecision decision = evaluator.Allows(accountId, action, target);
        if (!decision.Allowed || !ActionIds.IsAuth(action))
            return new AnchorAccessResult(decision, ReauthRequired: false);

        DateTimeOffset? proved = await sessions.CredentialAtAsync(sessionId, ct).ConfigureAwait(false);
        bool recent = proved is { } at && clock.GetUtcNow() - at <= options.ReauthWindow;
        return new AnchorAccessResult(decision, ReauthRequired: !recent);
    }
}
