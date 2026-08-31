using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Journal;
using TheKrystalShip.KGSM.Core.Interfaces;
using TheKrystalShip.KGSM.Events;
using TheKrystalShip.KGSM.Services;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Records what happened to this cluster's accounts, in this anchor's own event journal.
/// </summary>
/// <remarks>
/// <para>
/// <b>A producer records what that producer did.</b> The anchor is where a person signs in, where an
/// account is created, and where authority is granted and taken away — for the whole cluster. Nothing
/// else witnesses any of it, so nothing else can honestly say it happened. These lines are written
/// beside the engine's journal and every leaf's, and a Control Panel's audit page is the merge.
/// </para>
/// <para>
/// <b>The wire shape is not this daemon's.</b> Both the names and the payloads come from
/// <see cref="AuthEvents"/> and <see cref="AuthEventPayloads"/>, which a host holding its own accounts
/// writes too. A reader deserializes into a fixed shape and a misspelled field lands as a null rather
/// than an error, so the shape is called rather than described a second time here.
/// </para>
/// <para>
/// <b>Facts, not sentences.</b> No summary and no severity: the wording is a reader's, built at read
/// time from what is recorded, which is what lets one fact read one way in a Control Panel and another
/// in a chat surface.
/// </para>
/// <para>
/// <b>Best-effort, always.</b> Every method swallows its failure after logging it. The action has
/// already happened by the time one of these is called — a session exists, a tier is already changed —
/// so refusing it because the record could not be written would trade a missing line for a broken
/// door.
/// </para>
/// </remarks>
internal sealed class AnchorJournal(IEventJournalWriter writer, ILogger<AnchorJournal> logger)
    : JournalRecorder(writer, logger)
{
    /// <summary>
    /// This anchor's producer id — its own state directory's name.
    /// </summary>
    /// <remarks>
    /// A producer's id, its state directory and the directory it appends to are one fact spelled
    /// three ways, and a reader establishes the producer from the path it read a line out of. So this
    /// has to be the name in the unit's <c>StateDirectory=</c>: a journal written anywhere else is not
    /// reported as misplaced, it is simply never found, and looks exactly like a daemon that recorded
    /// nothing.
    /// </remarks>
    internal const string ProducerId = "kgsm-auth-anchor";

    /// <summary>
    /// This anchor attributes nothing to itself.
    /// </summary>
    /// <remarks>
    /// Every line here records something a <em>person</em> did. The call site knows who; a default of
    /// <c>system:auth-anchor</c> would put this daemon's name on somebody's sign-in. An actor that did
    /// not reach the call site is a real null, which reads as unknown rather than as the machine.
    /// </remarks>
    protected override string? DefaultActor => null;

    /// <inheritdoc cref="DefaultActor"/>
    protected override string? DefaultOrigin => null;

    /// <summary>
    /// A person at a browser.
    /// </summary>
    /// <remarks>
    /// Every door here is one somebody types a password into or is redirected through, so it is what
    /// drove all of them — there is no machine-to-machine sign-in on this surface, because a member
    /// authenticates with the cluster secret rather than an account. A reader's closed set of origins
    /// is kgsm-api's <c>AuditOrigin</c>; a spelling outside it reads as unknown rather than as this.
    /// </remarks>
    internal const string OriginUi = "ui";

    /// <summary>Record a session beginning or ending.</summary>
    /// <remarks>
    /// The actor is the identity that arrived, not this anchor: nobody else was involved in a sign-in,
    /// and naming the component that minted the token would hide who came through the door.
    /// </remarks>
    internal Task SessionAsync(
        string type, string? userId, string username, string identity, string? provider, string? tier,
        string? sid, string? userAgent, string actor, string? origin, CancellationToken ct = default) =>
        WriteAsync(
            type, actor, origin,
            AuthEventPayloads.Session(userId, username, identity, provider, tier, sid, userAgent,
                // Never set here. A vouch is one node asserting an identity to another, and an anchor
                // is the thing that makes vouching unnecessary.
                peerNode: null),
            ct);

    /// <summary>Record sessions being torn down before they expired.</summary>
    internal Task SessionRevokedAsync(
        string scope, string userId, string username, string? sid, int? count,
        string actor, string? origin, CancellationToken ct = default) =>
        WriteAsync(
            AuthEvents.SessionRevoked, actor, origin,
            AuthEventPayloads.SessionRevoked(scope, userId, username, sid, count), ct);

    /// <summary>Record a run of wrong passwords locking an account.</summary>
    /// <remarks>
    /// The actor is the account the attempts were made against, which is <em>not</em> a claim about
    /// who made them — nobody authenticated, so there is nobody to name. It is the subject, recorded
    /// so the row reads beside that account's other rows, and the reason this event exists at all.
    /// </remarks>
    internal Task LockedOutAsync(
        string userId, string username, string identity, int failedCount, DateTimeOffset until,
        string actor, CancellationToken ct = default) =>
        WriteAsync(
            AuthEvents.LockedOut, actor, origin: null,
            AuthEventPayloads.LockedOut(userId, username, identity, failedCount, until), ct);

    /// <summary>
    /// Record an account being provisioned, approved, disabled, deleted, or having its authority or
    /// password changed.
    /// </summary>
    /// <remarks>
    /// Takes no password parameter and never will. What is recorded is that a credential was set and
    /// by whom — the only signal an account takeover leaves — and the credential is not part of that
    /// fact.
    /// </remarks>
    internal Task AccountAsync(
        string type, string userId, string username, string? fromTier = null, string? toTier = null,
        string? fromStatus = null, string? toStatus = null, bool? byHolder = null,
        string actor = "", string? origin = null, CancellationToken ct = default) =>
        WriteAsync(
            type, actor, origin,
            AuthEventPayloads.Account(userId, username, fromTier, toTier, fromStatus, toStatus, byHolder),
            ct);

    /// <summary>Record an external identity being attached to or detached from an account.</summary>
    internal Task IdentityAsync(
        string type, string userId, string username, string provider, string handle,
        string actor, string? origin, CancellationToken ct = default) =>
        WriteAsync(
            type, actor, origin, AuthEventPayloads.Identity(userId, username, provider, handle), ct);

    /// <summary>Append one line, saying what was lost if it cannot.</summary>
    /// <remarks>
    /// The base logs the generic failure; this adds what the base cannot know — a line nobody will
    /// find later, for an action that did happen.
    /// </remarks>
    private async Task WriteAsync(
        string type, string actor, string? origin, Action<Utf8JsonWriter> payload, CancellationToken ct)
    {
        // Parsed at this boundary because several of these names are chosen at run time from the
        // catalog — which of the user.* events an admin's patch turned out to be. A name that is not a
        // name is dropped loudly rather than written: a line no consumer matches fails silently
        // everywhere downstream.
        if (!EventName.TryParse(type, out EventName name))
        {
            logger.LogError("'{Event}' is not a valid event name; the line was not written", type);
            return;
        }

        if (!await RecordAsync(name, payload, actor, origin, ct: ct).ConfigureAwait(false))
        {
            logger.LogWarning(
                "{Event} was not recorded — the action happened, the line did not", type);
        }
    }
}
