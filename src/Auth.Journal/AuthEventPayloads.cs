using System.Text.Json;

namespace TheKrystalShip.KGSM.Auth.Journal;

/// <summary>
/// The bytes a KGSM account event carries.
/// </summary>
/// <remarks>
/// <para>
/// <b>One implementation, because two would fail silently.</b> Two components write these — a host's
/// own API when it holds its accounts, and a cluster's auth anchor when one does — and one reads them
/// back by deserializing into a fixed shape. A field spelled differently by one writer does not throw:
/// it deserializes to null, and the row renders with a name missing and nothing reported. So the shape
/// lives here and both call it, rather than being described twice and trusted to stay agreed.
/// </para>
/// <para>
/// <b>Facts, not sentences.</b> No summary, no severity, no formatted value — those belong to a reader
/// and are built at read time. It is what lets one fact be worded one way in a Control Panel and
/// another in a chat surface, and what keeps a wording improvement from applying only to the rows
/// written after it.
/// </para>
/// <para>
/// <b>An absent value is written as a real null.</b> Never an empty string: "nobody looked this up" and
/// "this is blank" are different facts, and a reader that meets <c>""</c> cannot tell which it has.
/// </para>
/// </remarks>
public static class AuthEventPayloads
{
    /// <summary>
    /// A session beginning or ending.
    /// </summary>
    /// <param name="userId">
    /// The account's id, or null when the caller did not have the row in hand. A sign-out holds the
    /// token's identity and nothing else, and deriving an id from the handle would record a lookup
    /// that never happened.
    /// </param>
    /// <param name="username">What the account was called when this happened.</param>
    /// <param name="identity">The identity that arrived, as <c>provider:name</c>.</param>
    /// <param name="provider">The provider that vouched, or null.</param>
    /// <param name="tier">The authority the account store resolved, or null.</param>
    /// <param name="sid">The session id, so a sign-in and its sign-out pair up.</param>
    /// <param name="userAgent">The calling device, or null when it sent none.</param>
    /// <param name="peerNode">The node that vouched, on a cluster vouch only.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> Session(
        string? userId, string username, string identity, string? provider, string? tier,
        string? sid, string? userAgent, string? peerNode) =>
        w =>
        {
            Nullable(w, "UserId", userId);
            w.WriteString("Username", username ?? string.Empty);
            w.WriteString("Identity", identity ?? string.Empty);
            Nullable(w, "Provider", provider);
            Nullable(w, "Tier", tier);
            Nullable(w, "Sid", sid);
            Nullable(w, "UserAgent", userAgent);
            Nullable(w, "PeerNode", peerNode);
        };

    /// <summary>
    /// Sessions torn down before they expired.
    /// </summary>
    /// <param name="scope">How far it reached — <c>self</c>, <c>all</c> or <c>admin</c>.</param>
    /// <param name="userId">Whose sessions they were.</param>
    /// <param name="username">What that account was called.</param>
    /// <param name="sid">The single session ended, or null when it was a sweep.</param>
    /// <param name="count">How many a sweep ended, or null when one was named.</param>
    /// <returns>The payload writer.</returns>
    /// <remarks>
    /// A single revocation names the session; a sweep names how many it ended. Neither fabricates the
    /// other, which is why both are nullable and never defaulted to each other.
    /// </remarks>
    public static Action<Utf8JsonWriter> SessionRevoked(
        string scope, string userId, string username, string? sid, int? count) =>
        w =>
        {
            w.WriteString("UserId", userId ?? string.Empty);
            w.WriteString("Username", username ?? string.Empty);
            w.WriteString("Scope", scope ?? string.Empty);
            Nullable(w, "Sid", sid);

            if (count is { } n)
                w.WriteNumber("Count", n);
            else
                w.WriteNull("Count");
        };

    /// <summary>
    /// A run of wrong passwords that locked an account.
    /// </summary>
    /// <param name="userId">The account that was locked. It exists — nothing locks a wrong username.</param>
    /// <param name="username">What it was called.</param>
    /// <param name="identity">The identity the attempts were made against, as <c>provider:name</c>.</param>
    /// <param name="failedCount">How many consecutive failures the lock followed.</param>
    /// <param name="until">When the account can be tried again.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> LockedOut(
        string userId, string username, string identity, int failedCount, DateTimeOffset until) =>
        w =>
        {
            w.WriteString("UserId", userId ?? string.Empty);
            w.WriteString("Username", username ?? string.Empty);
            w.WriteString("Identity", identity ?? string.Empty);
            w.WriteNumber("FailedCount", failedCount);
            w.WriteString("Until", until.ToUniversalTime().ToString("O"));
        };

    /// <summary>
    /// An account provisioned, approved, disabled, deleted, or having its authority or password changed.
    /// </summary>
    /// <param name="userId">The account.</param>
    /// <param name="username">What it was called when this happened.</param>
    /// <param name="fromTier">The authority it held before, or null when the event did not move it.</param>
    /// <param name="toTier">The authority it holds after, or null.</param>
    /// <param name="fromStatus">The status it held before, or null.</param>
    /// <param name="toStatus">The status it holds after, or null.</param>
    /// <param name="byHolder">
    /// Whether the account's own holder did this rather than an administrator acting on them. Null when
    /// the distinction does not apply. It is the whole point of recording a password change: somebody
    /// else setting yours reads completely differently from you setting it.
    /// </param>
    /// <returns>The payload writer.</returns>
    /// <remarks>
    /// Takes no password parameter and never will. What is recorded is that a credential was set and by
    /// whom — the only signal an account takeover leaves — and the credential is not part of that fact.
    /// </remarks>
    public static Action<Utf8JsonWriter> Account(
        string userId, string username, string? fromTier, string? toTier,
        string? fromStatus, string? toStatus, bool? byHolder) =>
        w =>
        {
            w.WriteString("UserId", userId ?? string.Empty);
            w.WriteString("Username", username ?? string.Empty);
            Nullable(w, "FromTier", fromTier);
            Nullable(w, "ToTier", toTier);
            Nullable(w, "FromStatus", fromStatus);
            Nullable(w, "ToStatus", toStatus);

            if (byHolder is { } held)
                w.WriteBoolean("ByHolder", held);
            else
                w.WriteNull("ByHolder");
        };

    /// <summary>
    /// An external identity attached to or detached from an account.
    /// </summary>
    /// <param name="userId">The account.</param>
    /// <param name="username">What it was called.</param>
    /// <param name="provider">The provider the identity comes from.</param>
    /// <param name="handle">The identity, as <c>provider:name</c>.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> Identity(
        string userId, string username, string provider, string handle) =>
        w =>
        {
            w.WriteString("UserId", userId ?? string.Empty);
            w.WriteString("Username", username ?? string.Empty);
            w.WriteString("Provider", provider ?? string.Empty);
            w.WriteString("Handle", handle ?? string.Empty);
        };

    /// <summary>A real null for an absent value, never an empty string.</summary>
    private static void Nullable(Utf8JsonWriter writer, string name, string? value)
    {
        if (string.IsNullOrEmpty(value))
            writer.WriteNull(name);
        else
            writer.WriteString(name, value);
    }
}
