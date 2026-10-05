using System.Text.Json;

namespace TheKrystalShip.Auth.Journal;

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
    /// <param name="provider">The provider that proved who they are, or null.</param>
    /// <param name="sid">The session id, so a sign-in and its sign-out pair up.</param>
    /// <param name="userAgent">The calling device, or null when it sent none.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> Session(
        string? userId, string username, string identity, string? provider, string? sid, string? userAgent) =>
        w =>
        {
            Nullable(w, "UserId", userId);
            w.WriteString("Username", username ?? string.Empty);
            w.WriteString("Identity", identity ?? string.Empty);
            Nullable(w, "Provider", provider);
            Nullable(w, "Sid", sid);
            Nullable(w, "UserAgent", userAgent);
        };

    /// <summary>
    /// Sessions torn down before they expired.
    /// </summary>
    /// <param name="scope">How far it reached — one of <see cref="SessionRevokeScopes"/>.</param>
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
    /// An account provisioned, approved, disabled, deleted, or having its password changed.
    /// </summary>
    /// <param name="userId">The account.</param>
    /// <param name="username">What it was called when this happened.</param>
    /// <param name="fromStatus">The status it held before, or null.</param>
    /// <param name="toStatus">The status it holds after, or null.</param>
    /// <param name="byHolder">
    /// Whether the account's own holder did this rather than somebody else acting on them. Null when
    /// the distinction does not apply. It is the whole point of recording a password change: somebody
    /// else setting yours reads completely differently from you setting it.
    /// </param>
    /// <returns>The payload writer.</returns>
    /// <remarks>
    /// Takes no password parameter and never will. What is recorded is that a credential was set and by
    /// whom — the only signal an account takeover leaves — and the credential is not part of that fact.
    /// </remarks>
    public static Action<Utf8JsonWriter> Account(
        string userId, string username, string? fromStatus, string? toStatus, bool? byHolder) =>
        w =>
        {
            w.WriteString("UserId", userId ?? string.Empty);
            w.WriteString("Username", username ?? string.Empty);
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

    /// <summary>
    /// An account given a role within a scope, or losing one.
    /// </summary>
    /// <param name="assignmentId">The assignment.</param>
    /// <param name="userId">The account holding it.</param>
    /// <param name="username">What the account was called.</param>
    /// <param name="roleId">The role.</param>
    /// <param name="role">What the role was called.</param>
    /// <param name="scope">Where it applies, in its wire form.</param>
    /// <param name="authorityVersion">The authority version the change produced.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> Assignment(
        string assignmentId, string userId, string? username, string roleId, string? role, string scope,
        long authorityVersion) =>
        w =>
        {
            w.WriteString("AssignmentId", assignmentId ?? string.Empty);
            w.WriteString("UserId", userId ?? string.Empty);
            Nullable(w, "Username", username);
            w.WriteString("RoleId", roleId ?? string.Empty);
            Nullable(w, "Role", role);
            w.WriteString("Scope", scope ?? string.Empty);
            w.WriteNumber("AuthorityVersion", authorityVersion);
        };

    /// <summary>
    /// The catalog of declared actions changing: which actions arrived and which left.
    /// </summary>
    /// <param name="member">The member whose report, or removal, changed it.</param>
    /// <param name="added">Action ids that arrived, unmapped.</param>
    /// <param name="removed">Action ids no member declares any more, gone from every permission.</param>
    /// <param name="authorityVersion">The authority version the change produced.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> Catalog(
        string member, IReadOnlyList<string> added, IReadOnlyList<string> removed, long authorityVersion) =>
        w =>
        {
            w.WriteString("Member", member ?? string.Empty);
            Strings(w, "Added", added);
            Strings(w, "Removed", removed);
            w.WriteNumber("AuthorityVersion", authorityVersion);
        };

    /// <summary>A service's requirement approved, narrowed or revoked.</summary>
    /// <param name="accountId">The service account.</param>
    /// <param name="service">The service, as <c>svc:&lt;component&gt;@&lt;member&gt;</c>, when known.</param>
    /// <param name="action">The action it requires.</param>
    /// <param name="scope">Where it is approved, or null when revoked.</param>
    /// <param name="automatic">Whether nobody decided it: approved because it was never held before.</param>
    /// <param name="authorityVersion">The authority version the change produced.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> Requirement(
        string accountId, string? service, string action, string? scope, bool automatic, long authorityVersion) =>
        w =>
        {
            w.WriteString("AccountId", accountId ?? string.Empty);
            Nullable(w, "Service", service);
            w.WriteString("Action", action ?? string.Empty);
            Nullable(w, "Scope", scope);
            w.WriteBoolean("Automatic", automatic);
            w.WriteNumber("AuthorityVersion", authorityVersion);
        };

    /// <summary>A permission or a role created, changed or removed.</summary>
    /// <param name="id">The permission's or role's id.</param>
    /// <param name="name">What it is called, when known.</param>
    /// <param name="authorityVersion">The authority version the change produced.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> Authority(string id, string? name, long authorityVersion) =>
        w =>
        {
            w.WriteString("Id", id ?? string.Empty);
            Nullable(w, "Name", name);
            w.WriteNumber("AuthorityVersion", authorityVersion);
        };

    /// <summary>An application, or one of its clients, registered, changed or removed.</summary>
    /// <param name="id">The application's id.</param>
    /// <param name="name">What it is called, when known.</param>
    /// <param name="clientId">The client the change was to, or null for the application's own fields.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> Application(string id, string? name, string? clientId) =>
        w =>
        {
            w.WriteString("Id", id ?? string.Empty);
            Nullable(w, "Name", name);
            Nullable(w, "Client", clientId);
        };

    /// <summary>A token exchange: who asked, for whom, and what it came to.</summary>
    /// <param name="client">The client that authenticated and asked.</param>
    /// <param name="application">The application the token is, or would have been, for.</param>
    /// <param name="identity">The Discord identity exchanged, as <c>provider:subject</c>, when it is known.</param>
    /// <param name="userId">The account that identity proves, when one does.</param>
    /// <param name="username">What that account is called, when one does.</param>
    /// <param name="actedBy">
    /// The client acting for the person, when the token names it as actor (RFC 8693 <c>act</c>); null when
    /// the person presented their own credential.
    /// </param>
    /// <param name="reason">Why no token was given — one of <see cref="TokenExchangeRefusals"/> — or null when one was.</param>
    /// <returns>The payload writer.</returns>
    public static Action<Utf8JsonWriter> TokenExchange(
        string client, string application, string? identity, string? userId, string? username,
        string? actedBy, string? reason) =>
        w =>
        {
            w.WriteString("Client", client ?? string.Empty);
            w.WriteString("Application", application ?? string.Empty);
            Nullable(w, "Identity", identity);
            Nullable(w, "UserId", userId);
            Nullable(w, "Username", username);
            Nullable(w, "ActedBy", actedBy);
            Nullable(w, "Reason", reason);
        };

    private static void Strings(Utf8JsonWriter writer, string name, IReadOnlyList<string> values)
    {
        writer.WriteStartArray(name);
        foreach (string value in values)
            writer.WriteStringValue(value);
        writer.WriteEndArray();
    }

    /// <summary>A real null for an absent value, never an empty string.</summary>
    private static void Nullable(Utf8JsonWriter writer, string name, string? value)
    {
        if (string.IsNullOrEmpty(value))
            writer.WriteNull(name);
        else
            writer.WriteString(name, value);
    }
}
