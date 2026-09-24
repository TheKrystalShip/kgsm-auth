using System.Globalization;
using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Sessions;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// A browser's sign-in at the anchor itself: the row its <c>kgsm_anchor</c> cookie names.
/// </summary>
/// <param name="SessionId">The provider session, as every <c>id_token</c> minted under it carries it in <c>sid</c>.</param>
/// <param name="Handle">The credential handle it was last proved with.</param>
/// <param name="Identity">That credential's identity, as the sessions minted under it carry it.</param>
/// <param name="Created">When this browser first signed in here.</param>
/// <param name="Expires">When the cookie stops being honoured.</param>
/// <param name="CredentialAt">When a credential was last typed or a provider last completed for it.</param>
internal sealed record ProviderSessionRow(
    string SessionId,
    string Handle,
    StoredIdentity Identity,
    DateTimeOffset Created,
    DateTimeOffset Expires,
    DateTimeOffset CredentialAt);

/// <summary>
/// An authorization request, held at the provider while a person proves who they are.
/// </summary>
/// <remarks>
/// Held here rather than carried by the page, so the page, its fallback form and its provider links carry
/// no request field for anybody to edit on the way through. The browser holds only the secret that names
/// it, in <c>kgsm_authz</c>.
/// </remarks>
/// <param name="SecretHash">The hash of the cookie's secret, which is the row's key.</param>
/// <param name="ClientId">The client that asked.</param>
/// <param name="RedirectUri">Where the code goes, already matched against the client's registration.</param>
/// <param name="State">The client's <c>state</c>, returned untouched.</param>
/// <param name="CodeChallenge">The S256 challenge the code will be held to.</param>
/// <param name="Nonce">The client's <c>nonce</c>, stated back in the <c>id_token</c>.</param>
/// <param name="Prompt">What the client asked about showing a page.</param>
/// <param name="UpstreamState">
/// The <c>state</c> a round trip to an external provider was started with, so its callback completes this
/// request and not whatever else the browser has in flight.
/// </param>
/// <param name="Expires">When the request is abandoned.</param>
internal sealed record AuthorizeRequest(
    string SecretHash,
    string ClientId,
    string RedirectUri,
    string? State,
    string CodeChallenge,
    string? Nonce,
    string? Prompt,
    string? UpstreamState,
    DateTimeOffset Expires);

/// <summary>A code, as it waits to be exchanged at <c>/token</c>.</summary>
/// <param name="ClientId">The client it was issued to.</param>
/// <param name="RedirectUri">The exact redirect it was sent to, which the exchange must repeat.</param>
/// <param name="CodeChallenge">What the exchange's verifier must hash to.</param>
/// <param name="Nonce">Stated back in the <c>id_token</c>.</param>
/// <param name="UserId">The account it was issued for.</param>
/// <param name="ProviderSession">The provider session it was issued under.</param>
/// <param name="AuthTime">When that provider session last saw a credential.</param>
/// <param name="Expires">Sixty seconds after issue.</param>
internal sealed record AuthorizationCode(
    string ClientId,
    string RedirectUri,
    string CodeChallenge,
    string? Nonce,
    string UserId,
    string ProviderSession,
    DateTimeOffset AuthTime,
    DateTimeOffset Expires);

/// <summary>Where a registered client came from.</summary>
internal static class ClientSources
{
    /// <summary>Announced over gossip by a member serving a surface; it leaves when the member does.</summary>
    public const string Member = "member";

    /// <summary>Registered by an administrator on this anchor.</summary>
    public const string Admin = "admin";

    /// <summary>A panel on a static host, declared in this anchor's configuration and never stored.</summary>
    public const string Config = "config";
}

/// <summary>A client this provider will issue codes to.</summary>
/// <param name="ClientId">What the client names itself with.</param>
/// <param name="Name">What a person is shown.</param>
/// <param name="RedirectUris">The only places a code is sent, matched exactly.</param>
/// <param name="PostLogoutRedirectUris">The only places a signed-out browser is returned to, matched exactly.</param>
/// <param name="Source">Member or admin.</param>
/// <param name="MemberId">The member that announced it, for a member's client.</param>
/// <param name="Created">When it was registered.</param>
internal sealed record RegisteredClient(
    string ClientId,
    string Name,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris,
    string Source,
    string? MemberId,
    DateTimeOffset Created);

/// <summary>
/// The provider's own rows: its sign-ins, the requests in flight, the codes, and the clients.
/// </summary>
/// <remarks>
/// <para>
/// Beside the sessions rather than in a file of their own, because a provider session is a session — it
/// is listed with the others and ended with them — and every session minted through the provider records
/// the one it came from, so the two are joined by a column rather than across files.
/// </para>
/// <para>
/// A cookie, a request secret and a code are stored hashed. Each is a bearer in its own right, and a
/// copy of this file must not be a way to present one.
/// </para>
/// </remarks>
internal sealed partial class SqliteSessionRegistry
{
    /// <summary>The <c>kind</c> a provider session's row carries. Every other row carries none.</summary>
    internal const string ProviderKind = "provider";

    private static void InitializeProvider(SqliteConnection connection)
    {
        // Additive and nullable, like every column this file has gained: a row written before one
        // existed has no answer for it, and null says so.
        foreach (string column in (string[])
        [
            // The provider session a session was minted under. Survives every rotation, because a
            // rotation updates its row in place.
            "provider_session TEXT NULL",
            // 'provider' on a browser's sign-in at the anchor, null on everything a surface holds.
            "kind TEXT NULL",
            // A provider session's cookie secret, hashed.
            "cookie_hash TEXT NULL",
            // When a provider session last saw a credential: the recent-proof clock and auth_time.
            "credential_at TEXT NULL",
            // The identity a provider session was proved with, which every session minted under it carries.
            "identity TEXT NULL",
        ])
        {
            using SqliteCommand add = connection.CreateCommand();
            add.CommandText = $"ALTER TABLE sessions ADD COLUMN {column};";
            try
            {
                add.ExecuteNonQuery();
            }
            catch (SqliteException)
            {
                // Already there.
            }
        }

        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            CREATE INDEX IF NOT EXISTS ix_sessions_provider ON sessions (provider_session);
            CREATE UNIQUE INDEX IF NOT EXISTS ix_sessions_cookie ON sessions (cookie_hash)
                WHERE cookie_hash IS NOT NULL;

            CREATE TABLE IF NOT EXISTS authorize_requests (
                secret_hash    TEXT PRIMARY KEY,
                client_id      TEXT NOT NULL,
                redirect_uri   TEXT NOT NULL,
                state          TEXT NULL,
                code_challenge TEXT NOT NULL,
                nonce          TEXT NULL,
                prompt         TEXT NULL,
                upstream_state TEXT NULL,
                expires        TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authorization_codes (
                code_hash        TEXT PRIMARY KEY,
                client_id        TEXT NOT NULL,
                redirect_uri     TEXT NOT NULL,
                code_challenge   TEXT NOT NULL,
                nonce            TEXT NULL,
                user_id          TEXT NOT NULL,
                provider_session TEXT NOT NULL,
                auth_time        TEXT NOT NULL,
                expires          TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS clients (
                client_id        TEXT PRIMARY KEY,
                name             TEXT NOT NULL,
                redirect_uris    TEXT NOT NULL,
                post_logout_uris TEXT NOT NULL,
                source           TEXT NOT NULL,
                member_id        TEXT NULL,
                created          TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    // ── Sessions minted under a provider session ─────────────────────────────

    /// <summary>Record a session minted through the provider, naming the provider session it came from.</summary>
    internal Task CreateAsync(SessionRegistration session, string providerSession, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO sessions
                    (session_id, user_id, host_id, created, expires, user_agent, current_jti, revoked,
                     provider_session)
                VALUES ($sid, $user, $host, $created, $expires, $ua, $jti, 0, $provider);
                """;
            cmd.Parameters.AddWithValue("$sid", session.SessionId);
            cmd.Parameters.AddWithValue("$user", session.UserId);
            cmd.Parameters.AddWithValue("$host", session.HostId);
            cmd.Parameters.AddWithValue("$created", session.Created.ToString("O"));
            cmd.Parameters.AddWithValue("$expires", session.Expires.ToString("O"));
            cmd.Parameters.AddWithValue("$ua", (object?)session.UserAgent ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$jti", (object?)session.CurrentJti ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$provider", providerSession);
            cmd.ExecuteNonQuery();
        }

        return Task.CompletedTask;
    }

    // ── Provider sessions ─────────────────────────────────────────────────────

    /// <summary>Start a browser's sign-in at the anchor.</summary>
    internal Task CreateProviderSessionAsync(
        string sessionId, string handle, string identityJson, string cookieHash, string clusterId,
        DateTimeOffset now, DateTimeOffset expires, string? userAgent, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO sessions
                    (session_id, user_id, host_id, created, expires, user_agent, current_jti, revoked,
                     kind, cookie_hash, credential_at, identity)
                VALUES ($sid, $user, $host, $now, $expires, $ua, NULL, 0, $kind, $cookie, $now, $identity);
                """;
            cmd.Parameters.AddWithValue("$sid", sessionId);
            cmd.Parameters.AddWithValue("$user", handle);
            cmd.Parameters.AddWithValue("$host", clusterId);
            cmd.Parameters.AddWithValue("$now", now.ToString("O"));
            cmd.Parameters.AddWithValue("$expires", expires.ToString("O"));
            cmd.Parameters.AddWithValue("$ua", (object?)userAgent ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$kind", ProviderKind);
            cmd.Parameters.AddWithValue("$cookie", cookieHash);
            cmd.Parameters.AddWithValue("$identity", identityJson);
            cmd.ExecuteNonQuery();
        }

        return Task.CompletedTask;
    }

    /// <summary>The live provider session a cookie names, or null.</summary>
    internal Task<ProviderSessionRow?> FindProviderSessionByCookieAsync(string cookieHash, CancellationToken ct = default) =>
        Task.FromResult(ReadProviderSession("cookie_hash = $key", cookieHash));

    /// <summary>The live provider session with this id, or null.</summary>
    internal Task<ProviderSessionRow?> FindProviderSessionAsync(string sessionId, CancellationToken ct = default) =>
        Task.FromResult(ReadProviderSession("session_id = $key", sessionId));

    private ProviderSessionRow? ReadProviderSession(string where, string key)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            $"""
            SELECT session_id, user_id, identity, created, expires, credential_at
              FROM sessions
             WHERE {where} AND kind = $kind AND revoked = 0 AND expires > $now;
            """;
        cmd.Parameters.AddWithValue("$key", key);
        cmd.Parameters.AddWithValue("$kind", ProviderKind);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));

        using SqliteDataReader reader = cmd.ExecuteReader();
        if (!reader.Read())
            return null;

        // A row whose identity cannot be read is a sign-in nothing can be minted under. It is treated as
        // absent, so the browser is asked for a credential rather than handed something half-formed.
        if (reader.IsDBNull(2) || reader.IsDBNull(5) || StoredIdentity.Read(reader.GetString(2)) is not { } identity)
            return null;

        return new ProviderSessionRow(
            reader.GetString(0),
            reader.GetString(1),
            identity,
            Parse(reader.GetString(3)),
            Parse(reader.GetString(4)),
            Parse(reader.GetString(5)));
    }

    /// <summary>
    /// A credential proved the same account again: record when, and which credential, and give the cookie
    /// its full lifetime from now.
    /// </summary>
    internal Task<bool> ReproveProviderSessionAsync(
        string sessionId, string handle, string identityJson, DateTimeOffset now, DateTimeOffset expires,
        CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                UPDATE sessions
                   SET user_id = $user, identity = $identity, credential_at = $now, expires = $expires
                 WHERE session_id = $sid AND kind = $kind AND revoked = 0;
                """;
            cmd.Parameters.AddWithValue("$sid", sessionId);
            cmd.Parameters.AddWithValue("$user", handle);
            cmd.Parameters.AddWithValue("$identity", identityJson);
            cmd.Parameters.AddWithValue("$now", now.ToString("O"));
            cmd.Parameters.AddWithValue("$expires", expires.ToString("O"));
            cmd.Parameters.AddWithValue("$kind", ProviderKind);

            return Task.FromResult(cmd.ExecuteNonQuery() == 1);
        }
    }

    /// <summary>
    /// End a provider session and every session minted under it, and say which of them were live.
    /// </summary>
    /// <remarks>
    /// Found by the column rather than by the cookie, so a sign-out naming the provider session in an
    /// <c>id_token_hint</c> ends it whether or not the browser still carries the cookie. The ids come back
    /// with the handle each was keyed by, because each one has to be announced to the other members and
    /// recorded against its account.
    /// </remarks>
    /// <returns>The live sessions ended, the provider session itself included when it was live.</returns>
    internal Task<IReadOnlyList<(string SessionId, string Handle, bool Provider)>> EndProviderSessionAsync(
        string providerSession, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteTransaction tx = connection.BeginTransaction();

            var ended = new List<(string, string, bool)>();
            using (SqliteCommand read = connection.CreateCommand())
            {
                read.Transaction = tx;
                read.CommandText =
                    """
                    SELECT session_id, user_id, kind
                      FROM sessions
                     WHERE (session_id = $psid OR provider_session = $psid) AND revoked = 0 AND expires > $now;
                    """;
                read.Parameters.AddWithValue("$psid", providerSession);
                read.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
                using SqliteDataReader reader = read.ExecuteReader();
                while (reader.Read())
                {
                    ended.Add((reader.GetString(0), reader.GetString(1),
                        !reader.IsDBNull(2) && reader.GetString(2) == ProviderKind));
                }
            }

            using (SqliteCommand revoke = connection.CreateCommand())
            {
                revoke.Transaction = tx;
                revoke.CommandText =
                    """
                    UPDATE sessions SET revoked = 1, current_jti = NULL, cookie_hash = NULL
                     WHERE (session_id = $psid OR provider_session = $psid) AND revoked = 0;
                    """;
                revoke.Parameters.AddWithValue("$psid", providerSession);
                revoke.ExecuteNonQuery();
            }

            tx.Commit();
            return Task.FromResult<IReadOnlyList<(string, string, bool)>>(ended);
        }
    }

    /// <summary>Whether this session id is a provider session's, live or not.</summary>
    internal Task<bool> IsProviderSessionAsync(string sessionId, CancellationToken ct = default)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM sessions WHERE session_id = $sid AND kind = $kind;";
        cmd.Parameters.AddWithValue("$sid", sessionId);
        cmd.Parameters.AddWithValue("$kind", ProviderKind);
        return Task.FromResult(cmd.ExecuteScalar() is not null);
    }

    // ── Requests in flight ────────────────────────────────────────────────────

    /// <summary>Hold a validated authorization request under the hash of the secret its cookie carries.</summary>
    internal Task StoreRequestAsync(AuthorizeRequest request, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO authorize_requests
                    (secret_hash, client_id, redirect_uri, state, code_challenge, nonce, prompt, upstream_state, expires)
                VALUES ($key, $client, $redirect, $state, $challenge, $nonce, $prompt, NULL, $expires);
                """;
            cmd.Parameters.AddWithValue("$key", request.SecretHash);
            cmd.Parameters.AddWithValue("$client", request.ClientId);
            cmd.Parameters.AddWithValue("$redirect", request.RedirectUri);
            cmd.Parameters.AddWithValue("$state", (object?)request.State ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$challenge", request.CodeChallenge);
            cmd.Parameters.AddWithValue("$nonce", (object?)request.Nonce ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$prompt", (object?)request.Prompt ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$expires", request.Expires.ToString("O"));
            cmd.ExecuteNonQuery();
        }

        return Task.CompletedTask;
    }

    /// <summary>The live request a cookie's secret names, or null.</summary>
    internal Task<AuthorizeRequest?> FindRequestAsync(string secretHash, CancellationToken ct = default)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            SELECT secret_hash, client_id, redirect_uri, state, code_challenge, nonce, prompt, upstream_state, expires
              FROM authorize_requests
             WHERE secret_hash = $key AND expires > $now;
            """;
        cmd.Parameters.AddWithValue("$key", secretHash);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));

        using SqliteDataReader reader = cmd.ExecuteReader();
        if (!reader.Read())
            return Task.FromResult<AuthorizeRequest?>(null);

        return Task.FromResult<AuthorizeRequest?>(new AuthorizeRequest(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            NullableString(reader, 3),
            reader.GetString(4),
            NullableString(reader, 5),
            NullableString(reader, 6),
            NullableString(reader, 7),
            Parse(reader.GetString(8))));
    }

    /// <summary>Record the state a round trip to an external provider began with.</summary>
    internal Task SetUpstreamStateAsync(string secretHash, string upstreamState, CancellationToken ct = default) =>
        Execute("UPDATE authorize_requests SET upstream_state = $value WHERE secret_hash = $key;",
            secretHash, upstreamState);

    /// <summary>Keep a request alive while its account waits for approval.</summary>
    internal Task ExtendRequestAsync(string secretHash, DateTimeOffset expires, CancellationToken ct = default) =>
        Execute("UPDATE authorize_requests SET expires = $value WHERE secret_hash = $key;",
            secretHash, expires.ToString("O"));

    /// <summary>Forget a request, answered or abandoned.</summary>
    internal Task DeleteRequestAsync(string secretHash, CancellationToken ct = default) =>
        Execute("DELETE FROM authorize_requests WHERE secret_hash = $key;", secretHash, null);

    // ── Codes ─────────────────────────────────────────────────────────────────

    /// <summary>Hold a code until it is exchanged or expires.</summary>
    internal Task IssueCodeAsync(string codeHash, AuthorizationCode code, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO authorization_codes
                    (code_hash, client_id, redirect_uri, code_challenge, nonce, user_id, provider_session,
                     auth_time, expires)
                VALUES ($key, $client, $redirect, $challenge, $nonce, $user, $provider, $auth, $expires);
                """;
            cmd.Parameters.AddWithValue("$key", codeHash);
            cmd.Parameters.AddWithValue("$client", code.ClientId);
            cmd.Parameters.AddWithValue("$redirect", code.RedirectUri);
            cmd.Parameters.AddWithValue("$challenge", code.CodeChallenge);
            cmd.Parameters.AddWithValue("$nonce", (object?)code.Nonce ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$user", code.UserId);
            cmd.Parameters.AddWithValue("$provider", code.ProviderSession);
            cmd.Parameters.AddWithValue("$auth", code.AuthTime.ToString("O"));
            cmd.Parameters.AddWithValue("$expires", code.Expires.ToString("O"));
            cmd.ExecuteNonQuery();
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Take a code out of the store, whatever else is wrong with the exchange presenting it.
    /// </summary>
    /// <remarks>
    /// One statement that deletes and returns, so two exchanges racing with the same code cannot both
    /// read it: exactly one gets the row and the other gets nothing. The caller checks expiry, client,
    /// redirect and verifier afterwards — a code presented wrongly is spent, because the only party that
    /// presents one wrongly is one that should not have it.
    /// </remarks>
    internal Task<AuthorizationCode?> ConsumeCodeAsync(string codeHash, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                DELETE FROM authorization_codes WHERE code_hash = $key
                RETURNING client_id, redirect_uri, code_challenge, nonce, user_id, provider_session, auth_time, expires;
                """;
            cmd.Parameters.AddWithValue("$key", codeHash);

            using SqliteDataReader reader = cmd.ExecuteReader();
            if (!reader.Read())
                return Task.FromResult<AuthorizationCode?>(null);

            return Task.FromResult<AuthorizationCode?>(new AuthorizationCode(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                NullableString(reader, 3),
                reader.GetString(4),
                reader.GetString(5),
                Parse(reader.GetString(6)),
                Parse(reader.GetString(7))));
        }
    }

    // ── Clients ───────────────────────────────────────────────────────────────

    /// <summary>Every registered client.</summary>
    internal Task<IReadOnlyList<RegisteredClient>> ListClientsAsync(CancellationToken ct = default)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand cmd = connection.CreateCommand();
        cmd.CommandText =
            """
            SELECT client_id, name, redirect_uris, post_logout_uris, source, member_id, created
              FROM clients ORDER BY client_id;
            """;

        var clients = new List<RegisteredClient>();
        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            clients.Add(new RegisteredClient(
                reader.GetString(0),
                reader.GetString(1),
                Lines(reader.GetString(2)),
                Lines(reader.GetString(3)),
                reader.GetString(4),
                NullableString(reader, 5),
                Parse(reader.GetString(6))));
        }

        return Task.FromResult<IReadOnlyList<RegisteredClient>>(clients);
    }

    /// <summary>Register an administrator's client. False when the id is already taken.</summary>
    internal Task<bool> AddClientAsync(RegisteredClient client, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO clients (client_id, name, redirect_uris, post_logout_uris, source, member_id, created)
                VALUES ($id, $name, $redirects, $logouts, $source, $member, $created)
                ON CONFLICT (client_id) DO NOTHING;
                """;
            BindClient(cmd, client);
            return Task.FromResult(cmd.ExecuteNonQuery() == 1);
        }
    }

    /// <summary>Remove an administrator's client. False when there is none by that id.</summary>
    internal Task<bool> RemoveAdminClientAsync(string clientId, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM clients WHERE client_id = $id AND source = $source;";
            cmd.Parameters.AddWithValue("$id", clientId);
            cmd.Parameters.AddWithValue("$source", ClientSources.Admin);
            return Task.FromResult(cmd.ExecuteNonQuery() == 1);
        }
    }

    /// <summary>
    /// Make the members' clients exactly <paramref name="announced"/>, leaving every administrator's alone.
    /// </summary>
    /// <remarks>
    /// One transaction, so a reader never sees a member's client missing between its removal and its
    /// re-insertion. An announced id that an administrator already registered keeps the administrator's
    /// row: a member cannot take over a client somebody registered by hand.
    /// </remarks>
    /// <returns>Whether anything changed.</returns>
    internal Task<bool> ReplaceMemberClientsAsync(IReadOnlyList<RegisteredClient> announced, CancellationToken ct = default)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteTransaction tx = connection.BeginTransaction();

            var current = new Dictionary<string, (string Name, string Redirects, string Logouts, string? Member)>(StringComparer.Ordinal);
            using (SqliteCommand read = connection.CreateCommand())
            {
                read.Transaction = tx;
                read.CommandText =
                    "SELECT client_id, name, redirect_uris, post_logout_uris, member_id FROM clients WHERE source = $source;";
                read.Parameters.AddWithValue("$source", ClientSources.Member);
                using SqliteDataReader reader = read.ExecuteReader();
                while (reader.Read())
                {
                    current[reader.GetString(0)] =
                        (reader.GetString(1), reader.GetString(2), reader.GetString(3), NullableString(reader, 4));
                }
            }

            bool changed = false;
            var keep = new HashSet<string>(StringComparer.Ordinal);

            foreach (RegisteredClient client in announced)
            {
                keep.Add(client.ClientId);
                if (current.TryGetValue(client.ClientId, out var row)
                    && row.Name == client.Name
                    && row.Redirects == Join(client.RedirectUris)
                    && row.Logouts == Join(client.PostLogoutRedirectUris)
                    && row.Member == client.MemberId)
                    continue;

                using SqliteCommand upsert = connection.CreateCommand();
                upsert.Transaction = tx;
                upsert.CommandText =
                    """
                    INSERT INTO clients (client_id, name, redirect_uris, post_logout_uris, source, member_id, created)
                    VALUES ($id, $name, $redirects, $logouts, $source, $member, $created)
                    ON CONFLICT (client_id) DO UPDATE SET
                        name = excluded.name,
                        redirect_uris = excluded.redirect_uris,
                        post_logout_uris = excluded.post_logout_uris,
                        member_id = excluded.member_id
                    WHERE clients.source = excluded.source;
                    """;
                BindClient(upsert, client);
                changed |= upsert.ExecuteNonQuery() > 0;
            }

            foreach (string gone in current.Keys.Where(id => !keep.Contains(id)))
            {
                using SqliteCommand delete = connection.CreateCommand();
                delete.Transaction = tx;
                delete.CommandText = "DELETE FROM clients WHERE client_id = $id AND source = $source;";
                delete.Parameters.AddWithValue("$id", gone);
                delete.Parameters.AddWithValue("$source", ClientSources.Member);
                changed |= delete.ExecuteNonQuery() > 0;
            }

            tx.Commit();
            return Task.FromResult(changed);
        }
    }

    private static void BindClient(SqliteCommand cmd, RegisteredClient client)
    {
        cmd.Parameters.AddWithValue("$id", client.ClientId);
        cmd.Parameters.AddWithValue("$name", client.Name);
        cmd.Parameters.AddWithValue("$redirects", Join(client.RedirectUris));
        cmd.Parameters.AddWithValue("$logouts", Join(client.PostLogoutRedirectUris));
        cmd.Parameters.AddWithValue("$source", client.Source);
        cmd.Parameters.AddWithValue("$member", (object?)client.MemberId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$created", client.Created.ToString("O"));
    }

    // A URI never contains a line break, so a list of them is stored one per line.
    private static string Join(IReadOnlyList<string> uris) => string.Join('\n', uris);

    private static IReadOnlyList<string> Lines(string stored) =>
        stored.Split('\n', StringSplitOptions.RemoveEmptyEntries);

    private Task Execute(string sql, string key, string? value)
    {
        lock (_writeGate)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand cmd = connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.Parameters.AddWithValue("$key", key);
            cmd.Parameters.AddWithValue("$value", (object?)value ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }

        return Task.CompletedTask;
    }

    private static string? NullableString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTimeOffset Parse(string stored) =>
        DateTimeOffset.Parse(stored, CultureInfo.InvariantCulture);
}
