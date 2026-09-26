using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;

namespace TheKrystalShip.KGSM.Auth.Users;

// People's accounts at schema version 2: the account store every sign-in door reads, over the same file
// and the same write path as the authority, so an account change is versioned, owed to the cluster and
// cached against exactly as a role change is.
//
// Only person accounts are reached through IUserStore; service accounts belong to the reports that
// create them. A version 2 account holds no tier: what it may do is its assignments, so a KgsmUser read
// here carries KgsmTier.None, and its TierSource is the account's origin — Granted for one somebody
// admitted, Derived for one that arrived by itself.
public sealed partial class SqliteAuthorityStore : IUserStore
{
    private const string PersonColumns =
        "u.user_id, u.username, u.display_name, u.origin, u.status, u.created_utc, u.updated_utc";

    private const string CredentialColumns =
        "credential_id, user_id, kind, handle, secret, label, created_utc, last_used_utc";

    /// <inheritdoc />
    public Task<KgsmUser?> FindByIdAsync(string userId, CancellationToken ct = default) =>
        ReadPersonAsync("WHERE u.user_id = $p", userId, ct);

    /// <inheritdoc />
    public Task<KgsmUser?> FindByUsernameAsync(string username, CancellationToken ct = default) =>
        ReadPersonAsync("WHERE u.username_key = $p", Usernames.Key(username), ct);

    /// <inheritdoc />
    public Task<KgsmUser?> FindByCredentialAsync(string handle, CancellationToken ct = default) =>
        ReadPersonAsync("JOIN credentials c ON c.user_id = u.user_id WHERE c.handle = $p", handle, ct);

    /// <inheritdoc />
    public async Task<IReadOnlyList<KgsmUser>> ListAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        List<KgsmUser> users = [];
        Read(connection, null,
            $"SELECT {PersonColumns} FROM users u WHERE u.kind = 'person' ORDER BY u.created_utc, u.user_id;",
            r => users.Add(MapPerson(r)));
        return users;
    }

    /// <inheritdoc />
    /// <remarks>A person account, holding nothing but <c>everyone</c> until somebody assigns it a role.</remarks>
    public Task CreateAsync(KgsmUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        return AccountWriteAsync(ct, w =>
        {
            Unique(() => w.Execute(
                """
                INSERT INTO users (user_id, username, username_key, display_name, origin, kind, status, created_utc, updated_utc, version)
                VALUES ($id, $name, $key, $display, $origin, 'person', $status, $created, $updated, $v);
                """,
                ("$id", user.UserId), ("$name", user.Username), ("$key", Usernames.Key(user.Username)),
                ("$display", user.DisplayName), ("$origin", Origin(user)), ("$status", UserStatuses.ToWire(user.Status)),
                ("$created", UserWire.ToWire(user.Created)), ("$updated", UserWire.ToWire(user.Updated))),
                "username_key", () => new DuplicateUsernameException(user.Username));
            return true;
        });
    }

    /// <inheritdoc />
    /// <remarks>
    /// Writes the username, display name, origin and status. Disabling somebody through here bypasses the
    /// administration rules; a request doing it goes through <see cref="DisableAccount"/> instead, which is
    /// what holds the last Owner.
    /// </remarks>
    public Task<bool> UpdateAsync(KgsmUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        return AccountWriteAsync(ct, w =>
        {
            int changed = 0;
            Unique(() => changed = w.ExecuteCount(
                """
                UPDATE users SET username = $name, username_key = $key, display_name = $display, origin = $origin,
                                 status = $status, updated_utc = $updated, version = $v
                WHERE user_id = $id AND kind = 'person';
                """,
                ("$id", user.UserId), ("$name", user.Username), ("$key", Usernames.Key(user.Username)),
                ("$display", user.DisplayName), ("$origin", Origin(user)), ("$status", UserStatuses.ToWire(user.Status)),
                ("$updated", UserWire.ToWire(user.Updated))),
                "username_key", () => new DuplicateUsernameException(user.Username));
            return changed > 0;
        });
    }

    /// <inheritdoc />
    /// <remarks>
    /// The system's removal — an arrival nobody approved, expiring — with none of the administration
    /// rules. A person deleting an account goes through <see cref="DeleteAccount"/>.
    /// </remarks>
    public async Task<bool> DeleteAsync(string userId, CancellationToken ct = default)
    {
        bool deleted = false;
        await WriteAsync(expectedVersion: null, DateTimeOffset.UtcNow, ct, (w, s) =>
        {
            if (s.Accounts.TryGetValue(userId, out AccessAccount? account) && account.Kind == AccountKind.Person)
            {
                DeleteAccountRow(w, s, userId);
                deleted = true;
            }

            return null;
        }).ConfigureAwait(false);
        return deleted;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<UserCredential>> ListCredentialsAsync(string userId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        List<UserCredential> credentials = [];
        Read(connection, null,
            $"SELECT {CredentialColumns} FROM credentials WHERE user_id = $id ORDER BY created_utc, credential_id;",
            r => credentials.Add(MapCredential(r)), ("$id", userId));
        return credentials;
    }

    /// <inheritdoc />
    public async Task<UserCredential?> FindCredentialAsync(string handle, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        UserCredential? found = null;
        Read(connection, null, $"SELECT {CredentialColumns} FROM credentials WHERE handle = $h;",
            r => found = MapCredential(r), ("$h", handle));
        return found;
    }

    /// <inheritdoc />
    /// <remarks>The account's handles travel with it, so attaching one is a change to the account the cluster is owed.</remarks>
    public Task AddCredentialAsync(UserCredential credential, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        return AccountWriteAsync(ct, w =>
        {
            Unique(() => w.Execute(
                """
                INSERT INTO credentials (credential_id, user_id, kind, handle, secret, label, created_utc, last_used_utc)
                VALUES ($cid, $id, $kind, $handle, $secret, $label, $created, $used);
                """,
                ("$cid", credential.CredentialId), ("$id", credential.UserId), ("$kind", CredentialKinds.ToWire(credential.Kind)),
                ("$handle", credential.Handle), ("$secret", (object?)credential.Secret ?? DBNull.Value),
                ("$label", (object?)credential.Label ?? DBNull.Value), ("$created", UserWire.ToWire(credential.Created)),
                ("$used", credential.LastUsed is { } used ? UserWire.ToWire(used) : DBNull.Value)),
                "handle", () => new DuplicateCredentialException(credential.Handle));
            Stamp(w, credential.UserId);
            return true;
        });
    }

    /// <inheritdoc />
    /// <remarks>A secret never travels, so setting one owes the cluster nothing.</remarks>
    public Task<bool> SetCredentialSecretAsync(string credentialId, string secret, CancellationToken ct = default) =>
        RecordAsync(ct, w => w.RecordCount("UPDATE credentials SET secret = $s WHERE credential_id = $id;",
            ("$id", credentialId), ("$s", secret)) > 0);

    /// <inheritdoc />
    public Task TouchCredentialAsync(string credentialId, DateTimeOffset when, CancellationToken ct = default) =>
        RecordAsync(ct, w => w.RecordCount("UPDATE credentials SET last_used_utc = $at WHERE credential_id = $id;",
            ("$id", credentialId), ("$at", UserWire.ToWire(when))) > 0);

    /// <inheritdoc />
    public Task<bool> RemoveCredentialAsync(string credentialId, CancellationToken ct = default) =>
        AccountWriteAsync(ct, w =>
        {
            string? owner = w.Query((c, t) =>
                Scalar(c, t, "SELECT user_id FROM credentials WHERE credential_id = $id;", ("$id", credentialId)) as string);
            if (owner is null)
                return false;

            w.Execute("DELETE FROM credentials WHERE credential_id = $id;", ("$id", credentialId));
            Stamp(w, owner);
            return true;
        });

    /// <inheritdoc />
    public async Task<LoginLockout> GetLockoutAsync(string userId, LockoutPolicy policy, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(policy);

        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        LoginLockout standing = LoginLockout.Clear;
        Read(connection, null,
            "SELECT failed_count, last_failed_utc, locked_until_utc FROM login_failures WHERE user_id = $id;",
            r =>
            {
                bool stale = now - UserWire.ReadTime(r.GetString(1)) >= policy.FailureWindow;
                standing = new LoginLockout(stale ? 0 : r.GetInt32(0), r.IsDBNull(2) ? null : UserWire.ReadTime(r.GetString(2)));
            },
            ("$id", userId));
        return standing;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Bookkeeping, never authority: a failed sign-in is recorded in the write that counts it, and the
    /// lock it implies is decided in the same transaction, so the two cannot disagree.
    /// </remarks>
    public Task<LoginLockout> RecordFailureAsync(string userId, LockoutPolicy policy, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(policy);

        return RecordAsync(ct, w =>
        {
            (int previous, DateTimeOffset? last) = w.Query((c, t) =>
            {
                (int, DateTimeOffset?) held = (0, null);
                Read(c, t, "SELECT failed_count, last_failed_utc FROM login_failures WHERE user_id = $id;",
                    r => held = (r.GetInt32(0), UserWire.ReadTime(r.GetString(1))), ("$id", userId));
                return held;
            });

            bool stale = last is null || now - last.Value >= policy.FailureWindow;
            int count = stale ? 1 : previous + 1;
            TimeSpan delay = policy.DelayAfter(count);
            DateTimeOffset? until = delay > TimeSpan.Zero ? now + delay : null;

            w.Record(
                """
                INSERT INTO login_failures (user_id, failed_count, last_failed_utc, locked_until_utc)
                VALUES ($id, $count, $last, $until)
                ON CONFLICT(user_id) DO UPDATE SET failed_count = excluded.failed_count,
                    last_failed_utc = excluded.last_failed_utc, locked_until_utc = excluded.locked_until_utc;
                """,
                ("$id", userId), ("$count", count), ("$last", UserWire.ToWire(now)),
                ("$until", until is { } u ? UserWire.ToWire(u) : DBNull.Value));

            return new LoginLockout(count, until);
        });
    }

    /// <inheritdoc />
    public Task ClearLockoutAsync(string userId, CancellationToken ct = default) =>
        RecordAsync(ct, w => w.RecordCount("DELETE FROM login_failures WHERE user_id = $id;", ("$id", userId)) > 0);

    // ── plumbing ──────────────────────────────────────────────────────────────────────────────

    /// <summary>An account write: versioned, owed to the cluster, cached against — through the authority's own path.</summary>
    private async Task<T> AccountWriteAsync<T>(CancellationToken ct, Func<Writer, T> apply)
    {
        T result = default!;
        await WriteAsync(expectedVersion: null, DateTimeOffset.UtcNow, ct, (w, _) =>
        {
            result = apply(w);
            return null;
        }).ConfigureAwait(false);
        return result;
    }

    /// <summary>Bookkeeping that is nobody's access: committed without advancing the authority version.</summary>
    private Task<T> RecordAsync<T>(CancellationToken ct, Func<Writer, T> apply) => AccountWriteAsync(ct, apply);

    /// <summary>Stamp an account with this write's version, so the cluster is owed its current state.</summary>
    private static void Stamp(Writer w, string userId) =>
        w.Execute("UPDATE users SET version = $v WHERE user_id = $id;", ("$id", userId));

    /// <summary>Run a write, turning a unique violation on <paramref name="column"/> into the store's own exception.</summary>
    private static void Unique(Action write, string column, Func<Exception> duplicate)
    {
        try
        {
            write();
        }
        catch (SqliteException e) when (e.SqliteExtendedErrorCode == 2067 && e.Message.Contains('.' + column, StringComparison.Ordinal))
        {
            throw duplicate();
        }
    }

    private static string Origin(KgsmUser user) =>
        AccountWire.ToWire(user.TierSource == TierSource.Granted ? AccountOrigin.Admitted : AccountOrigin.Arrived);

    private async Task<KgsmUser?> ReadPersonAsync(string where, string parameter, CancellationToken ct)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        KgsmUser? found = null;
        Read(connection, null, $"SELECT {PersonColumns} FROM users u {where} AND u.kind = 'person';",
            r => found = MapPerson(r), ("$p", parameter));
        return found;
    }

    private static KgsmUser MapPerson(SqliteDataReader r) => new(
        UserId: r.GetString(0),
        Username: r.GetString(1),
        DisplayName: r.GetString(2),
        Tier: KgsmTier.None,
        TierSource: AccountWire.ParseOrigin(r.GetString(3)) == AccountOrigin.Admitted ? TierSource.Granted : TierSource.Derived,
        Status: UserStatuses.Parse(r.GetString(4)),
        Created: UserWire.ReadTime(r.GetString(5)),
        Updated: UserWire.ReadTime(r.GetString(6)));

    private static UserCredential MapCredential(SqliteDataReader r) => new(
        CredentialId: r.GetString(0),
        UserId: r.GetString(1),
        Kind: CredentialKinds.Parse(r.GetString(2)),
        Handle: r.GetString(3),
        Secret: r.IsDBNull(4) ? null : r.GetString(4),
        Label: r.IsDBNull(5) ? null : r.GetString(5),
        Created: UserWire.ReadTime(r.GetString(6)),
        LastUsed: r.IsDBNull(7) ? null : UserWire.ReadTime(r.GetString(7)));
}
