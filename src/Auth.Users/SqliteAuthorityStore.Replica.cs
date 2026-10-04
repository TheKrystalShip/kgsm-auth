using System.Data;
using System.Globalization;

using Microsoft.Data.Sqlite;

using TheKrystalShip.Auth.Access;

namespace TheKrystalShip.Auth.Users;

/// <summary>What a replica holds about its own freshness, read in one statement.</summary>
/// <param name="Generation">The counter every applied change advances.</param>
/// <param name="Version">The highest authority version applied.</param>
/// <param name="Freshness">When it was last confirmed current, and for how long.</param>
/// <param name="MinimumContractVersion">The lowest evaluation contract the cluster accepts.</param>
public readonly record struct ReplicaState(long Generation, long Version, AuthorityFreshness Freshness, int MinimumContractVersion);

// A member's half of replication: applying what the anchor sends, one record at a time and in any
// order, and a whole snapshot when it has nothing or has fallen behind.
//
// A replica applies with foreign keys off. The bus does not order delivery, so an assignment can
// arrive before the role it names; each record is applied on its own version, and one naming a record
// that is not here yet grants nothing until that record arrives.
public sealed partial class SqliteAuthorityStore
{
    /// <summary>Apply an account's state.</summary>
    public Task<AuthorityApplyOutcome> ApplyAsync(AccountRecord record, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return ReplicaWriteAsync(AuthorityRecordKey.Account(record.UserId), record.Version, removed: false, now, ct,
            (c, t) => PutAccount(c, t, record));
    }

    /// <summary>Apply a role's state.</summary>
    public Task<AuthorityApplyOutcome> ApplyAsync(RoleRecord record, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return ReplicaWriteAsync(AuthorityRecordKey.Role(record.RoleId), record.Version, removed: false, now, ct,
            (c, t) => PutRole(c, t, record, now));
    }

    /// <summary>Apply a permission's state.</summary>
    public Task<AuthorityApplyOutcome> ApplyAsync(PermissionRecord record, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return ReplicaWriteAsync(AuthorityRecordKey.Permission(record.PermissionId), record.Version, removed: false, now, ct,
            (c, t) => PutPermission(c, t, record, now));
    }

    /// <summary>Apply an assignment's state.</summary>
    public Task<AuthorityApplyOutcome> ApplyAsync(AssignmentRecord record, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return ReplicaWriteAsync(AuthorityRecordKey.Assignment(record.AssignmentId), record.Version, removed: false, now, ct,
            (c, t) => PutAssignment(c, t, record));
    }

    /// <summary>Apply the catalog.</summary>
    public Task<AuthorityApplyOutcome> ApplyAsync(CatalogRecord record, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return ReplicaWriteAsync(AuthorityRecordKey.Catalog, record.Version, removed: false, now, ct,
            (c, t) => PutCatalog(c, t, record));
    }

    /// <summary>
    /// Apply a record's removal. The version it was removed at stays behind as a tombstone, so a change
    /// issued before the removal and delivered after it is refused rather than bringing the record back.
    /// </summary>
    public Task<AuthorityApplyOutcome> RemoveAsync(AuthorityRecordKey key, long version, DateTimeOffset now, CancellationToken ct = default)
    {
        if (key.Kind == AuthorityRecordKind.Catalog)
            throw new ArgumentException("The catalog is replaced, never removed.", nameof(key));

        return ReplicaWriteAsync(key, version, removed: true, now, ct, (c, t) => Delete(c, t, key, version));
    }

    /// <summary>
    /// Take the anchor's whole state: every record newer than what is held is applied, every record held
    /// that the snapshot does not contain and that is no newer than it is removed, and the replica is
    /// confirmed current as of the moment the snapshot was taken.
    /// </summary>
    /// <returns>The records a newer local one blocked, which the stream delivers again.</returns>
    public async Task<int> ApplySnapshotAsync(AuthorityReplicaSnapshot snapshot, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        await using SqliteConnection connection = await ConnectReplicaAsync(ct).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);

        // Absent from the snapshot and no newer than it: removed at the anchor since this replica last
        // heard. A row newer than the snapshot arrived on the stream after the snapshot was cut, and stays.
        void Absent(string table, string column, IEnumerable<string> present, Func<string, AuthorityRecordKey> key)
        {
            HashSet<string> keep = present.ToHashSet(StringComparer.Ordinal);
            List<string> gone = [];
            Read(connection, transaction, $"SELECT {column} FROM {table} WHERE version <= $v;",
                r => { if (!keep.Contains(r.GetString(0))) gone.Add(r.GetString(0)); }, ("$v", snapshot.Version));

            foreach (string id in gone)
                Delete(connection, transaction, key(id), snapshot.Version);
        }

        Absent("assignments", "assignment_id", snapshot.Assignments.Select(a => a.AssignmentId), AuthorityRecordKey.Assignment);
        Absent("roles", "role_id", snapshot.Roles.Select(r => r.RoleId), AuthorityRecordKey.Role);
        Absent("permissions", "permission_id", snapshot.Permissions.Select(p => p.PermissionId), AuthorityRecordKey.Permission);
        Absent("users", "user_id", snapshot.Accounts.Select(a => a.UserId), AuthorityRecordKey.Account);

        int deferred = 0;
        void Take(AuthorityRecordKey key, long version, Action apply)
        {
            if (version <= Held(connection, transaction, key))
                return;

            string savepoint = "record";
            transaction.Save(savepoint);
            try
            {
                apply();
                Execute(connection, transaction, "DELETE FROM authority_tombstones WHERE record = $r;", ("$r", key.ToString()));
                transaction.Release(savepoint);
            }
            catch (SqliteException e) when (e.SqliteErrorCode == 19)
            {
                transaction.Rollback(savepoint);
                deferred++;
            }
        }

        foreach (PermissionRecord p in snapshot.Permissions)
            Take(AuthorityRecordKey.Permission(p.PermissionId), p.Version, () => PutPermission(connection, transaction, p, now));
        foreach (RoleRecord r in snapshot.Roles)
            Take(AuthorityRecordKey.Role(r.RoleId), r.Version, () => PutRole(connection, transaction, r, now));
        foreach (AccountRecord a in snapshot.Accounts)
            Take(AuthorityRecordKey.Account(a.UserId), a.Version, () => PutAccount(connection, transaction, a));
        foreach (AssignmentRecord a in snapshot.Assignments)
            Take(AuthorityRecordKey.Assignment(a.AssignmentId), a.Version, () => PutAssignment(connection, transaction, a));
        Take(AuthorityRecordKey.Catalog, snapshot.Catalog.Version, () => PutCatalog(connection, transaction, snapshot.Catalog));

        RaiseVersion(connection, transaction, snapshot.Version);
        Confirm(connection, transaction, snapshot.Current, now, requireVersion: false);
        AdvanceGeneration(connection, transaction);

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return deferred;
    }

    /// <summary>
    /// Apply the anchor's heartbeat. It confirms the replica current as of when it was sent, but only when
    /// the replica already holds that version: a replica that has not caught up is not confirmed by
    /// hearing that there is more.
    /// </summary>
    /// <returns>Whether the replica is confirmed by it.</returns>
    public async Task<bool> ConfirmAsync(AuthorityCurrent current, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(current);

        await using SqliteConnection connection = await ConnectReplicaAsync(ct).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);

        bool confirmed = Confirm(connection, transaction, current, now, requireVersion: true);
        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return confirmed;
    }

    /// <summary>The replica's generation, version and freshness, in one read.</summary>
    public async Task<ReplicaState> ReplicaStateAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);

        Dictionary<string, string> meta = new(StringComparer.Ordinal);
        Read(connection, null, "SELECT key, value FROM authority_meta;", r => meta[r.GetString(0)] = r.GetString(1));

        long Long(string key) =>
            meta.TryGetValue(key, out string? v) && long.TryParse(v, CultureInfo.InvariantCulture, out long n) ? n : 0;

        DateTimeOffset? confirmed =
            meta.TryGetValue(AuthoritySchema.ConfirmedKey, out string? at)
            && DateTimeOffset.TryParse(at, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset when)
                ? when
                : null;

        // A replica that has never heard a bound holds itself to none: it is current for no time at all.
        long bound = Long(AuthoritySchema.BoundKey);
        long contract = Long(AuthoritySchema.MinimumContractKey);

        return new ReplicaState(
            Long(AuthoritySchema.GenerationKey),
            Long(AuthoritySchema.AuthorityVersionKey),
            AuthorityFreshness.Replica(confirmed, TimeSpan.FromSeconds(bound)),
            contract > 0 ? (int)contract : AccessContract.Version);
    }

    /// <summary>The account a credential handle identifies, or <see langword="null"/>.</summary>
    public async Task<string?> FindAccountIdByHandleAsync(string handle, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(handle);

        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return Scalar(connection, null, "SELECT user_id FROM credentials WHERE handle = $h;", ("$h", handle)) as string;
    }

    /// <summary>The generation, read alone: what a cached snapshot is compared against.</summary>
    public async Task<long> GenerationAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return ReadMetaLong(connection, null, AuthoritySchema.GenerationKey);
    }

    /// <summary>The snapshot and the generation it was read at, in one transaction.</summary>
    internal async Task<(AuthoritySnapshot Snapshot, long Generation)> LoadWithGenerationAsync(CancellationToken ct)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);

        long generation = ReadMetaLong(connection, transaction, AuthoritySchema.GenerationKey);
        return (Load(connection, transaction, AuthorityFreshness.Authoritative), generation);
    }

    // ── one record ────────────────────────────────────────────────────────────────────────────

    private async Task<AuthorityApplyOutcome> ReplicaWriteAsync(
        AuthorityRecordKey key, long version, bool removed, DateTimeOffset now, CancellationToken ct,
        Action<SqliteConnection, SqliteTransaction> apply)
    {
        if (version <= 0)
            return AuthorityApplyOutcome.Stale;

        await using SqliteConnection connection = await ConnectReplicaAsync(ct).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);

        // Take the write lock before reading what is held, so two deliveries of one record cannot both
        // find themselves newer.
        Execute(connection, transaction, "UPDATE authority_meta SET value = value WHERE key = $key;",
            ("$key", AuthoritySchema.GenerationKey));

        if (version <= Held(connection, transaction, key))
            return AuthorityApplyOutcome.Stale;

        try
        {
            apply(connection, transaction);
        }
        catch (SqliteException e) when (e.SqliteErrorCode == 19)
        {
            // A unique name or handle another record still holds here. The message that moves it is in
            // flight; this one is delivered again after it.
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
            return AuthorityApplyOutcome.Deferred;
        }

        if (!removed)
            Execute(connection, transaction, "DELETE FROM authority_tombstones WHERE record = $r;", ("$r", key.ToString()));

        RaiseVersion(connection, transaction, version);
        AdvanceGeneration(connection, transaction);

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return AuthorityApplyOutcome.Applied;
    }

    /// <summary>The version held for a record: its row's, or the version it was removed at.</summary>
    private static long Held(SqliteConnection connection, SqliteTransaction transaction, AuthorityRecordKey key)
    {
        long row = key.Kind switch
        {
            AuthorityRecordKind.Account => RowVersion(connection, transaction, "SELECT version FROM users WHERE user_id = $id;", key.Id),
            AuthorityRecordKind.Role => RowVersion(connection, transaction, "SELECT version FROM roles WHERE role_id = $id;", key.Id),
            AuthorityRecordKind.Permission => RowVersion(connection, transaction, "SELECT version FROM permissions WHERE permission_id = $id;", key.Id),
            AuthorityRecordKind.Assignment => RowVersion(connection, transaction, "SELECT version FROM assignments WHERE assignment_id = $id;", key.Id),
            _ => ReadMetaLong(connection, transaction, AuthoritySchema.CatalogVersionKey),
        };

        long tombstone = Scalar(connection, transaction, "SELECT version FROM authority_tombstones WHERE record = $r;",
            ("$r", key.ToString())) is long t ? t : 0;

        return Math.Max(row, tombstone);
    }

    private static long RowVersion(SqliteConnection connection, SqliteTransaction transaction, string sql, string id) =>
        Scalar(connection, transaction, sql, ("$id", id)) is long v ? v : 0;

    private static void PutAccount(SqliteConnection c, SqliteTransaction t, AccountRecord a)
    {
        // Parsed and written back so an unknown word from a newer anchor is stored as the fail-closed
        // value, never as a spelling this build would read some other way later.
        UserStatus status = UserStatuses.Parse(a.Status);
        Execute(c, t,
            """
            INSERT INTO users (user_id, username, username_key, display_name, origin, kind, status, created_utc, updated_utc, version)
            VALUES ($id, $name, $key, $display, $origin, $kind, $status, $created, $updated, $v)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username, username_key = excluded.username_key,
                display_name = excluded.display_name, origin = excluded.origin, kind = excluded.kind,
                status = excluded.status, created_utc = excluded.created_utc,
                updated_utc = excluded.updated_utc, version = excluded.version;
            """,
            ("$id", a.UserId), ("$name", a.Username), ("$key", Usernames.Key(a.Username)), ("$display", a.DisplayName),
            ("$origin", AccountWire.ToWire(AccountWire.ParseOrigin(a.Origin))),
            ("$kind", AccountWire.ToWire(AccountWire.ParseKind(a.Kind))),
            ("$status", UserStatuses.ToWire(status)),
            ("$created", UserWire.ToWire(a.Created)), ("$updated", UserWire.ToWire(a.Updated)), ("$v", a.Version));

        Execute(c, t, "DELETE FROM credentials WHERE user_id = $id;", ("$id", a.UserId));
        foreach (ReplicatedIdentity identity in a.Identities)
        {
            Execute(c, t,
                """
                INSERT INTO credentials (credential_id, user_id, kind, handle, secret, label, created_utc, last_used_utc)
                VALUES ($cid, $id, $kind, $handle, NULL, $label, $now, NULL);
                """,
                ("$cid", UserIds.NewCredentialId()), ("$id", a.UserId), ("$kind", CredentialKinds.Identity),
                ("$handle", identity.Handle), ("$label", (object?)identity.Label ?? DBNull.Value),
                ("$now", UserWire.ToWire(a.Updated)));
        }

        Execute(c, t, "DELETE FROM service_accounts WHERE user_id = $id;", ("$id", a.UserId));
        if (a.Service is { } service)
        {
            Execute(c, t, "INSERT INTO service_accounts (user_id, component, member) VALUES ($id, $c, $m);",
                ("$id", a.UserId), ("$c", service.Component), ("$m", service.Member));
        }

        Execute(c, t, "DELETE FROM service_requirements WHERE user_id = $id;", ("$id", a.UserId));
        foreach (RequirementRecord r in a.Requirements)
        {
            Execute(c, t,
                """
                INSERT INTO service_requirements
                    (user_id, action, scope_kind, why, state, grant_scope, decided_by, declared, version, updated_utc)
                VALUES ($id, $a, $kind, $why, $state, $grant, $by, $declared, $v, $now);
                """,
                ("$id", a.UserId), ("$a", r.Action), ("$kind", r.ScopeKind), ("$why", (object?)r.Why ?? DBNull.Value),
                ("$state", r.State), ("$grant", (object?)r.Grant ?? DBNull.Value), ("$by", (object?)r.DecidedBy ?? DBNull.Value),
                ("$declared", r.Declared ? 1 : 0), ("$v", a.Version), ("$now", UserWire.ToWire(a.Updated)));
        }
    }

    private static void PutRole(SqliteConnection c, SqliteTransaction t, RoleRecord r, DateTimeOffset now)
    {
        Execute(c, t,
            """
            INSERT INTO roles (role_id, name, name_key, kind, rank, version, updated_utc)
            VALUES ($id, $name, $key, $kind, $rank, $v, $now)
            ON CONFLICT(role_id) DO UPDATE SET
                name = excluded.name, name_key = excluded.name_key, kind = excluded.kind,
                rank = excluded.rank, version = excluded.version, updated_utc = excluded.updated_utc;
            """,
            ("$id", r.RoleId), ("$name", r.Name), ("$key", AuthorityRules.NameKey(r.Name)),
            ("$kind", RoleKinds.ToWire(RoleKinds.Parse(r.Kind))), ("$rank", r.Rank), ("$v", r.Version),
            ("$now", UserWire.ToWire(now)));

        Execute(c, t, "DELETE FROM role_permissions WHERE role_id = $id;", ("$id", r.RoleId));
        foreach (string permission in r.Permissions)
        {
            Execute(c, t, "INSERT INTO role_permissions (role_id, permission_id) VALUES ($id, $p);",
                ("$id", r.RoleId), ("$p", permission));
        }
    }

    private static void PutPermission(SqliteConnection c, SqliteTransaction t, PermissionRecord p, DateTimeOffset now)
    {
        Execute(c, t,
            """
            INSERT INTO permissions (permission_id, name, name_key, version, updated_utc)
            VALUES ($id, $name, $key, $v, $now)
            ON CONFLICT(permission_id) DO UPDATE SET
                name = excluded.name, name_key = excluded.name_key, version = excluded.version,
                updated_utc = excluded.updated_utc;
            """,
            ("$id", p.PermissionId), ("$name", p.Name), ("$key", AuthorityRules.NameKey(p.Name)), ("$v", p.Version),
            ("$now", UserWire.ToWire(now)));

        Execute(c, t, "DELETE FROM permission_actions WHERE permission_id = $id;", ("$id", p.PermissionId));
        foreach (string action in p.Actions)
        {
            Execute(c, t, "INSERT INTO permission_actions (permission_id, action) VALUES ($id, $a);",
                ("$id", p.PermissionId), ("$a", action));
        }
    }

    private static void PutAssignment(SqliteConnection c, SqliteTransaction t, AssignmentRecord a) =>
        Execute(c, t,
            """
            INSERT INTO assignments (assignment_id, user_id, role_id, scope, granted_by, version, created_utc)
            VALUES ($id, $user, $role, $scope, $by, $v, $created)
            ON CONFLICT(assignment_id) DO UPDATE SET
                user_id = excluded.user_id, role_id = excluded.role_id, scope = excluded.scope,
                granted_by = excluded.granted_by, version = excluded.version, created_utc = excluded.created_utc;
            """,
            ("$id", a.AssignmentId), ("$user", a.AccountId), ("$role", a.RoleId), ("$scope", a.Scope),
            ("$by", (object?)a.GrantedBy ?? DBNull.Value), ("$v", a.Version), ("$created", UserWire.ToWire(a.Created)));

    private static void PutCatalog(SqliteConnection c, SqliteTransaction t, CatalogRecord catalog)
    {
        Execute(c, t, "DELETE FROM catalog_actions;");
        foreach (CatalogActionRecord a in catalog.Actions)
        {
            Execute(c, t,
                """
                INSERT INTO catalog_actions (action, title, effect, scope_kind, self, version)
                VALUES ($a, $title, $effect, $scope, $self, $v);
                """,
                ("$a", a.Action), ("$title", a.Title), ("$effect", a.Effect), ("$scope", a.Scope),
                ("$self", a.Self ? 1 : 0), ("$v", catalog.Version));
        }

        Execute(c, t, "UPDATE authority_meta SET value = $v WHERE key = $key;",
            ("$key", AuthoritySchema.CatalogVersionKey), ("$v", catalog.Version));
    }

    /// <summary>
    /// Remove a record and what hangs off it here, and leave its tombstone. Assignments that named a
    /// removed account or role are removed with it at the same version: the anchor removed them too, and
    /// their own removals may still be in flight.
    /// </summary>
    private static void Delete(SqliteConnection c, SqliteTransaction t, AuthorityRecordKey key, long version)
    {
        List<string> orphaned = [];
        switch (key.Kind)
        {
            case AuthorityRecordKind.Account:
                Read(c, t, "SELECT assignment_id FROM assignments WHERE user_id = $id;", r => orphaned.Add(r.GetString(0)), ("$id", key.Id));
                foreach (string table in new[] { "credentials", "login_failures", "service_accounts", "service_requirements", "users" })
                    Execute(c, t, $"DELETE FROM {table} WHERE user_id = $id;", ("$id", key.Id));
                break;

            case AuthorityRecordKind.Role:
                Read(c, t, "SELECT assignment_id FROM assignments WHERE role_id = $id;", r => orphaned.Add(r.GetString(0)), ("$id", key.Id));
                Execute(c, t, "DELETE FROM role_permissions WHERE role_id = $id;", ("$id", key.Id));
                Execute(c, t, "DELETE FROM roles WHERE role_id = $id;", ("$id", key.Id));
                break;

            case AuthorityRecordKind.Permission:
                Execute(c, t, "DELETE FROM role_permissions WHERE permission_id = $id;", ("$id", key.Id));
                Execute(c, t, "DELETE FROM permission_actions WHERE permission_id = $id;", ("$id", key.Id));
                Execute(c, t, "DELETE FROM permissions WHERE permission_id = $id;", ("$id", key.Id));
                break;

            case AuthorityRecordKind.Assignment:
                Execute(c, t, "DELETE FROM assignments WHERE assignment_id = $id;", ("$id", key.Id));
                break;
        }

        Tombstone(c, t, key, version);
        foreach (string assignment in orphaned)
        {
            Execute(c, t, "DELETE FROM assignments WHERE assignment_id = $id;", ("$id", assignment));
            Tombstone(c, t, AuthorityRecordKey.Assignment(assignment), version);
        }
    }

    private static void Tombstone(SqliteConnection c, SqliteTransaction t, AuthorityRecordKey key, long version) =>
        Execute(c, t,
            """
            INSERT INTO authority_tombstones (record, version) VALUES ($r, $v)
            ON CONFLICT(record) DO UPDATE SET version = max(version, excluded.version);
            """,
            ("$r", key.ToString()), ("$v", version));

    private static void RaiseVersion(SqliteConnection c, SqliteTransaction t, long version)
    {
        if (version > ReadMetaLong(c, t, AuthoritySchema.AuthorityVersionKey))
        {
            Execute(c, t, "UPDATE authority_meta SET value = $v WHERE key = $key;",
                ("$key", AuthoritySchema.AuthorityVersionKey), ("$v", version));
        }
    }

    private static bool Confirm(SqliteConnection c, SqliteTransaction t, AuthorityCurrent current, DateTimeOffset now, bool requireVersion)
    {
        PutMeta(c, t, AuthoritySchema.BoundKey, Math.Max(0, current.StalenessBoundSeconds).ToString(CultureInfo.InvariantCulture));
        PutMeta(c, t, AuthoritySchema.MinimumContractKey, current.MinimumContractVersion.ToString(CultureInfo.InvariantCulture));

        if (requireVersion && ReadMetaLong(c, t, AuthoritySchema.AuthorityVersionKey) < current.Version)
            return false;

        // The moment it was sent, never later than now: a clock ahead of this one confirms nothing past
        // the present.
        DateTimeOffset at = current.Sent < now ? current.Sent : now;

        string? held = Scalar(c, t, "SELECT value FROM authority_meta WHERE key = $key;", ("$key", AuthoritySchema.ConfirmedKey)) as string;
        if (held is not null
            && DateTimeOffset.TryParse(held, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset before)
            && before >= at)
        {
            return true;
        }

        PutMeta(c, t, AuthoritySchema.ConfirmedKey, UserWire.ToWire(at));
        return true;
    }

    private static void PutMeta(SqliteConnection c, SqliteTransaction t, string key, string value) =>
        Execute(c, t,
            "INSERT INTO authority_meta (key, value) VALUES ($key, $value) ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            ("$key", key), ("$value", value));

    /// <summary>A connection for applying replicated records: foreign keys off, since they arrive in any order.</summary>
    private async Task<SqliteConnection> ConnectReplicaAsync(CancellationToken ct)
    {
        SqliteConnection connection = new(_replicaConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        ApplyPragmas(connection);
        return connection;
    }
}
