using System.Data;

using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;

namespace TheKrystalShip.KGSM.Auth.Users;

// The anchor's half of replication: what it owes the cluster, each record as it now stands, and the
// whole of it for a member building a replica from nothing.
public sealed partial class SqliteAuthorityStore
{
    /// <summary>What this store owes the cluster, one entry per record, oldest first.</summary>
    public async Task<IReadOnlyList<AuthorityAnnouncement>> PendingAnnouncementsAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);

        List<AuthorityAnnouncement> owed = [];
        Read(connection, null, "SELECT record, version, removed FROM authority_outbox ORDER BY version, record;", r =>
        {
            // A key this build does not know is left owed rather than guessed at.
            if (AuthorityRecordKey.Parse(r.GetString(0)) is { } key)
                owed.Add(new AuthorityAnnouncement(key, r.GetInt64(1), r.GetInt64(2) != 0));
        });

        return owed;
    }

    /// <summary>
    /// Forget what is owed for <paramref name="key"/> up to <paramref name="version"/>: the bus holds it.
    /// A later write to the same record owes it again at its own version, which this leaves alone.
    /// </summary>
    public async Task ClearAnnouncementAsync(AuthorityRecordKey key, long version, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        Execute(connection, null, "DELETE FROM authority_outbox WHERE record = $r AND version <= $v;",
            ("$r", key.ToString()), ("$v", version));
    }

    /// <summary>An account as it travels, or <see langword="null"/> when there is none.</summary>
    public async Task<AccountRecord?> ReadAccountRecordAsync(string userId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return ReadAccounts(connection, null, userId).FirstOrDefault();
    }

    /// <summary>A role as it travels, or <see langword="null"/> when there is none.</summary>
    public async Task<RoleRecord?> ReadRoleRecordAsync(string roleId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return ReadRoles(connection, null, roleId).FirstOrDefault();
    }

    /// <summary>A permission as it travels, or <see langword="null"/> when there is none.</summary>
    public async Task<PermissionRecord?> ReadPermissionRecordAsync(string permissionId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return ReadPermissions(connection, null, permissionId).FirstOrDefault();
    }

    /// <summary>An assignment as it travels, or <see langword="null"/> when there is none.</summary>
    public async Task<AssignmentRecord?> ReadAssignmentRecordAsync(string assignmentId, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return ReadAssignments(connection, null, assignmentId).FirstOrDefault();
    }

    /// <summary>The catalog as it travels.</summary>
    public async Task<CatalogRecord> ReadCatalogRecordAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return ReadCatalog(connection, null);
    }

    /// <summary>
    /// Everything that decides access, read in one transaction, for a member building its replica.
    /// </summary>
    /// <param name="stalenessBound">The bound the member holds itself to, carried in <see cref="AuthorityReplicaSnapshot.Current"/>.</param>
    /// <param name="now">When the snapshot is taken, which confirms the member current as of this moment.</param>
    public async Task<AuthorityReplicaSnapshot> ExportAsync(TimeSpan stalenessBound, DateTimeOffset now, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);

        long version = ReadVersion(connection, transaction);
        return new AuthorityReplicaSnapshot(
            version,
            ReadAccounts(connection, transaction, null),
            ReadRoles(connection, transaction, null),
            ReadPermissions(connection, transaction, null),
            ReadAssignments(connection, transaction, null),
            ReadCatalog(connection, transaction),
            new AuthorityCurrent(version, (int)stalenessBound.TotalSeconds, AccessContract.Version, now));
    }

    // ── records, as they travel ───────────────────────────────────────────────────────────────

    private static List<AccountRecord> ReadAccounts(SqliteConnection connection, SqliteTransaction? transaction, string? only)
    {
        string where = only is null ? "" : " WHERE u.user_id = $id";
        (string, object)[] args = only is null ? [] : [("$id", only)];

        Dictionary<string, List<ReplicatedIdentity>> identities = new(StringComparer.Ordinal);
        Read(connection, transaction,
            "SELECT c.user_id, c.kind, c.handle, c.label FROM credentials c JOIN users u ON u.user_id = c.user_id" + where
            + " ORDER BY c.handle;",
            r =>
            {
                bool password = CredentialKinds.Parse(r.GetString(1)) == CredentialKind.Password;
                Bucket(identities, r.GetString(0)).Add(
                    new ReplicatedIdentity(r.GetString(2), password || r.IsDBNull(3) ? null : r.GetString(3)));
            },
            args);

        Dictionary<string, List<RequirementRecord>> requirements = new(StringComparer.Ordinal);
        Read(connection, transaction,
            "SELECT q.user_id, q.action, q.scope_kind, q.why, q.state, q.grant_scope, q.decided_by, q.declared "
            + "FROM service_requirements q JOIN users u ON u.user_id = q.user_id" + where + " ORDER BY q.action;",
            r => Bucket(requirements, r.GetString(0)).Add(new RequirementRecord(
                r.GetString(1), r.GetString(2), r.IsDBNull(3) ? null : r.GetString(3), r.GetString(4),
                r.IsDBNull(5) ? null : r.GetString(5), r.IsDBNull(6) ? null : r.GetString(6), r.GetInt64(7) != 0)),
            args);

        List<AccountRecord> accounts = [];
        Read(connection, transaction,
            """
            SELECT u.user_id, u.username, u.display_name, u.origin, u.kind, u.status, u.created_utc, u.updated_utc,
                   u.version, s.component, s.member
            FROM users u LEFT JOIN service_accounts s ON s.user_id = u.user_id
            """ + where + " ORDER BY u.user_id;",
            r =>
            {
                string id = r.GetString(0);
                accounts.Add(new AccountRecord(
                    id, r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5),
                    UserWire.ReadTime(r.GetString(6)), UserWire.ReadTime(r.GetString(7)),
                    identities.GetValueOrDefault(id) ?? [],
                    r.IsDBNull(9) ? null : new ServiceRecord(r.GetString(9), r.GetString(10)),
                    requirements.GetValueOrDefault(id) ?? [],
                    r.GetInt64(8)));
            },
            args);

        return accounts;
    }

    private static List<RoleRecord> ReadRoles(SqliteConnection connection, SqliteTransaction? transaction, string? only)
    {
        string where = only is null ? "" : " WHERE role_id = $id";
        (string, object)[] args = only is null ? [] : [("$id", only)];

        Dictionary<string, List<string>> links = new(StringComparer.Ordinal);
        Read(connection, transaction, "SELECT role_id, permission_id FROM role_permissions" + where + " ORDER BY permission_id;",
            r => Bucket(links, r.GetString(0)).Add(r.GetString(1)), args);

        List<RoleRecord> roles = [];
        Read(connection, transaction, "SELECT role_id, name, kind, rank, version FROM roles" + where + " ORDER BY rank, role_id;",
            r => roles.Add(new RoleRecord(
                r.GetString(0), r.GetString(1), r.GetString(2), r.GetInt32(3),
                links.GetValueOrDefault(r.GetString(0)) ?? [], r.GetInt64(4))),
            args);

        return roles;
    }

    private static List<PermissionRecord> ReadPermissions(SqliteConnection connection, SqliteTransaction? transaction, string? only)
    {
        string where = only is null ? "" : " WHERE permission_id = $id";
        (string, object)[] args = only is null ? [] : [("$id", only)];

        Dictionary<string, List<string>> actions = new(StringComparer.Ordinal);
        Read(connection, transaction, "SELECT permission_id, action FROM permission_actions" + where + " ORDER BY action;",
            r => Bucket(actions, r.GetString(0)).Add(r.GetString(1)), args);

        List<PermissionRecord> permissions = [];
        Read(connection, transaction, "SELECT permission_id, name, version FROM permissions" + where + " ORDER BY permission_id;",
            r => permissions.Add(new PermissionRecord(
                r.GetString(0), r.GetString(1), actions.GetValueOrDefault(r.GetString(0)) ?? [], r.GetInt64(2))),
            args);

        return permissions;
    }

    private static List<AssignmentRecord> ReadAssignments(SqliteConnection connection, SqliteTransaction? transaction, string? only)
    {
        string where = only is null ? "" : " WHERE assignment_id = $id";
        (string, object)[] args = only is null ? [] : [("$id", only)];

        List<AssignmentRecord> assignments = [];
        Read(connection, transaction,
            "SELECT assignment_id, user_id, role_id, scope, granted_by, created_utc, version FROM assignments"
            + where + " ORDER BY assignment_id;",
            r => assignments.Add(new AssignmentRecord(
                r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3),
                r.IsDBNull(4) ? null : r.GetString(4), UserWire.ReadTime(r.GetString(5)), r.GetInt64(6))),
            args);

        return assignments;
    }

    private static CatalogRecord ReadCatalog(SqliteConnection connection, SqliteTransaction? transaction)
    {
        List<CatalogActionRecord> actions = [];
        Read(connection, transaction, "SELECT action, title, effect, scope_kind, self FROM catalog_actions ORDER BY action;",
            r => actions.Add(new CatalogActionRecord(
                r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetInt64(4) != 0)));

        return new CatalogRecord(actions, ReadMetaLong(connection, transaction, AuthoritySchema.CatalogVersionKey));
    }

    private static List<T> Bucket<T>(Dictionary<string, List<T>> map, string key)
    {
        if (!map.TryGetValue(key, out List<T>? bucket))
            map[key] = bucket = [];

        return bucket;
    }
}
