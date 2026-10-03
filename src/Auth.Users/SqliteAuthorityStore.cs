using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

using Microsoft.Data.Sqlite;

using TheKrystalShip.KGSM.Auth.Access;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>What happened to one record in an authority write.</summary>
public enum AuthorityChangeKind
{
    RoleChanged,
    RoleRemoved,
    PermissionChanged,
    PermissionRemoved,
    AssignmentGranted,
    AssignmentRevoked,
    RequirementApproved,
    RequirementRevoked,
    CatalogActionAdded,
    CatalogActionRemoved,
    AccountDisabled,
    AccountDeleted,
}

/// <summary>
/// One record an authority write changed, reported so the caller can journal and announce each change
/// on its own — a cascade included.
/// </summary>
/// <param name="Kind">What happened.</param>
/// <param name="Subject">The record: a role, permission, assignment or account id, or an action id.</param>
/// <param name="Name">The role, permission or account name at the time, for a reader.</param>
/// <param name="AccountId">The account an assignment or requirement belongs to.</param>
/// <param name="RoleId">The role an assignment is of.</param>
/// <param name="Scope">The scope an assignment or approved requirement holds.</param>
public sealed record AuthorityChange(
    AuthorityChangeKind Kind,
    string Subject,
    string? Name = null,
    string? AccountId = null,
    string? RoleId = null,
    string? Scope = null);

/// <summary>The result of an authority write.</summary>
/// <param name="Version">The authority version after the write.</param>
/// <param name="Changes">Every record it changed, in the order it changed them.</param>
/// <param name="CreatedId">The id of the role, permission or assignment it created, if it created one.</param>
public sealed record AuthorityWrite(long Version, IReadOnlyList<AuthorityChange> Changes, string? CreatedId = null);

/// <summary>A change was refused by <see cref="AuthorityRules"/>.</summary>
public sealed class AuthorityRefusedException(AuthorityRefusal refusal) : Exception(refusal.Message)
{
    /// <summary>Why.</summary>
    public AuthorityRefusal Refusal { get; } = refusal;
}

/// <summary>
/// A change was made against an authority version older than the current one.
/// </summary>
/// <remarks>
/// Two people editing roles at once never silently overwrite each other: the second is told what the
/// state is now and decides again.
/// </remarks>
public sealed class StaleAuthorityException(long expected, long current)
    : Exception($"The change was made against authority version {expected}; the current version is {current}.")
{
    /// <summary>The version the change named.</summary>
    public long Expected { get; } = expected;

    /// <summary>The version it would have been applied to.</summary>
    public long Current { get; } = current;
}

/// <summary>An action a component's manifest says it performs as its own service account.</summary>
/// <param name="Action">The other component's action id.</param>
/// <param name="ScopeKind">The scope kind it needs the action at.</param>
/// <param name="Why">Why, for the person reviewing it.</param>
public sealed record DeclaredRequirement(string Action, ScopeKind ScopeKind, string? Why);

/// <summary>The opaque ids the authority tables hand out, on the pattern of <see cref="UserIds"/>.</summary>
public static class AuthorityIds
{
    /// <summary>A fresh role id.</summary>
    public static string NewRoleId() => "role_" + RandomHex();

    /// <summary>A fresh permission id.</summary>
    public static string NewPermissionId() => "prm_" + RandomHex();

    /// <summary>A fresh assignment id.</summary>
    public static string NewAssignmentId() => "asg_" + RandomHex();

    private static string RandomHex() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}

/// <summary>
/// Who may do what, stored in the account store at schema version 2, and the only writer of it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every write is checked and applied in one transaction.</b> The snapshot the rules read is loaded
/// under the write lock, the change is checked against it by <see cref="AuthorityRules"/>, and only
/// then applied — so the answer to "may this caller make this change" is the answer for the state it
/// is applied to, not one a second writer has since moved.
/// </para>
/// <para>
/// <b>Every write names the version it was made against</b> and is refused with
/// <see cref="StaleAuthorityException"/> when the store has moved past it. A write that succeeds
/// advances the authority version by one and stamps every row it touched with the new one.
/// </para>
/// <para>
/// <b>A cascade is reported one change at a time.</b> Deleting a role deletes its assignments through
/// the foreign keys, but the store reads them first and reports each one, so the journal carries every
/// assignment that ended rather than a role deletion that implied them.
/// </para>
/// <para>
/// The writes that belong to the system rather than to a person — the catalog, service accounts and
/// their declared requirements, and Owner granted from the host's shell — bypass the rules, and are
/// never reachable from a request.
/// </para>
/// <para>
/// <b>Every write owes the cluster what it changed, in the same transaction.</b> Each record a write
/// stamped with the new version, and each one it removed, is filed in <c>authority_outbox</c> before the
/// write commits, so a change can never exist without its announcement being owed.
/// </para>
/// </remarks>
public sealed partial class SqliteAuthorityStore
{
    private readonly string _connectionString;
    private readonly string _replicaConnectionString;
    private readonly TimeSpan _busyTimeout;

    /// <summary>
    /// Open the store at <paramref name="options"/>, creating a version 2 file when there is none.
    /// </summary>
    /// <exception cref="UserStoreSchemaException">The file is at another schema version.</exception>
    public SqliteAuthorityStore(UserStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _busyTimeout = options.BusyTimeout;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = options.Path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            ForeignKeys = true,
            Pooling = true,
            DefaultTimeout = (int)Math.Ceiling(options.BusyTimeout.TotalSeconds),
        }.ToString();

        // Unpooled, so a connection with foreign keys off never returns to a pool the anchor's own
        // writes draw from.
        _replicaConnectionString = new SqliteConnectionStringBuilder(_connectionString)
        {
            ForeignKeys = false,
            Pooling = false,
        }.ToString();

        string? directory = Path.GetDirectoryName(Path.GetFullPath(options.Path));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        Initialize(options.Path);
    }

    // ── schema ────────────────────────────────────────────────────────────────────────────────

    private void Initialize(string path)
    {
        using SqliteConnection connection = Connect();

        if (!OperatingSystem.IsWindows() && File.Exists(path))
        {
            const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            if (File.GetUnixFileMode(path) != ownerOnly)
                File.SetUnixFileMode(path, ownerOnly);
        }

        Execute(connection, null, "PRAGMA journal_mode=WAL;");

        using SqliteTransaction transaction = connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);

        bool fresh = Scalar(connection, transaction,
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta';") is 0L;

        string? found = fresh
            ? null
            : Scalar(connection, transaction, "SELECT value FROM schema_meta WHERE key = $key;",
                ("$key", UserSchema.VersionKey)) as string;

        if (found is null)
        {
            Execute(connection, transaction, AuthoritySchema.CreateAccounts);
            Execute(connection, transaction, AuthoritySchema.CreateAuthority);
            SeedBuiltIns(connection, transaction, UserWire.ToWire(DateTimeOffset.UtcNow));
            Execute(connection, transaction,
                "INSERT INTO schema_meta (key, value) VALUES ($key, $value);",
                ("$key", UserSchema.VersionKey),
                ("$value", AuthoritySchema.Version.ToString(CultureInfo.InvariantCulture)));
        }
        else if (found != AuthoritySchema.Version.ToString(CultureInfo.InvariantCulture))
        {
            throw new UserStoreSchemaException(
                $"The account store at '{path}' is at schema version {found}; the authority store reads " +
                $"version {AuthoritySchema.Version} and nothing else.");
        }

        transaction.Commit();
    }

    /// <summary>Create the two built-in roles and the authority version, where they are not already.</summary>
    internal static void SeedBuiltIns(SqliteConnection connection, SqliteTransaction transaction, string now) =>
        Execute(connection, transaction, AuthoritySchema.SeedBuiltInRoles,
            ("$owner_id", BuiltInRoles.OwnerId),
            ("$owner_name", BuiltInRoles.OwnerName),
            ("$owner_key", AuthorityRules.NameKey(BuiltInRoles.OwnerName)),
            ("$owner_rank", RoleRanks.Owner),
            ("$everyone_id", BuiltInRoles.EveryoneId),
            ("$everyone_name", BuiltInRoles.EveryoneName),
            ("$everyone_key", AuthorityRules.NameKey(BuiltInRoles.EveryoneName)),
            ("$everyone_rank", RoleRanks.Everyone),
            ("$now", now));

    // ── reads ─────────────────────────────────────────────────────────────────────────────────

    /// <summary>The current authority version.</summary>
    public async Task<long> VersionAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return ReadVersion(connection, null);
    }

    /// <summary>
    /// Everything that decides access, as one snapshot. The anchor's own store is the authority and
    /// is always current; a replica passes the freshness it last confirmed.
    /// </summary>
    public async Task<AuthoritySnapshot> LoadAsync(AuthorityFreshness? freshness = null, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);

        return Load(connection, transaction, freshness ?? AuthorityFreshness.Authoritative);
    }

    /// <summary>The account a username names, or <see langword="null"/>.</summary>
    public async Task<AccessAccount?> FindAccountAsync(string username, CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        string? id = Scalar(connection, null, "SELECT user_id FROM users WHERE username_key = $key;",
            ("$key", Usernames.Key(username))) as string;

        if (id is null)
            return null;

        return Load(connection, null, AuthorityFreshness.Authoritative).Accounts.GetValueOrDefault(id);
    }

    private static AuthoritySnapshot Load(SqliteConnection connection, SqliteTransaction? transaction, AuthorityFreshness freshness)
    {
        long version = ReadVersion(connection, transaction);

        List<AccessAccount> accounts = [];
        Read(connection, transaction,
            """
            SELECT u.user_id, u.username, u.kind, u.status, s.component, s.member
            FROM users u LEFT JOIN service_accounts s ON s.user_id = u.user_id;
            """,
            r => accounts.Add(new AccessAccount(
                r.GetString(0), r.GetString(1), AccountWire.ParseKind(r.GetString(2)),
                ToAccessStatus(UserStatuses.Parse(r.GetString(3))),
                r.IsDBNull(4) ? null : new ServiceIdentity(r.GetString(4), r.GetString(5)))));

        List<CatalogAction> catalog = [];
        Read(connection, transaction, "SELECT action, title, effect, scope_kind, self FROM catalog_actions;",
            r => catalog.Add(new CatalogAction(
                r.GetString(0), r.GetString(1), ActionEffects.Parse(r.GetString(2)),
                ScopeKinds.Parse(r.GetString(3)), r.GetInt64(4) != 0)));

        Dictionary<string, HashSet<string>> permissionActions = new(StringComparer.Ordinal);
        Read(connection, transaction, "SELECT permission_id, action FROM permission_actions;",
            r => Bucket(permissionActions, r.GetString(0)).Add(r.GetString(1)));

        List<Permission> permissions = [];
        Read(connection, transaction, "SELECT permission_id, name FROM permissions;",
            r => permissions.Add(new Permission(
                r.GetString(0), r.GetString(1), permissionActions.GetValueOrDefault(r.GetString(0)) ?? [])));

        Dictionary<string, HashSet<string>> rolePermissions = new(StringComparer.Ordinal);
        Read(connection, transaction, "SELECT role_id, permission_id FROM role_permissions;",
            r => Bucket(rolePermissions, r.GetString(0)).Add(r.GetString(1)));

        List<Role> roles = [];
        Read(connection, transaction, "SELECT role_id, name, kind, rank FROM roles;",
            r => roles.Add(new Role(
                r.GetString(0), r.GetString(1), RoleKinds.Parse(r.GetString(2)), r.GetInt32(3),
                rolePermissions.GetValueOrDefault(r.GetString(0)) ?? [])));

        // A scope that does not parse grants nothing: the row is left out rather than guessed at.
        List<Assignment> assignments = [];
        Read(connection, transaction, "SELECT assignment_id, user_id, role_id, scope FROM assignments;",
            r =>
            {
                if (AccessScope.TryParse(r.GetString(3), out AccessScope? scope))
                    assignments.Add(new Assignment(r.GetString(0), r.GetString(1), r.GetString(2), scope.Value));
            });

        List<ServiceRequirement> requirements = [];
        Read(connection, transaction,
            "SELECT user_id, action, scope_kind, why, state, grant_scope, decided_by, declared FROM service_requirements;",
            r => requirements.Add(new ServiceRequirement(
                r.GetString(0), r.GetString(1), ScopeKinds.Parse(r.GetString(2)),
                r.IsDBNull(3) ? null : r.GetString(3),
                RequirementStates.Parse(r.GetString(4)),
                !r.IsDBNull(5) && AccessScope.TryParse(r.GetString(5), out AccessScope? grant) ? grant : null,
                r.IsDBNull(6) ? null : r.GetString(6),
                r.GetInt64(7) != 0)));

        return new AuthoritySnapshot(version, accounts, catalog, permissions, roles, assignments, requirements, freshness);
    }

    private static AccountStatus ToAccessStatus(UserStatus status) => status switch
    {
        UserStatus.Active => AccountStatus.Active,
        UserStatus.Pending => AccountStatus.Pending,
        _ => AccountStatus.Disabled,
    };

    // ── a person's changes ────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Make <paramref name="edit"/> as <paramref name="actorId"/>, against
    /// <paramref name="expectedVersion"/>.
    /// </summary>
    /// <exception cref="StaleAuthorityException">The store has moved past <paramref name="expectedVersion"/>.</exception>
    /// <exception cref="AuthorityRefusedException">The rules refuse the change.</exception>
    public Task<AuthorityWrite> ApplyAsync(
        string actorId, AuthorityEdit edit, long expectedVersion, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(edit);

        return WriteAsync(expectedVersion, now, ct, (w, snapshot) =>
        {
            if (AuthorityRules.Check(snapshot, actorId, edit) is { } refusal)
                throw new AuthorityRefusedException(refusal);

            return Apply(w, snapshot, actorId, edit);
        });
    }

    private static string? Apply(Writer w, AuthoritySnapshot s, string actorId, AuthorityEdit edit)
    {
        switch (edit)
        {
            case CreateRole e:
            {
                int rank = AuthorityRules.CreationRank(s, actorId);
                ShiftCustomRanks(w, s, from: rank, by: 1);
                string id = AuthorityIds.NewRoleId();
                w.Execute(
                    """
                    INSERT INTO roles (role_id, name, name_key, kind, rank, version, updated_utc)
                    VALUES ($id, $name, $key, 'custom', $rank, $v, $now);
                    """,
                    ("$id", id), ("$name", e.Name.Trim()), ("$key", AuthorityRules.NameKey(e.Name)), ("$rank", rank));
                w.Changed(AuthorityChangeKind.RoleChanged, id, e.Name.Trim());
                return id;
            }

            case RenameRole e:
                w.Execute("UPDATE roles SET name = $name, name_key = $key, version = $v, updated_utc = $now WHERE role_id = $id;",
                    ("$id", e.RoleId), ("$name", e.Name.Trim()), ("$key", AuthorityRules.NameKey(e.Name)));
                w.Changed(AuthorityChangeKind.RoleChanged, e.RoleId, e.Name.Trim());
                return null;

            case DeleteRole e:
            {
                Role role = s.Roles[e.RoleId];
                foreach (Assignment a in s.Assignments.Where(a => a.RoleId == e.RoleId))
                    w.Changed(AuthorityChangeKind.AssignmentRevoked, a.AssignmentId, role.Name, a.AccountId, a.RoleId, a.Scope.ToString());

                w.Execute("DELETE FROM roles WHERE role_id = $id;", ("$id", e.RoleId));
                ShiftCustomRanks(w, s, from: role.Rank + 1, by: -1);
                w.Changed(AuthorityChangeKind.RoleRemoved, e.RoleId, role.Name);
                return null;
            }

            case RankRole e:
            {
                List<Role> order = [.. s.Roles.Values.Where(r => r.Kind == RoleKind.Custom).OrderBy(r => r.Rank)];
                Role moved = order.Single(r => r.RoleId == e.RoleId);
                order.Remove(moved);
                order.Insert(e.Rank - RoleRanks.FirstCustom, moved);

                for (int i = 0; i < order.Count; i++)
                {
                    int rank = RoleRanks.FirstCustom + i;
                    if (order[i].Rank == rank)
                        continue;

                    w.Execute("UPDATE roles SET rank = $rank, version = $v, updated_utc = $now WHERE role_id = $id;",
                        ("$id", order[i].RoleId), ("$rank", rank));
                    w.Changed(AuthorityChangeKind.RoleChanged, order[i].RoleId, order[i].Name);
                }

                return null;
            }

            case SetRolePermissions e:
            {
                w.Execute("DELETE FROM role_permissions WHERE role_id = $id;", ("$id", e.RoleId));
                foreach (string permission in e.PermissionIds)
                {
                    w.Execute("INSERT INTO role_permissions (role_id, permission_id) VALUES ($id, $p);",
                        ("$id", e.RoleId), ("$p", permission));
                }

                w.Execute("UPDATE roles SET version = $v, updated_utc = $now WHERE role_id = $id;", ("$id", e.RoleId));
                w.Changed(AuthorityChangeKind.RoleChanged, e.RoleId, s.Roles[e.RoleId].Name);
                return null;
            }

            case CreatePermission e:
            {
                string id = AuthorityIds.NewPermissionId();
                w.Execute(
                    """
                    INSERT INTO permissions (permission_id, name, name_key, version, updated_utc)
                    VALUES ($id, $name, $key, $v, $now);
                    """,
                    ("$id", id), ("$name", e.Name.Trim()), ("$key", AuthorityRules.NameKey(e.Name)));
                w.Changed(AuthorityChangeKind.PermissionChanged, id, e.Name.Trim());
                return id;
            }

            case RenamePermission e:
                w.Execute("UPDATE permissions SET name = $name, name_key = $key, version = $v, updated_utc = $now WHERE permission_id = $id;",
                    ("$id", e.PermissionId), ("$name", e.Name.Trim()), ("$key", AuthorityRules.NameKey(e.Name)));
                w.Changed(AuthorityChangeKind.PermissionChanged, e.PermissionId, e.Name.Trim());
                return null;

            case DeletePermission e:
            {
                Permission permission = s.Permissions[e.PermissionId];
                List<Role> holding = [.. s.RolesHolding(e.PermissionId)];

                w.Execute("DELETE FROM permissions WHERE permission_id = $id;", ("$id", e.PermissionId));
                foreach (Role role in holding)
                {
                    w.Execute("UPDATE roles SET version = $v, updated_utc = $now WHERE role_id = $id;", ("$id", role.RoleId));
                    w.Changed(AuthorityChangeKind.RoleChanged, role.RoleId, role.Name);
                }

                w.Changed(AuthorityChangeKind.PermissionRemoved, e.PermissionId, permission.Name);
                return null;
            }

            case SetPermissionActions e:
            {
                w.Execute("DELETE FROM permission_actions WHERE permission_id = $id;", ("$id", e.PermissionId));
                foreach (string action in e.Actions)
                {
                    w.Execute("INSERT INTO permission_actions (permission_id, action) VALUES ($id, $a);",
                        ("$id", e.PermissionId), ("$a", action));
                }

                w.Execute("UPDATE permissions SET version = $v, updated_utc = $now WHERE permission_id = $id;", ("$id", e.PermissionId));
                w.Changed(AuthorityChangeKind.PermissionChanged, e.PermissionId, s.Permissions[e.PermissionId].Name);
                return null;
            }

            case Assign e:
                return InsertAssignment(w, e.AccountId, e.RoleId, e.Scope, grantedBy: actorId, s.Roles[e.RoleId].Name);

            case Revoke e:
            {
                Assignment a = s.Assignments.Single(a => a.AssignmentId == e.AssignmentId);
                w.Execute("DELETE FROM assignments WHERE assignment_id = $id;", ("$id", e.AssignmentId));
                w.Changed(AuthorityChangeKind.AssignmentRevoked, a.AssignmentId, s.Roles[a.RoleId].Name, a.AccountId, a.RoleId, a.Scope.ToString());
                return null;
            }

            case ApproveRequirement e:
                SetRequirement(w, e.AccountId, e.Action, RequirementState.Approved, e.Scope, actorId);
                return null;

            case NarrowRequirement e:
                SetRequirement(w, e.AccountId, e.Action, RequirementState.Approved, e.Scope, actorId);
                return null;

            case RevokeRequirement e:
                SetRequirement(w, e.AccountId, e.Action, RequirementState.Revoked, null, actorId);
                return null;

            case DisableAccount e:
                w.Execute("UPDATE users SET status = $status, version = $v, updated_utc = $now WHERE user_id = $id;",
                    ("$id", e.AccountId), ("$status", UserStatuses.Disabled));
                w.Changed(AuthorityChangeKind.AccountDisabled, e.AccountId, s.Accounts[e.AccountId].Name, e.AccountId);
                return null;

            case DeleteAccount e:
                DeleteAccountRow(w, s, e.AccountId);
                return null;

            default:
                throw new ArgumentOutOfRangeException(nameof(edit), edit.GetType().Name, "Not an authority edit.");
        }
    }

    private static void ShiftCustomRanks(Writer w, AuthoritySnapshot s, int from, int by)
    {
        foreach (Role role in s.Roles.Values.Where(r => r.Kind == RoleKind.Custom && r.Rank >= from))
        {
            w.Execute("UPDATE roles SET rank = $rank, version = $v, updated_utc = $now WHERE role_id = $id;",
                ("$id", role.RoleId), ("$rank", role.Rank + by));
            w.Changed(AuthorityChangeKind.RoleChanged, role.RoleId, role.Name);
        }
    }

    private static string InsertAssignment(Writer w, string accountId, string roleId, AccessScope scope, string grantedBy, string roleName)
    {
        string id = AuthorityIds.NewAssignmentId();
        w.Execute(
            """
            INSERT INTO assignments (assignment_id, user_id, role_id, scope, granted_by, version, created_utc)
            VALUES ($id, $user, $role, $scope, $by, $v, $now);
            """,
            ("$id", id), ("$user", accountId), ("$role", roleId), ("$scope", scope.ToString()), ("$by", grantedBy));
        w.Changed(AuthorityChangeKind.AssignmentGranted, id, roleName, accountId, roleId, scope.ToString());
        return id;
    }

    private static void SetRequirement(
        Writer w, string accountId, string action, RequirementState state, AccessScope? grant, string decidedBy)
    {
        w.Execute(
            """
            UPDATE service_requirements
            SET state = $state, grant_scope = $grant, decided_by = $by, version = $v, updated_utc = $now
            WHERE user_id = $id AND action = $action;
            """,
            ("$id", accountId), ("$action", action), ("$state", RequirementStates.ToWire(state)),
            ("$grant", (object?)grant?.ToString() ?? DBNull.Value), ("$by", decidedBy));

        w.Changed(
            state == RequirementState.Approved ? AuthorityChangeKind.RequirementApproved : AuthorityChangeKind.RequirementRevoked,
            action, accountId: accountId, scope: grant?.ToString());
    }

    private static void DeleteAccountRow(Writer w, AuthoritySnapshot s, string accountId)
    {
        foreach (Assignment a in s.AssignmentsOf(accountId))
            w.Changed(AuthorityChangeKind.AssignmentRevoked, a.AssignmentId, s.Roles.GetValueOrDefault(a.RoleId)?.Name, a.AccountId, a.RoleId, a.Scope.ToString());

        w.Execute("DELETE FROM users WHERE user_id = $id;", ("$id", accountId));
        w.Changed(AuthorityChangeKind.AccountDeleted, accountId, s.Accounts.GetValueOrDefault(accountId)?.Name, accountId);
    }

    // ── the system's changes ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Assign Owner to <paramref name="username"/> from the host's shell, with none of the rules.
    /// </summary>
    /// <remarks>
    /// Adds no power: whoever can run it already holds this file. It is the recovery path for a
    /// cluster whose every Owner has lost every credential, and it is recorded like any other grant,
    /// under <paramref name="actor"/>. An account already holding Owner is left as it is and the write
    /// changes nothing.
    /// </remarks>
    /// <exception cref="InvalidOperationException">No such account, or a service account.</exception>
    public Task<AuthorityWrite> GrantOwnerLocallyAsync(string username, string actor, DateTimeOffset now, CancellationToken ct = default) =>
        WriteAsync(expectedVersion: null, now, ct, (w, s) =>
        {
            AccessAccount account = s.Accounts.Values.FirstOrDefault(a => Usernames.Key(a.Name) == Usernames.Key(username))
                ?? throw new InvalidOperationException($"There is no account named '{username}'.");

            if (account.Kind != AccountKind.Person)
                throw new InvalidOperationException($"'{account.Name}' is a service account; Owner is held by people.");

            return s.IsOwner(account.AccountId)
                ? null
                : InsertAssignment(w, account.AccountId, BuiltInRoles.OwnerId, AccessScope.Cluster, actor, BuiltInRoles.OwnerName);
        });

    /// <summary>
    /// Replace the catalog with <paramref name="actions"/>: the union of every roster member's last
    /// report. An action no longer declared leaves every permission that held it.
    /// </summary>
    public Task<AuthorityWrite> ReplaceCatalogAsync(IReadOnlyCollection<CatalogAction> actions, DateTimeOffset now, CancellationToken ct = default) =>
        WriteAsync(expectedVersion: null, now, ct, (w, s) =>
        {
            ReplaceCatalog(w, s, actions);
            return null;
        });

    /// <summary>
    /// Make the catalog <paramref name="actions"/>, writing nothing when it already is.
    /// </summary>
    /// <remarks>
    /// Each action that arrives or leaves is reported on its own. One that leaves is taken out of every
    /// permission holding it, and each such permission is reported changed.
    /// </remarks>
    private static void ReplaceCatalog(Writer w, AuthoritySnapshot s, IReadOnlyCollection<CatalogAction> actions)
    {
        Dictionary<string, CatalogAction> next = actions.ToDictionary(a => a.Id, StringComparer.Ordinal);

        bool same = next.Count == s.Catalog.Count
                    && next.All(a => s.Catalog.TryGetValue(a.Key, out CatalogAction? held) && held == a.Value);
        if (same)
            return;

        foreach (Permission permission in s.Permissions.Values)
        {
            string[] dead = [.. permission.Actions.Where(a => !next.ContainsKey(a))];
            if (dead.Length == 0)
                continue;

            foreach (string action in dead)
            {
                w.Execute("DELETE FROM permission_actions WHERE permission_id = $id AND action = $a;",
                    ("$id", permission.PermissionId), ("$a", action));
            }

            w.Execute("UPDATE permissions SET version = $v, updated_utc = $now WHERE permission_id = $id;",
                ("$id", permission.PermissionId));
            w.Changed(AuthorityChangeKind.PermissionChanged, permission.PermissionId, permission.Name);
        }

        w.Execute("DELETE FROM catalog_actions;");
        w.Execute("UPDATE authority_meta SET value = $v WHERE key = $key;", ("$key", AuthoritySchema.CatalogVersionKey));
        foreach (CatalogAction action in next.Values.OrderBy(a => a.Id, StringComparer.Ordinal))
        {
            w.Execute(
                """
                INSERT INTO catalog_actions (action, title, effect, scope_kind, self, version)
                VALUES ($a, $title, $effect, $scope, $self, $v);
                """,
                ("$a", action.Id), ("$title", action.Title), ("$effect", ActionEffects.ToWire(action.Effect)),
                ("$scope", ScopeKinds.ToWire(action.Scope)), ("$self", action.Self ? 1 : 0));
        }

        foreach (string arrived in next.Keys.Where(id => !s.Catalog.ContainsKey(id)).Order(StringComparer.Ordinal))
            w.Changed(AuthorityChangeKind.CatalogActionAdded, arrived);

        foreach (string left in s.Catalog.Keys.Where(id => !next.ContainsKey(id)).Order(StringComparer.Ordinal))
            w.Changed(AuthorityChangeKind.CatalogActionRemoved, left);
    }

    // ── members' reports ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Record what <paramref name="member"/> reports it is responsible for, and bring the catalog and
    /// that member's service accounts in line with it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The report replaces the member's previous one. The catalog becomes the union of every stored
    /// report; each component requiring something gets its service account and its requirements; a
    /// component the member no longer reports has its service account forgotten.
    /// </para>
    /// <para>
    /// A report identical to the last one writes nothing and leaves the authority version alone, so the
    /// periodic re-report every member sends costs the cluster nothing.
    /// </para>
    /// </remarks>
    public Task<AuthorityWrite> RecordMemberReportAsync(
        string member, MemberCatalogReport report, DateTimeOffset now, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(member);
        ArgumentNullException.ThrowIfNull(report);

        return WriteAsync(expectedVersion: null, now, ct, (w, s) =>
        {
            Dictionary<string, MemberCatalogReport> reports = ReadReports(w);

            // Delivery is not ordered: a report read before the one held arrived late, and taking it
            // would put back what the member has since stopped declaring.
            if (reports.TryGetValue(member, out MemberCatalogReport? held) && held.Sequence > report.Sequence)
                return null;

            string json = JsonSerializer.Serialize(report, AccessJsonContext.Default.MemberCatalogReport);
            w.Record(
                """
                INSERT INTO member_reports (member, report, received_utc) VALUES ($m, $r, $now)
                ON CONFLICT(member) DO UPDATE SET report = excluded.report, received_utc = excluded.received_utc;
                """,
                ("$m", member), ("$r", json));

            reports[member] = report;
            ReplaceCatalog(w, s, [.. CatalogUnion.Of(reports).Select(e => e.Action)]);

            HashSet<string> components = new(StringComparer.Ordinal);
            foreach (ActionManifest manifest in report.Manifests)
            {
                components.Add(manifest.Component);
                DeclareRequirements(w, s, new ServiceIdentity(manifest.Component, member), report.Anchor, Requirements(manifest));
            }

            foreach (AccessAccount account in s.Accounts.Values.Where(a =>
                         a.Service is { } svc && svc.Member == member && !components.Contains(svc.Component)))
            {
                DeleteAccountRow(w, s, account.AccountId);
            }

            return null;
        });
    }

    /// <summary>
    /// Forget everything <paramref name="member"/> reported: it has been removed from the cluster.
    /// </summary>
    /// <remarks>
    /// Every action only it declared leaves the catalog and every permission, and every service account
    /// belonging to it is forgotten. A member that is merely offline keeps its report; only removal
    /// comes here.
    /// </remarks>
    public Task<AuthorityWrite> ForgetMemberAsync(string member, DateTimeOffset now, CancellationToken ct = default) =>
        WriteAsync(expectedVersion: null, now, ct, (w, s) =>
        {
            Dictionary<string, MemberCatalogReport> reports = ReadReports(w);
            if (reports.Remove(member))
                w.Record("DELETE FROM member_reports WHERE member = $m;", ("$m", member));

            ReplaceCatalog(w, s, [.. CatalogUnion.Of(reports).Select(e => e.Action)]);

            foreach (AccessAccount account in s.Accounts.Values.Where(a => a.Service?.Member == member))
                DeleteAccountRow(w, s, account.AccountId);

            return null;
        });

    /// <summary>
    /// Drop every assignment naming one install of an instance on <paramref name="node"/>: the install
    /// with <paramref name="nonce"/> is gone.
    /// </summary>
    /// <remarks>
    /// Matched on the nonce, so a message arriving after the instance was installed again under the same
    /// name takes nothing from the new install.
    /// </remarks>
    public Task<AuthorityWrite> RemoveInstanceAsync(string node, string nonce, DateTimeOffset now, CancellationToken ct = default) =>
        WriteAsync(expectedVersion: null, now, ct, (w, s) =>
        {
            foreach (Assignment a in s.Assignments.Where(a =>
                         a.Scope.Kind == ScopeKind.Instance && a.Scope.Node == node && a.Scope.Nonce == nonce))
            {
                w.Execute("DELETE FROM assignments WHERE assignment_id = $id;", ("$id", a.AssignmentId));
                w.Changed(AuthorityChangeKind.AssignmentRevoked, a.AssignmentId, s.Roles.GetValueOrDefault(a.RoleId)?.Name,
                    a.AccountId, a.RoleId, a.Scope.ToString());
            }

            return null;
        });

    /// <summary>The members whose reports the catalog is built from.</summary>
    public async Task<IReadOnlyList<string>> ReportingMembersAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        List<string> members = [];
        Read(connection, null, "SELECT member FROM member_reports ORDER BY member;", r => members.Add(r.GetString(0)));
        return members;
    }

    /// <summary>The catalog, with every member and component version declaring each action.</summary>
    public async Task<IReadOnlyList<CatalogEntry>> CatalogAsync(CancellationToken ct = default)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        return CatalogUnion.Of(ReadReports(connection, null));
    }

    private static Dictionary<string, MemberCatalogReport> ReadReports(Writer w) => w.Query(ReadReports);

    /// <summary>Every stored report. One that no longer parses is left out, as if never reported.</summary>
    private static Dictionary<string, MemberCatalogReport> ReadReports(SqliteConnection connection, SqliteTransaction? transaction)
    {
        Dictionary<string, MemberCatalogReport> reports = new(StringComparer.Ordinal);
        Read(connection, transaction, "SELECT member, report FROM member_reports;", r =>
        {
            try
            {
                if (JsonSerializer.Deserialize(r.GetString(1), AccessJsonContext.Default.MemberCatalogReport) is { } report)
                    reports[r.GetString(0)] = report;
            }
            catch (JsonException)
            {
            }
        });

        return reports;
    }

    private static IReadOnlyCollection<DeclaredRequirement> Requirements(ActionManifest manifest) =>
        [.. (manifest.Requires ?? [])
            .Where(r => ActionIds.IsValid(r.Action))
            .Select(r => new DeclaredRequirement(r.Action, ScopeKinds.Parse(r.Scope), r.Why))];

    /// <summary>
    /// Record what a component on a member now requires, creating its service account the first time
    /// it requires anything.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A requirement the account has never held is approved automatically at the member's own scope —
    /// the node for a component on a node, the cluster for an anchor — except an <c>auth:*</c> one,
    /// which waits for an Owner. A requirement the account has held before keeps whatever it was left
    /// at, so an Owner's revocation or narrowing sticks for the account's life. One the manifest no
    /// longer lists stops granting until it is listed again.
    /// </para>
    /// <para>Each automatic approval is reported, so it is journaled and announced.</para>
    /// </remarks>
    public Task<AuthorityWrite> DeclareRequirementsAsync(
        ServiceIdentity service, bool anchor, IReadOnlyCollection<DeclaredRequirement> requires, DateTimeOffset now,
        CancellationToken ct = default) =>
        WriteAsync(expectedVersion: null, now, ct, (w, s) => DeclareRequirements(w, s, service, anchor, requires));

    /// <summary>
    /// The body of <see cref="DeclareRequirementsAsync"/>: writes only what differs from what is held.
    /// Returns the service account's id, or <see langword="null"/> when there is none and nothing was
    /// required.
    /// </summary>
    private static string? DeclareRequirements(
        Writer w, AuthoritySnapshot s, ServiceIdentity service, bool anchor, IReadOnlyCollection<DeclaredRequirement> requires)
    {
        string? accountId = ServiceAccountId(s, service);
        if (accountId is null)
        {
            if (requires.Count == 0)
                return null;

            accountId = CreateServiceAccount(w, service);
        }

        Dictionary<string, ServiceRequirement> held = s.RequirementsOf(accountId).ToDictionary(r => r.Action, StringComparer.Ordinal);
        HashSet<string> listed = requires.Select(r => r.Action).ToHashSet(StringComparer.Ordinal);

        foreach (ServiceRequirement stale in held.Values.Where(r => r.Declared && !listed.Contains(r.Action)))
        {
            w.Execute("UPDATE service_requirements SET declared = 0, version = $v, updated_utc = $now WHERE user_id = $id AND action = $a;",
                ("$id", accountId), ("$a", stale.Action));
        }

        AccessScope memberScope = service.MemberScope(anchor);
        foreach (DeclaredRequirement requirement in requires)
        {
            if (!ActionIds.IsValid(requirement.Action))
                continue;

            if (held.TryGetValue(requirement.Action, out ServiceRequirement? existing))
            {
                if (existing.Declared && existing.ScopeKind == requirement.ScopeKind && existing.Why == requirement.Why)
                    continue;

                w.Execute(
                    """
                    UPDATE service_requirements
                    SET declared = 1, scope_kind = $kind, why = $why, version = $v, updated_utc = $now
                    WHERE user_id = $id AND action = $a;
                    """,
                    ("$id", accountId), ("$a", requirement.Action), ("$kind", ScopeKinds.ToWire(requirement.ScopeKind)),
                    ("$why", (object?)requirement.Why ?? DBNull.Value));
                continue;
            }

            bool waits = ActionIds.IsAuth(requirement.Action);
            w.Execute(
                """
                INSERT INTO service_requirements
                    (user_id, action, scope_kind, why, state, grant_scope, decided_by, declared, version, updated_utc)
                VALUES ($id, $a, $kind, $why, $state, $grant, NULL, 1, $v, $now);
                """,
                ("$id", accountId), ("$a", requirement.Action), ("$kind", ScopeKinds.ToWire(requirement.ScopeKind)),
                ("$why", (object?)requirement.Why ?? DBNull.Value),
                ("$state", RequirementStates.ToWire(waits ? RequirementState.Waiting : RequirementState.Approved)),
                ("$grant", waits ? DBNull.Value : memberScope.ToString()));

            if (!waits)
                w.Changed(AuthorityChangeKind.RequirementApproved, requirement.Action, accountId: accountId, scope: memberScope.ToString());
        }

        return accountId;
    }

    /// <summary>
    /// Forget a component's service account on a member entirely: its roles, its requirements and
    /// every decision about them. The component installed again later is a new service.
    /// </summary>
    public Task<AuthorityWrite> ForgetServiceAccountAsync(ServiceIdentity service, DateTimeOffset now, CancellationToken ct = default) =>
        WriteAsync(expectedVersion: null, now, ct, (w, s) =>
        {
            if (ServiceAccountId(s, service) is { } accountId)
                DeleteAccountRow(w, s, accountId);

            return null;
        });

    private static string? ServiceAccountId(AuthoritySnapshot s, ServiceIdentity service) =>
        s.Accounts.Values.FirstOrDefault(a => a.Service == service)?.AccountId;

    /// <summary>
    /// A service account's row. Its username is <c>&lt;component&gt;@&lt;member&gt;</c>, which no
    /// person's username can be — <c>@</c> is outside what <see cref="Usernames"/> accepts — so a person
    /// can never register a service's name.
    /// </summary>
    private static string CreateServiceAccount(Writer w, ServiceIdentity service)
    {
        string id = UserIds.NewUserId();
        w.Execute(
            """
            INSERT INTO users (user_id, username, username_key, display_name, origin, kind, status, created_utc, updated_utc, version)
            VALUES ($id, $name, $key, $display, $origin, $kind, $status, $now, $now, $v);
            """,
            ("$id", id), ("$name", service.Name), ("$key", Usernames.Key(service.Name)), ("$display", service.Actor),
            ("$origin", AccountWire.Admitted), ("$kind", AccountWire.Service), ("$status", UserStatuses.Active));
        w.Execute("INSERT INTO service_accounts (user_id, component, member) VALUES ($id, $c, $m);",
            ("$id", id), ("$c", service.Component), ("$m", service.Member));
        return id;
    }

    // ── plumbing ──────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Run one write: take the write lock, check the version, load the snapshot the change is judged
    /// against, apply it, and advance the version — unless it changed nothing.
    /// </summary>
    private async Task<AuthorityWrite> WriteAsync(
        long? expectedVersion, DateTimeOffset now, CancellationToken ct, Func<Writer, AuthoritySnapshot, string?> apply)
    {
        await using SqliteConnection connection = await ConnectAsync(ct).ConfigureAwait(false);
        await using SqliteTransaction transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);

        // An immediate transaction: take the write lock before reading, so the snapshot the rules
        // judge is the one the change lands on.
        Execute(connection, transaction, "UPDATE authority_meta SET value = value WHERE key = $key;",
            ("$key", AuthoritySchema.AuthorityVersionKey));

        long current = ReadVersion(connection, transaction);
        if (expectedVersion is { } expected && expected != current)
            throw new StaleAuthorityException(expected, current);

        AuthoritySnapshot snapshot = Load(connection, transaction, AuthorityFreshness.Authoritative);
        Writer writer = new(connection, transaction, current + 1, UserWire.ToWire(now));

        string? created = apply(writer, snapshot);
        if (!writer.Wrote)
        {
            // Bookkeeping alone — a member's report stored again unchanged — commits and leaves the
            // authority where it was.
            if (writer.Recorded)
                await transaction.CommitAsync(ct).ConfigureAwait(false);

            return new AuthorityWrite(current, [], created);
        }

        Execute(connection, transaction, "UPDATE authority_meta SET value = $value WHERE key = $key;",
            ("$key", AuthoritySchema.AuthorityVersionKey),
            ("$value", writer.Version.ToString(CultureInfo.InvariantCulture)));

        Owe(connection, transaction, writer);
        AdvanceGeneration(connection, transaction);

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return new AuthorityWrite(writer.Version, writer.Changes, created);
    }

    /// <summary>
    /// File every record this write changed in the outbox: each one stamped with its version, and each
    /// one it reported removed. A record removed and changed in one write is owed as removed.
    /// </summary>
    private static void Owe(SqliteConnection connection, SqliteTransaction transaction, Writer writer)
    {
        Dictionary<string, bool> owed = new(StringComparer.Ordinal);

        void Stamped(string sql, Func<string, AuthorityRecordKey> key) =>
            Read(connection, transaction, sql, r => owed.TryAdd(key(r.GetString(0)).ToString(), false), ("$v", writer.Version));

        Stamped("SELECT role_id FROM roles WHERE version = $v;", AuthorityRecordKey.Role);
        Stamped("SELECT permission_id FROM permissions WHERE version = $v;", AuthorityRecordKey.Permission);
        Stamped("SELECT assignment_id FROM assignments WHERE version = $v;", AuthorityRecordKey.Assignment);
        Stamped("SELECT user_id FROM users WHERE version = $v;", AuthorityRecordKey.Account);
        Stamped("SELECT DISTINCT user_id FROM service_requirements WHERE version = $v;", AuthorityRecordKey.Account);

        if (ReadMetaLong(connection, transaction, AuthoritySchema.CatalogVersionKey) == writer.Version)
            owed.TryAdd(AuthorityRecordKey.Catalog.ToString(), false);

        foreach (AuthorityChange change in writer.Changes)
        {
            AuthorityRecordKey? removed = change.Kind switch
            {
                AuthorityChangeKind.RoleRemoved => AuthorityRecordKey.Role(change.Subject),
                AuthorityChangeKind.PermissionRemoved => AuthorityRecordKey.Permission(change.Subject),
                AuthorityChangeKind.AssignmentRevoked => AuthorityRecordKey.Assignment(change.Subject),
                AuthorityChangeKind.AccountDeleted => AuthorityRecordKey.Account(change.Subject),
                _ => null,
            };

            if (removed is { } key)
                owed[key.ToString()] = true;
        }

        foreach ((string record, bool removed) in owed)
        {
            Execute(connection, transaction,
                """
                INSERT INTO authority_outbox (record, version, removed) VALUES ($r, $v, $removed)
                ON CONFLICT(record) DO UPDATE SET version = excluded.version, removed = excluded.removed;
                """,
                ("$r", record), ("$v", writer.Version), ("$removed", removed ? 1 : 0));
        }
    }

    /// <summary>Advance the counter a cached snapshot is compared against.</summary>
    private static void AdvanceGeneration(SqliteConnection connection, SqliteTransaction transaction) =>
        Execute(connection, transaction,
            """
            INSERT INTO authority_meta (key, value) VALUES ($key, '1')
            ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT);
            """,
            ("$key", AuthoritySchema.GenerationKey));

    private static long ReadMetaLong(SqliteConnection connection, SqliteTransaction? transaction, string key) =>
        Scalar(connection, transaction, "SELECT value FROM authority_meta WHERE key = $key;", ("$key", key)) is string value
        && long.TryParse(value, CultureInfo.InvariantCulture, out long parsed)
            ? parsed
            : 0;

    /// <summary>One write in progress: its connection, the version it writes at, and what it changed.</summary>
    private sealed class Writer(SqliteConnection connection, SqliteTransaction transaction, long version, string now)
    {
        public long Version { get; } = version;

        public List<AuthorityChange> Changes { get; } = [];

        /// <summary>
        /// Whether anything was written. Not every write is a change worth journaling — a requirement
        /// a manifest stopped listing, a service account created for a requirement that waits — but
        /// every one advances the version.
        /// </summary>
        public bool Wrote { get; private set; }

        /// <summary>Whether bookkeeping was written that is not itself a change to who may do what.</summary>
        public bool Recorded { get; private set; }

        /// <summary>Run a statement, with <c>$v</c> bound to the new version and <c>$now</c> to the time.</summary>
        public void Execute(string sql, params (string Name, object Value)[] parameters)
        {
            SqliteAuthorityStore.Execute(connection, transaction, sql, [.. parameters, ("$v", Version), ("$now", now)]);
            Wrote = true;
        }

        /// <summary>
        /// Run a statement that records bookkeeping rather than authority — a member's stored report. It
        /// commits with the write and does not, alone, advance the version.
        /// </summary>
        public void Record(string sql, params (string Name, object Value)[] parameters)
        {
            SqliteAuthorityStore.Execute(connection, transaction, sql, [.. parameters, ("$now", now)]);
            Recorded = true;
        }

        /// <summary>
        /// Run a statement as <see cref="Execute"/> does and say how many rows it changed. One that changed
        /// none advances nothing.
        /// </summary>
        public int ExecuteCount(string sql, params (string Name, object Value)[] parameters)
        {
            using SqliteCommand command = Command(connection, transaction, sql, [.. parameters, ("$v", Version), ("$now", now)]);
            int changed = command.ExecuteNonQuery();
            if (changed > 0)
                Wrote = true;
            return changed;
        }

        /// <summary>Run bookkeeping as <see cref="Record"/> does and say how many rows it changed.</summary>
        public int RecordCount(string sql, params (string Name, object Value)[] parameters)
        {
            using SqliteCommand command = Command(connection, transaction, sql, [.. parameters, ("$now", now)]);
            int changed = command.ExecuteNonQuery();
            if (changed > 0)
                Recorded = true;
            return changed;
        }

        /// <summary>Read inside this write's transaction.</summary>
        public T Query<T>(Func<SqliteConnection, SqliteTransaction, T> read) => read(connection, transaction);

        public void Changed(
            AuthorityChangeKind kind, string subject, string? name = null, string? accountId = null,
            string? roleId = null, string? scope = null) =>
            Changes.Add(new AuthorityChange(kind, subject, name, accountId, roleId, scope));
    }

    private static long ReadVersion(SqliteConnection connection, SqliteTransaction? transaction)
    {
        string? value = Scalar(connection, transaction, "SELECT value FROM authority_meta WHERE key = $key;",
            ("$key", AuthoritySchema.AuthorityVersionKey)) as string;

        return long.TryParse(value, CultureInfo.InvariantCulture, out long version)
            ? version
            : throw new UserStoreSchemaException("The account store holds no readable authority version.");
    }

    private static HashSet<string> Bucket(Dictionary<string, HashSet<string>> map, string key)
    {
        if (!map.TryGetValue(key, out HashSet<string>? bucket))
            map[key] = bucket = new HashSet<string>(StringComparer.Ordinal);

        return bucket;
    }

    private SqliteConnection Connect()
    {
        SqliteConnection connection = new(_connectionString);
        connection.Open();
        ApplyPragmas(connection);
        return connection;
    }

    private async Task<SqliteConnection> ConnectAsync(CancellationToken ct)
    {
        SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        ApplyPragmas(connection);
        return connection;
    }

    private void ApplyPragmas(SqliteConnection connection) =>
        Execute(connection, null, FormattableString.Invariant(
            $"PRAGMA busy_timeout={(int)_busyTimeout.TotalMilliseconds};"));

    private static void Read(
        SqliteConnection connection, SqliteTransaction? transaction, string sql, Action<SqliteDataReader> row,
        params (string Name, object Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, transaction, sql, parameters);
        using SqliteDataReader reader = command.ExecuteReader();
        while (reader.Read())
            row(reader);
    }

    private static object? Scalar(
        SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, transaction, sql, parameters);
        return command.ExecuteScalar();
    }

    private static void Execute(
        SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, transaction, sql, parameters);
        command.ExecuteNonQuery();
    }

    private static SqliteCommand Command(
        SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object Value)[] parameters)
    {
        SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;

        foreach ((string name, object value) in parameters)
            command.Parameters.AddWithValue(name, value);

        return command;
    }
}
