namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// Schema version 2 of the account store: accounts without tiers, and everything that decides access
/// beside them.
/// </summary>
/// <remarks>
/// <para>
/// Version 2 is where the store holds permissions, roles, assignments, service accounts and their
/// requirements, the catalog of declared actions, each member's last report and the authority version.
/// An account carries no tier: what it may do is its assignments. <c>origin</c> says whether it arrived
/// by itself or was admitted by somebody, and <c>kind</c> whether it is a person or a service.
/// </para>
/// <para>
/// <see cref="SqliteAuthorityStore"/> reads and writes version 2, <see cref="SqliteUserStore"/> reads
/// version 1, and <see cref="UserStoreUpgrade"/> brings a version 1 file to version 2 in one
/// transaction.
/// </para>
/// <para>
/// Every authority row, and every account, carries the authority version it was written at, which is
/// what orders a change against a later one when the rows are replicated. The anchor's
/// <c>authority_outbox</c> holds what it owes the cluster; a replica's <c>authority_tombstones</c>
/// holds the version each removed record was removed at.
/// </para>
/// </remarks>
public static class AuthoritySchema
{
    /// <summary>The schema version this layout is.</summary>
    public const int Version = 2;

    /// <summary>The key the authority version is filed under in <c>authority_meta</c>.</summary>
    /// <remarks>On the anchor, the version of the last write. On a replica, the highest version applied.</remarks>
    public const string AuthorityVersionKey = "authority_version";

    /// <summary>
    /// The key of a counter every change to what this file holds advances, the anchor's writes and a
    /// replica's applied changes alike: what a cached snapshot is compared against.
    /// </summary>
    public const string GenerationKey = "generation";

    /// <summary>The version the catalog was last replaced at.</summary>
    public const string CatalogVersionKey = "catalog_version";

    /// <summary>On a replica: when it was last confirmed current, as a UTC timestamp.</summary>
    public const string ConfirmedKey = "confirmed_utc";

    /// <summary>On a replica: how long it stays current after a confirmation, in seconds.</summary>
    public const string BoundKey = "bound_seconds";

    /// <summary>On a replica: the lowest evaluation contract the cluster accepts.</summary>
    public const string MinimumContractKey = "minimum_contract";

    /// <summary>The accounts, credentials and lockouts at version 2.</summary>
    public const string CreateAccounts = """
        CREATE TABLE IF NOT EXISTS schema_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id      TEXT PRIMARY KEY,
            username     TEXT NOT NULL,
            username_key TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            origin       TEXT NOT NULL,
            kind         TEXT NOT NULL,
            status       TEXT NOT NULL,
            created_utc  TEXT NOT NULL,
            updated_utc  TEXT NOT NULL,
            version      INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS credentials (
            credential_id TEXT PRIMARY KEY,
            user_id       TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            kind          TEXT NOT NULL,
            handle        TEXT NOT NULL UNIQUE,
            secret        TEXT NULL,
            label         TEXT NULL,
            created_utc   TEXT NOT NULL,
            last_used_utc TEXT NULL
        );

        CREATE INDEX IF NOT EXISTS ix_credentials_user ON credentials(user_id);

        CREATE TABLE IF NOT EXISTS login_failures (
            user_id          TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
            failed_count     INTEGER NOT NULL,
            last_failed_utc  TEXT NOT NULL,
            locked_until_utc TEXT NULL
        );
        """;

    /// <summary>
    /// Everything that decides access. Created by a fresh version 2 file and by the upgrade alike.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deleting a role, a permission or an account takes what hangs off it with it through the foreign
    /// keys: a role's assignments and permission links, a permission's links, an account's assignments,
    /// service identity and requirements. The store reads what a cascade will take before it deletes, so
    /// each removal is still reported one change at a time.
    /// </para>
    /// <para>
    /// A requirement is keyed by account and action: a service needs an action once, at one scope.
    /// <c>decided_by</c> is null while the requirement stands as it was approved automatically, and
    /// names the person who revoked, narrowed or approved it otherwise.
    /// </para>
    /// </remarks>
    public const string CreateAuthority = """
        CREATE TABLE IF NOT EXISTS authority_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS permissions (
            permission_id TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            name_key      TEXT NOT NULL UNIQUE,
            version       INTEGER NOT NULL,
            updated_utc   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS permission_actions (
            permission_id TEXT NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
            action        TEXT NOT NULL,
            PRIMARY KEY (permission_id, action)
        );

        CREATE TABLE IF NOT EXISTS roles (
            role_id     TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            name_key    TEXT NOT NULL UNIQUE,
            kind        TEXT NOT NULL,
            rank        INTEGER NOT NULL,
            version     INTEGER NOT NULL,
            updated_utc TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id       TEXT NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
            permission_id TEXT NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
            PRIMARY KEY (role_id, permission_id)
        );

        CREATE TABLE IF NOT EXISTS assignments (
            assignment_id TEXT PRIMARY KEY,
            user_id       TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            role_id       TEXT NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
            scope         TEXT NOT NULL,
            granted_by    TEXT NULL,
            version       INTEGER NOT NULL,
            created_utc   TEXT NOT NULL,
            UNIQUE (user_id, role_id, scope)
        );

        CREATE INDEX IF NOT EXISTS ix_assignments_role ON assignments(role_id);

        CREATE TABLE IF NOT EXISTS service_accounts (
            user_id   TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
            component TEXT NOT NULL,
            member    TEXT NOT NULL,
            UNIQUE (component, member)
        );

        CREATE TABLE IF NOT EXISTS service_requirements (
            user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            action      TEXT NOT NULL,
            scope_kind  TEXT NOT NULL,
            why         TEXT NULL,
            state       TEXT NOT NULL,
            grant_scope TEXT NULL,
            decided_by  TEXT NULL,
            declared    INTEGER NOT NULL,
            version     INTEGER NOT NULL,
            updated_utc TEXT NOT NULL,
            PRIMARY KEY (user_id, action)
        );

        CREATE TABLE IF NOT EXISTS catalog_actions (
            action     TEXT PRIMARY KEY,
            title      TEXT NOT NULL,
            effect     TEXT NOT NULL,
            scope_kind TEXT NOT NULL,
            self       INTEGER NOT NULL,
            version    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS member_reports (
            member       TEXT PRIMARY KEY,
            report       TEXT NOT NULL,
            received_utc TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS authority_outbox (
            record  TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            removed INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS authority_tombstones (
            record  TEXT PRIMARY KEY,
            version INTEGER NOT NULL
        );
        """;

    /// <summary>
    /// The two built-in roles, at authority version 1. Owner holds everything implicitly and
    /// <c>everyone</c> starts empty, so neither is linked to a permission here.
    /// </summary>
    internal const string SeedBuiltInRoles = """
        INSERT OR IGNORE INTO roles (role_id, name, name_key, kind, rank, version, updated_utc)
        VALUES ($owner_id, $owner_name, $owner_key, 'owner', $owner_rank, 1, $now),
               ($everyone_id, $everyone_name, $everyone_key, 'everyone', $everyone_rank, 1, $now);

        INSERT OR IGNORE INTO authority_meta (key, value) VALUES ('authority_version', '1');
        INSERT OR IGNORE INTO authority_meta (key, value) VALUES ('generation', '1');
        INSERT OR IGNORE INTO authority_meta (key, value) VALUES ('catalog_version', '1');
        """;
}

/// <summary>Where an account came from, which is what pending-account expiry reads.</summary>
public enum AccountOrigin
{
    /// <summary>Created itself, through registration or a provider. Expires if nobody approves it.</summary>
    Arrived = 0,

    /// <summary>Made or approved by somebody. Never expires.</summary>
    Admitted = 1,
}

/// <summary>Storage strings for the version 2 account columns, and the parse back.</summary>
public static class AccountWire
{
    public const string Arrived = "arrived";
    public const string Admitted = "admitted";
    public const string Person = "person";
    public const string Service = "service";

    /// <summary>The storage form of an origin.</summary>
    public static string ToWire(AccountOrigin origin) => origin == AccountOrigin.Admitted ? Admitted : Arrived;

    /// <summary>
    /// The origin a string names, with anything unrecognised read as <see cref="AccountOrigin.Arrived"/>
    /// — the origin that expires rather than the one that is spared.
    /// </summary>
    public static AccountOrigin ParseOrigin(string? wire) =>
        wire?.Trim().ToLowerInvariant() == Admitted ? AccountOrigin.Admitted : AccountOrigin.Arrived;

    /// <summary>The storage form of an account kind.</summary>
    public static string ToWire(Access.AccountKind kind) => kind == Access.AccountKind.Service ? Service : Person;

    /// <summary>
    /// The kind a string names, with anything unrecognised read as a service — the kind that holds no
    /// <c>everyone</c>, no self actions and cannot hold Owner.
    /// </summary>
    public static Access.AccountKind ParseKind(string? wire) =>
        wire?.Trim().ToLowerInvariant() == Person ? Access.AccountKind.Person : Access.AccountKind.Service;
}
