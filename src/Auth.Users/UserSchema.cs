namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>
/// The account store's schema is written by a build that does not know which other build will read
/// it next.
/// </summary>
/// <remarks>
/// Thrown when the file on disk declares a version this build does not understand. The store refuses
/// to open rather than reading what it can and ignoring the rest: half-understood accounts is the
/// one failure mode here that grants access quietly, and a service that will not start is a problem
/// somebody fixes in minutes.
/// </remarks>
public sealed class UserStoreSchemaException(string message) : Exception(message);

/// <summary>
/// The store's schema, and the rule that keeps two independently deployed services able to share
/// one file.
/// </summary>
/// <remarks>
/// <para>
/// <b>Schema changes are additive only, and the version is a floor rather than a match.</b> The
/// ecosystem's usual answer — <c>EnsureCreated</c>, and wipe the database when the schema
/// changes — cannot apply to this one. Wiping it is every account, every password and every link, and
/// there is nothing to re-derive them from. On top of that the Control Panel API and the assistant
/// deploy separately, so at any moment one of them may be a version ahead: an older build must keep
/// working against a newer file, which it can, as long as every change only ever adds.
/// </para>
/// <para>
/// So: add tables, add nullable columns, add indexes. Never drop or rename one, never make an
/// existing column <c>NOT NULL</c> without a default, and never change what a value in an existing
/// column means. Anything that cannot be expressed that way needs a new table beside the old one.
/// </para>
/// </remarks>
public static class UserSchema
{
    /// <summary>
    /// The schema version this build writes and understands.
    /// </summary>
    /// <remarks>
    /// Bumped only when the shape changes, and a bump obliges a matching forward step in
    /// <see cref="SqliteUserStore"/>'s initialisation so an existing file is brought up rather than
    /// rejected.
    /// </remarks>
    public const int Version = 1;

    /// <summary>The key the version is filed under in <c>schema_meta</c>.</summary>
    public const string VersionKey = "schema_version";

    /// <summary>
    /// Version 1: accounts, the credentials that prove them, and the failed-password counter.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>credentials.handle</c> is unique across the whole table, and that one constraint carries
    /// two rules the code would otherwise have to remember: an external identity belongs to exactly
    /// one account, and an account has at most one password. Enforcing them in the schema means a
    /// second service writing the same file cannot break either, however it was written.
    /// </para>
    /// <para>
    /// Times are ISO-8601 round-trip strings in UTC. Sortable as text, unambiguous to a human
    /// reading the file with <c>sqlite3</c>, and immune to the epoch-unit confusion an integer
    /// invites.
    /// </para>
    /// </remarks>
    public const string CreateV1 = """
        CREATE TABLE IF NOT EXISTS schema_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id      TEXT PRIMARY KEY,
            username     TEXT NOT NULL,
            username_key TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            tier         TEXT NOT NULL,
            tier_source  TEXT NOT NULL,
            status       TEXT NOT NULL,
            created_utc  TEXT NOT NULL,
            updated_utc  TEXT NOT NULL
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
}
