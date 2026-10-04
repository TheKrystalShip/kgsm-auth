namespace TheKrystalShip.Auth.Users;

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

/// <summary>Where a store file states its schema version.</summary>
public static class UserSchema
{
    /// <summary>The key the version is filed under in <c>schema_meta</c>.</summary>
    public const string VersionKey = "schema_version";
}
