using TheKrystalShip.Auth.Access;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// Enters this anchor's own actions into its catalog on a machine in no cluster.
/// </summary>
/// <remarks>
/// <para>
/// An action is grantable only once the catalog holds it. In a KGSM cluster this anchor's manifest
/// reaches the catalog the way every member's does, read off disk by the reporter; with no cluster
/// there is no reporter and no KGSM directory to read, so the report is built from
/// <see cref="AuthActions.Declared"/> — the same declarations the build writes the manifest from, held
/// equal to it by <c>AnchorManifestTests</c> — and handed to <see cref="AuthorityIntake"/> on start.
/// </para>
/// <para>
/// It carries the <c>auth:*</c> actions that administer access and nothing else. The standard surface's
/// actions (<c>auth:config.*</c>, <c>auth:journal.read</c>) belong to the component surface, which is
/// served only in a cluster.
/// </para>
/// <para>
/// Sent on every start. An unchanged report changes nothing and journals nothing.
/// </para>
/// </remarks>
internal sealed class StandaloneCatalog(
    AuthorityIntake intake, AnchorOptions options, ILogger<StandaloneCatalog> logger) : IHostedService
{
    private static readonly string Version =
        typeof(StandaloneCatalog).Assembly.GetName().Version is { } v ? $"{v.Major}.{v.Minor}.{v.Build}" : "";

    /// <summary>This anchor's report: one manifest, its own, as a member that is an anchor.</summary>
    internal static MemberCatalogReport Report(DateTimeOffset now) => new(
        Anchor: true,
        Manifests:
        [
            new ActionManifest(
                ActionManifest.SupportedSchemaVersion,
                ActionIds.AuthComponent,
                Version,
                [
                    .. AuthActions.Declared.Select(a => new ManifestAction(
                        a.Id[(ActionIds.AuthComponent.Length + 1)..],
                        a.Title,
                        ActionEffects.ToWire(a.Effect),
                        ScopeKinds.ToWire(a.Scope),
                        a.Self ? true : null)),
                ],
                Requires: []),
        ],
        Sequence: now.ToUnixTimeMilliseconds());

    public async Task StartAsync(CancellationToken ct)
    {
        try
        {
            await intake.CatalogDeclaredAsync(options.MemberId, Report(DateTimeOffset.UtcNow), ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // The daemon still serves; what is missing is that nobody but an Owner can be granted the
            // actions that administer access, which is what this line says.
            logger.LogError(e, "could not enter this anchor's own actions into its catalog");
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
