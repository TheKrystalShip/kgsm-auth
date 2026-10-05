using System.Text.Json;

using TheKrystalShip.Auth.Access;
using TheKrystalShip.Auth.Cluster;
using TheKrystalShip.Auth.Journal;
using TheKrystalShip.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Messaging;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>
/// This anchor's authority store, opened on first use.
/// </summary>
/// <remarks>
/// The authority lives in the account store. A store at a schema version this build does not read
/// says so once through <see cref="UnavailableReason"/> rather than stopping the daemon, which is the
/// surface that reports it.
/// </remarks>
internal sealed class AnchorAuthority(AnchorOptions options, ILogger<AnchorAuthority> logger)
{
    private readonly Lock _gate = new();
    private SqliteAuthorityStore? _store;
    private AuthoritySource? _source;
    private string? _unavailable;

    /// <summary>The snapshot this anchor evaluates its own actions against, cached per change.</summary>
    public AuthoritySource? Source
    {
        get
        {
            if (Store is not { } store)
                return null;

            lock (_gate)
                return _source ??= new AuthoritySource(store, AuthorityStanding.Anchor);
        }
    }

    /// <summary>Why there is no store, when there is none.</summary>
    public string? UnavailableReason => _unavailable;

    /// <summary>The store, or <see langword="null"/> when the file cannot hold the authority.</summary>
    public SqliteAuthorityStore? Store
    {
        get
        {
            lock (_gate)
            {
                if (_store is not null)
                    return _store;

                try
                {
                    _store = new SqliteAuthorityStore(new UserStoreOptions { Path = options.UserStorePath });
                    _unavailable = null;
                }
                catch (UserStoreSchemaException e)
                {
                    if (_unavailable is null)
                        logger.LogWarning("the authority store is unavailable: {Reason}", e.Message);

                    _unavailable = e.Message;
                }

                return _store;
            }
        }
    }
}

/// <summary>
/// Where every member's report reaches this anchor — over the bus from another member, directly from
/// this one — and the one place each write it makes is journaled.
/// </summary>
internal sealed class AuthorityIntake(
    AnchorAuthority authority,
    AnchorJournal journal,
    IAuthorityAnnouncer broadcast,
    ILogger<AuthorityIntake> logger) : IAuthorityIntake
{
    /// <inheritdoc />
    public async Task CatalogDeclaredAsync(string member, MemberCatalogReport report, CancellationToken ct)
    {
        if (authority.Store is not { } store)
        {
            logger.LogWarning("'{Member}' reported its actions and there is no authority store to hold them", member);
            return;
        }

        AuthorityWrite write = await store.RecordMemberReportAsync(member, report, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        await SettleAsync(member, write, ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task InstanceUninstalledAsync(string member, InstanceUninstalledReport report, CancellationToken ct)
    {
        if (authority.Store is not { } store)
        {
            logger.LogWarning("'{Member}' reported {Instance} uninstalled and there is no authority store", member, report.Instance);
            return;
        }

        AuthorityWrite write = await store.RemoveInstanceAsync(member, report.Nonce, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        await SettleAsync(member, write, ct).ConfigureAwait(false);
    }

    /// <summary>A removed member: forget everything it reported.</summary>
    public async Task MemberRemovedAsync(string member, CancellationToken ct)
    {
        if (authority.Store is not { } store)
            return;

        AuthorityWrite write = await store.ForgetMemberAsync(member, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        await SettleAsync(member, write, ct).ConfigureAwait(false);
    }

    /// <summary>Journal a write, then tell the cluster what it changed.</summary>
    private async Task SettleAsync(string member, AuthorityWrite write, CancellationToken ct)
    {
        string[] added = [.. write.Changes.Where(c => c.Kind == AuthorityChangeKind.CatalogActionAdded).Select(c => c.Subject)];
        if (added.Length > 0)
            logger.LogInformation("'{Member}' declared {Count} action(s) new to the catalog, unmapped: {Actions}",
                member, added.Length, string.Join(", ", added));

        await AuthorityJournaling.JournalAsync(
            journal, write, KgsmActor.Format(KgsmActorProvider.System, member), origin: null, member, ct).ConfigureAwait(false);
        await broadcast.DrainAsync(ct).ConfigureAwait(false);
    }
}

/// <summary>
/// One journal line per change an authority write made, whoever made it.
/// </summary>
/// <remarks>
/// A cascade is journaled as the changes it made — deleting a role is the role's line and one line per
/// assignment that ended with it — so an access review reads what happened to each person rather than
/// inferring it. The catalog's arrivals and departures from one report are one line.
/// </remarks>
internal static class AuthorityJournaling
{
    /// <param name="journal">Where the lines go.</param>
    /// <param name="write">What the write changed.</param>
    /// <param name="actor">Who made it: a person, or <c>system:&lt;member&gt;</c> for a member's report.</param>
    /// <param name="origin">The surface a person made it from, when a person did.</param>
    /// <param name="member">The member whose report changed the catalog, when one did.</param>
    /// <param name="ct">Cancellation.</param>
    internal static async Task JournalAsync(
        AnchorJournal journal, AuthorityWrite write, string actor, string? origin, string? member, CancellationToken ct)
    {
        if (write.Changes.Count == 0)
            return;

        bool automatic = origin is null && actor.StartsWith(KgsmActorProvider.System + ":", StringComparison.Ordinal);

        string[] added = [.. write.Changes.Where(c => c.Kind == AuthorityChangeKind.CatalogActionAdded).Select(c => c.Subject)];
        string[] removed = [.. write.Changes.Where(c => c.Kind == AuthorityChangeKind.CatalogActionRemoved).Select(c => c.Subject)];
        if (added.Length > 0 || removed.Length > 0)
            await journal.CatalogAsync(member ?? "", added, removed, write.Version, actor, ct).ConfigureAwait(false);

        foreach (AuthorityChange change in write.Changes)
        {
            switch (change.Kind)
            {
                case AuthorityChangeKind.RoleChanged:
                case AuthorityChangeKind.RoleRemoved:
                case AuthorityChangeKind.PermissionChanged:
                case AuthorityChangeKind.PermissionRemoved:
                    await journal.AuthorityRecordAsync(RecordEvent(change.Kind), change.Subject, change.Name,
                        write.Version, actor, ct).ConfigureAwait(false);
                    break;

                case AuthorityChangeKind.AssignmentGranted:
                case AuthorityChangeKind.AssignmentRevoked:
                    await journal.AssignmentAsync(
                        change.Kind == AuthorityChangeKind.AssignmentGranted ? AuthEvents.AssignmentGranted : AuthEvents.AssignmentRevoked,
                        change.Subject, change.AccountId!, null, change.RoleId!, change.Name, change.Scope!,
                        write.Version, actor, origin, ct).ConfigureAwait(false);
                    break;

                case AuthorityChangeKind.RequirementApproved:
                case AuthorityChangeKind.RequirementRevoked:
                    await journal.RequirementAsync(
                        change.Kind == AuthorityChangeKind.RequirementApproved
                            ? AuthEvents.ServiceRequirementApproved
                            : AuthEvents.ServiceRequirementRevoked,
                        change.AccountId!, null, change.Subject, change.Scope, automatic, write.Version, actor, ct).ConfigureAwait(false);
                    break;

                case AuthorityChangeKind.AccountDisabled:
                    await journal.AccountAsync(AuthEvents.UserDisabled, change.Subject, change.Name ?? change.Subject,
                        fromStatus: UserStatuses.Active, toStatus: UserStatuses.Disabled, actor: actor, origin: origin, ct: ct)
                        .ConfigureAwait(false);
                    break;

                case AuthorityChangeKind.AccountDeleted:
                    await journal.AccountAsync(AuthEvents.UserDeleted, change.Subject, change.Name ?? change.Subject,
                        actor: actor, origin: origin, ct: ct).ConfigureAwait(false);
                    break;
            }
        }
    }

    private static string RecordEvent(AuthorityChangeKind kind) => kind switch
    {
        AuthorityChangeKind.RoleChanged => AuthEvents.RoleChanged,
        AuthorityChangeKind.RoleRemoved => AuthEvents.RoleRemoved,
        AuthorityChangeKind.PermissionChanged => AuthEvents.PermissionChanged,
        _ => AuthEvents.PermissionRemoved,
    };
}

/// <summary><c>catalog.declared</c>: another member's report.</summary>
internal sealed class CatalogDeclaredHandler(AuthorityIntake intake, ILogger<CatalogDeclaredHandler> logger)
    : IClusterMessageHandler
{
    /// <inheritdoc />
    public string Type => AuthorityMessages.CatalogDeclared;

    /// <inheritdoc />
    public async Task HandleAsync(ClusterEnvelope envelope, CancellationToken ct)
    {
        // A malformed report is acknowledged, never retried: it will not parse on any later attempt,
        // and the member sends a fresh one on its next change or interval.
        MemberCatalogReport? report;
        try
        {
            report = envelope.Payload.Deserialize(AccessJsonContext.Default.MemberCatalogReport);
        }
        catch (JsonException e)
        {
            logger.LogWarning("'{Member}' sent a catalog report that does not parse: {Reason}", envelope.From, e.Message);
            return;
        }

        if (report is not null)
            await intake.CatalogDeclaredAsync(envelope.From, report, ct).ConfigureAwait(false);
    }
}

/// <summary><c>instance.uninstalled</c>: a node's word that one install of an instance is gone.</summary>
internal sealed class InstanceUninstalledHandler(AuthorityIntake intake, ILogger<InstanceUninstalledHandler> logger)
    : IClusterMessageHandler
{
    /// <inheritdoc />
    public string Type => AuthorityMessages.InstanceUninstalled;

    /// <inheritdoc />
    public async Task HandleAsync(ClusterEnvelope envelope, CancellationToken ct)
    {
        InstanceUninstalledReport? report;
        try
        {
            report = envelope.Payload.Deserialize(AccessJsonContext.Default.InstanceUninstalledReport);
        }
        catch (JsonException e)
        {
            logger.LogWarning("'{Member}' sent an uninstall that does not parse: {Reason}", envelope.From, e.Message);
            return;
        }

        // The sender is the node: a grant names an instance by the member it runs on, so a node speaks
        // only for its own instances.
        if (report is { Nonce.Length: > 0 })
            await intake.InstanceUninstalledAsync(envelope.From, report, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// Forgets what a removed member reported. A member that has only gone quiet keeps its report.
/// </summary>
/// <remarks>
/// Removal is the roster marking the member <em>left</em>, which is what removing it from the cluster
/// does. A member that crashed is marked dead and eventually reaped from the roster, and that is not a
/// removal: a node down for a week keeps every action it declared, so its grants still mean something
/// when it returns.
/// </remarks>
internal sealed class MemberDepartureWorker(
    AnchorAuthority authority,
    AuthorityIntake intake,
    TheKrystalShip.KGSM.Cluster.Membership.MembersStore members,
    TheKrystalShip.KGSM.Cluster.ClusterOptions cluster,
    ILogger<MemberDepartureWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!cluster.Enabled)
            return;

        using PeriodicTimer timer = new(Interval);
        try
        {
            do
            {
                await SweepAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // The host is stopping.
        }
    }

    /// <summary>Forget every reporting member the roster says has left.</summary>
    public async Task SweepAsync(CancellationToken ct)
    {
        if (authority.Store is not { } store)
            return;

        try
        {
            IReadOnlyList<string> reporting = await store.ReportingMembersAsync(ct).ConfigureAwait(false);
            foreach (string member in reporting)
            {
                if (member == cluster.MemberId)
                    continue;

                var row = await members.GetByMemberIdAsync(member, ct).ConfigureAwait(false);
                if (row?.MembershipState != TheKrystalShip.KGSM.Cluster.Membership.GossipState.Left)
                    continue;

                logger.LogInformation("'{Member}' was removed from the cluster; forgetting what it declared", member);
                await intake.MemberRemovedAsync(member, ct).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            logger.LogWarning(e, "could not sweep removed members' reports");
        }
    }
}
