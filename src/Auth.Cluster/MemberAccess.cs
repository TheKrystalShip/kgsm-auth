using System.Security.Claims;

using Microsoft.Extensions.Logging;

using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// A member's authority replica in its account store's file, opened once the file holds one.
/// </summary>
/// <remarks>
/// <para>
/// <b>It never creates the file.</b> The replica belongs to the one process on the machine that keeps
/// it (<see cref="OwnedReplicaFile"/>); every other process reads it through this, and a reader that
/// created the file would be a second answer to whose file it is. A file that does not exist, or one at
/// schema version 1, is reported unavailable with the reason, and asked again at most once a minute.
/// </para>
/// <para>
/// Every surface that reads this answers <c>authority_unavailable</c> while it is unavailable, which is
/// the truth: nothing here can say what anybody may do.
/// </para>
/// </remarks>
public sealed class AuthorityReplicaFile(string path, ILogger<AuthorityReplicaFile> logger, TimeProvider? clock = null)
    : IReplicatedAuthority
{
    private static readonly TimeSpan Retry = TimeSpan.FromMinutes(1);

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private SqliteAuthorityStore? _replica;
    private string? _unavailable;
    private DateTimeOffset _nextTry = DateTimeOffset.MinValue;

    /// <inheritdoc />
    public SqliteAuthorityStore? Replica
    {
        get
        {
            lock (_gate)
            {
                if (_replica is not null || _clock.GetUtcNow() < _nextTry)
                    return _replica;

                _nextTry = _clock.GetUtcNow() + Retry;
                if (!File.Exists(path))
                {
                    _unavailable = $"There is no account store at '{path}'.";
                    return null;
                }

                try
                {
                    _replica = new SqliteAuthorityStore(new UserStoreOptions { Path = path });
                    _unavailable = null;
                }
                catch (UserStoreSchemaException e)
                {
                    if (_unavailable != e.Message)
                        logger.LogInformation("the authority replica is unavailable: {Reason}", e.Message);
                    _unavailable = e.Message;
                }

                return _replica;
            }
        }
    }

    /// <inheritdoc />
    public string? UnavailableReason
    {
        get
        {
            _ = Replica;
            lock (_gate)
                return _unavailable;
        }
    }
}

/// <summary>Why a member cannot evaluate the person behind a verified session.</summary>
public enum MemberAccessRefusal
{
    /// <summary>It can.</summary>
    None = 0,

    /// <summary>The replica cannot be read. An outage, never a denial.</summary>
    Unavailable,

    /// <summary>No account in the replica is identified by the session's subject.</summary>
    NoAccount,

    /// <summary>The account is switched off.</summary>
    AccountDisabled,
}

/// <summary>The person behind a verified session, and the evaluator to ask about them, or why there is none.</summary>
/// <param name="Refusal">Why not, or <see cref="MemberAccessRefusal.None"/>.</param>
/// <param name="AccountId">The account the session's identity belongs to.</param>
/// <param name="Evaluator">The evaluator over the replica's current snapshot.</param>
/// <param name="Reason">Why the replica is unavailable, when it is.</param>
public sealed record MemberAccessCaller(
    MemberAccessRefusal Refusal, string? AccountId, AccessEvaluator? Evaluator, string? Reason = null);

/// <summary>
/// Resolves the person behind a session a member has already verified, against the member's own
/// replica, and answers what they may do there.
/// </summary>
/// <remarks>
/// <para>
/// <b>The token names who, the replica says what.</b> The session's subject is a credential handle; it
/// is looked up in the replica on every request, and nothing about access is read off the token, so a
/// role change reaches this member at the next request with no session ended.
/// </para>
/// <para>
/// One implementation for every member — kgsm-api, the assistant, kgsm-dns — so a person resolves the
/// same way wherever they are asking.
/// </para>
/// </remarks>
public sealed class MemberAccess(IReplicatedAuthority authority, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private (SqliteAuthorityStore Store, AuthoritySource Source)? _source;

    /// <summary>The person behind <paramref name="user"/>, a principal the member's own validation produced.</summary>
    public Task<MemberAccessCaller> ResolveAsync(ClaimsPrincipal user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        return user.Identity is ClaimsIdentity identity && SessionClaims.ReadIdentity(identity) is { } who
            ? ResolveAsync(who, ct)
            : Task.FromResult(new MemberAccessCaller(MemberAccessRefusal.NoAccount, null, null));
    }

    /// <summary>
    /// The person a verified session names, for a member whose own session check hands it the identity
    /// rather than a principal.
    /// </summary>
    public async Task<MemberAccessCaller> ResolveAsync(KgsmIdentity who, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(who);

        if (Source() is not { } source)
            return new MemberAccessCaller(MemberAccessRefusal.Unavailable, null, null,
                authority.UnavailableReason ?? "The authority replica is unavailable.");

        string? accountId;
        AuthoritySnapshot snapshot;
        try
        {
            accountId = await source.Store.FindAccountIdByHandleAsync(who.Handle, ct).ConfigureAwait(false);
            snapshot = await source.CurrentAsync(ct).ConfigureAwait(false);
        }
        catch (Microsoft.Data.Sqlite.SqliteException e)
        {
            return new MemberAccessCaller(MemberAccessRefusal.Unavailable, null, null, e.Message);
        }

        if (accountId is null || !snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account))
            return new MemberAccessCaller(MemberAccessRefusal.NoAccount, null, null);

        if (account.Status == AccountStatus.Disabled)
            return new MemberAccessCaller(MemberAccessRefusal.AccountDisabled, accountId, null);

        return new MemberAccessCaller(MemberAccessRefusal.None, accountId, new AccessEvaluator(snapshot, _clock));
    }

    /// <summary>
    /// The <c>/me/access</c> answer for <paramref name="user"/> at <paramref name="targets"/>, listing the
    /// actions <paramref name="include"/> accepts — the ones this member performs.
    /// </summary>
    public async Task<(MemberAccessCaller Caller, AccessReport? Report)> ReportAsync(
        ClaimsPrincipal user, IEnumerable<AccessScope> targets, Func<string, bool> include, CancellationToken ct = default) =>
        Report(await ResolveAsync(user, ct).ConfigureAwait(false), targets, include);

    /// <inheritdoc cref="ReportAsync(ClaimsPrincipal, IEnumerable{AccessScope}, Func{string, bool}, CancellationToken)"/>
    public async Task<(MemberAccessCaller Caller, AccessReport? Report)> ReportAsync(
        KgsmIdentity who, IEnumerable<AccessScope> targets, Func<string, bool> include, CancellationToken ct = default) =>
        Report(await ResolveAsync(who, ct).ConfigureAwait(false), targets, include);

    private (MemberAccessCaller Caller, AccessReport? Report) Report(
        MemberAccessCaller caller, IEnumerable<AccessScope> targets, Func<string, bool> include) =>
        caller.Refusal != MemberAccessRefusal.None
            ? (caller, null)
            : (caller, AccessReport.For(caller.Evaluator!, caller.AccountId!, targets, include, _clock.GetUtcNow()));

    /// <summary>
    /// The <c>/me/access</c> answer for an account already known — what a surface pushes to that
    /// account's open connections when the replica changes. Null when the replica is unavailable or the
    /// account is gone or switched off.
    /// </summary>
    public async Task<AccessReport?> ReportForAccountAsync(
        string accountId, IEnumerable<AccessScope> targets, Func<string, bool> include, CancellationToken ct = default)
    {
        if (Source() is not { } source)
            return null;

        AuthoritySnapshot snapshot = await source.CurrentAsync(ct).ConfigureAwait(false);
        if (!snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account) || account.Status == AccountStatus.Disabled)
            return null;

        return AccessReport.For(new AccessEvaluator(snapshot, _clock), accountId, targets, include, _clock.GetUtcNow());
    }

    private AuthoritySource? Source()
    {
        if (authority.Replica is not { } replica)
            return null;

        lock (_gate)
        {
            if (_source is not { } held || !ReferenceEquals(held.Store, replica))
                _source = (replica, new AuthoritySource(replica, AuthorityStanding.Replica, _clock));

            return _source.Value.Source;
        }
    }
}
