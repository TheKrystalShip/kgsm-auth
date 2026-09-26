using TheKrystalShip.KGSM.Auth.Access;

namespace TheKrystalShip.KGSM.Auth.Users;

/// <summary>Whether a store is the authority itself or a member's replica of it.</summary>
public enum AuthorityStanding
{
    /// <summary>The anchor's own store: always current.</summary>
    Anchor,

    /// <summary>A member's replica: current only within the bound of its last confirmation.</summary>
    Replica,
}

/// <summary>
/// The snapshot every evaluation on this member reads, loaded once per change to what the store holds.
/// </summary>
/// <remarks>
/// <para>
/// <b>Cached per generation, with no time-to-live.</b> Every write on the anchor and every change a
/// replica applies advances the store's generation in the same transaction, so a cached snapshot is
/// exact until something changes and is discarded the next time anybody asks after it does. A
/// revocation takes effect on the next request, never after a timer.
/// </para>
/// <para>
/// A replica's freshness moves on every heartbeat while its content rarely does, so the freshness is
/// read on every call and laid over the cached snapshot rather than being a reason to load it again.
/// </para>
/// <para>
/// One read per call, of the file's small metadata table. A process that shares the file with another
/// — a leaf reading its node's replica — sees the other's changes the same way.
/// </para>
/// </remarks>
public sealed class AuthoritySource(SqliteAuthorityStore store, AuthorityStanding standing, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly SemaphoreSlim _load = new(1, 1);
    private (AuthoritySnapshot Snapshot, long Generation)? _cached;
    private AuthoritySnapshot? _last;

    /// <summary>The store this reads.</summary>
    public SqliteAuthorityStore Store { get; } = store;

    /// <summary>The current snapshot, with the freshness this member holds right now.</summary>
    public async Task<AuthoritySnapshot> CurrentAsync(CancellationToken ct = default)
    {
        long generation;
        AuthorityFreshness freshness;
        int contract;

        if (standing == AuthorityStanding.Replica)
        {
            ReplicaState state = await Store.ReplicaStateAsync(ct).ConfigureAwait(false);
            (generation, freshness, contract) = (state.Generation, state.Freshness, state.MinimumContractVersion);
        }
        else
        {
            generation = await Store.GenerationAsync(ct).ConfigureAwait(false);
            (freshness, contract) = (AuthorityFreshness.Authoritative, AccessContract.Version);
        }

        if (_cached is not { } held || held.Generation != generation)
        {
            await _load.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_cached is not { } again || again.Generation != generation)
                    _cached = await Store.LoadWithGenerationAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                _load.Release();
            }
        }

        AuthoritySnapshot loaded = _cached!.Value.Snapshot;
        AuthoritySnapshot? last = _last;

        // The same content, confirmed at the same moment, is the same snapshot.
        if (last is not null && last.Version == loaded.Version && ReferenceEquals(last.Roles, loaded.Roles)
            && last.Freshness == freshness && last.MinimumContractVersion == contract)
        {
            return last;
        }

        return _last = loaded.With(freshness, contract);
    }

    /// <summary>An evaluator over the current snapshot.</summary>
    public async Task<AccessEvaluator> EvaluatorAsync(CancellationToken ct = default) =>
        new(await CurrentAsync(ct).ConfigureAwait(false), _clock);
}
