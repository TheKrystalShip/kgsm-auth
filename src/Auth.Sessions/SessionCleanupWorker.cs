using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace TheKrystalShip.KGSM.Auth.Sessions;

/// <summary>
/// Deletes expired sessions on a timer, so the registry does not grow forever across a long run.
/// </summary>
/// <remarks>
/// A catch-up pass runs at startup: a host that was down for a while has a backlog, and waiting a
/// full interval to start shedding it serves nobody. Each tick is wrapped, because one failed sweep
/// must not kill the worker — the next tick simply tries again.
/// </remarks>
public sealed class SessionCleanupWorker(
    ISessionRegistry registry,
    TimeSpan interval,
    ILogger<SessionCleanupWorker>? logger = null) : BackgroundService
{
    private readonly TimeSpan _interval = interval > TimeSpan.Zero ? interval : TimeSpan.FromMinutes(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await SweepAsync(stoppingToken).ConfigureAwait(false);

        using var timer = new PeriodicTimer(_interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
                await SweepAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The host is stopping. Not a failure.
        }
    }

    private async Task SweepAsync(CancellationToken ct)
    {
        try
        {
            int removed = await registry.DeleteExpiredAsync(DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
            if (removed > 0)
                logger?.LogInformation("session GC: removed {Count} expired session(s)", removed);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger?.LogWarning(ex, "session GC: sweep failed");
        }
    }
}
