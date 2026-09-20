using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;

using TheKrystalShip.Api.Contracts;
using TheKrystalShip.KGSM.ComponentSurface;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// This anchor's own journal, served on its own origin.
/// </summary>
/// <remarks>
/// A node's journal is read by the API on that node; an anchor has no node above it, so it reads its
/// own — the same reason it serves its own configuration. The lines are <see cref="LogLine"/>, the
/// shape every KGSM log surface renders, so the panel's console shows an anchor's journal and a leaf's
/// through one component.
/// <para>
/// <b>Reading a journal has to be granted.</b> Without membership of <c>systemd-journal</c>,
/// <c>journalctl</c> exits 0 having printed nothing — a success that looks exactly like a unit which
/// has logged nothing — so the unit carries <c>SupplementaryGroups=systemd-journal</c>.
/// </para>
/// </remarks>
internal static class LogEndpoints
{
    /// <summary>
    /// <c>GET /auth/logs?lines=N</c> — this anchor's own journal. Admin: a daemon's log carries
    /// usernames, addresses and the shape of every failure it has had.
    /// </summary>
    internal static async Task Read(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        int? lines = int.TryParse(ctx.Request.Query["lines"], out int asked) ? asked : null;

        var journal = ctx.RequestServices.GetRequiredService<ComponentJournal>();
        if (journal.Read(lines) is not { } read)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "journal_unreadable",
                "This anchor's journal could not be read on this host.");
            return;
        }

        // No cursor: this is the whole tail that was asked for, not a page of a walk backwards.
        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new LogPage(read, null),
            ApiContractsJson.Default.LogPage);
    }

    /// <summary>
    /// <c>GET /auth/logs/stream</c> — the same lines, as they happen.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Server-sent events rather than a socket, because this carries one thing in one direction and a
    /// browser reconnects it for free. It is read with <c>fetch</c> on the panel's side for the
    /// ordinary reason: <c>EventSource</c> sends no <c>Authorization</c> header, and a daemon holding
    /// the cluster's accounts does not put its journal behind a token in the query string.
    /// </para>
    /// <para>
    /// <b>Follow-only.</b> The caller hydrated its scrollback from the read above and applies lines
    /// from the next one on, so nothing here replays history — sending it would show every line twice
    /// on every attach.
    /// </para>
    /// <para>
    /// The comment line at the start is what makes a proxy release the response: a stream that has
    /// carried no bytes is a stream several of them hold on to until it does. The heartbeats after it
    /// are what stop an idle journal reading as a dropped connection.
    /// </para>
    /// </remarks>
    internal static async Task Stream(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        var follower = ctx.RequestServices.GetRequiredService<ComponentJournalFollower>();
        if (follower.Watch() is not { } watch)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "journal_unreadable",
                "This anchor's journal could not be followed on this host.");
            return;
        }

        using IDisposable handle = watch.Handle;

        ctx.Response.StatusCode = StatusCodes.Status200OK;
        ctx.Response.ContentType = "text/event-stream";
        ctx.Response.Headers.CacheControl = "no-cache";
        ctx.Response.Headers["X-Accel-Buffering"] = "no";
        ctx.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();

        await ctx.Response.WriteAsync(": open\n\n", ctx.RequestAborted);
        await ctx.Response.Body.FlushAsync(ctx.RequestAborted);

        var heartbeat = new PeriodicTimer(TimeSpan.FromSeconds(20));
        Task<bool> tick = heartbeat.WaitForNextTickAsync(ctx.RequestAborted).AsTask();

        try
        {
            while (!ctx.RequestAborted.IsCancellationRequested)
            {
                ValueTask<bool> waiting = watch.Lines.WaitToReadAsync(ctx.RequestAborted);
                Task<bool> lines = waiting.AsTask();

                Task done = await Task.WhenAny(lines, tick).ConfigureAwait(false);

                if (done == tick)
                {
                    if (!await tick)
                        break;
                    tick = heartbeat.WaitForNextTickAsync(ctx.RequestAborted).AsTask();
                    await ctx.Response.WriteAsync(": ping\n\n", ctx.RequestAborted);
                    await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
                    continue;
                }

                // The follow ended. Closing is the honest answer: the panel says the tail stopped
                // rather than showing a live pill over a stream carrying nothing.
                if (!await lines)
                    break;

                while (watch.Lines.TryRead(out LogLine? line))
                {
                    string json = JsonSerializer.Serialize(line, ApiContractsJson.Default.LogLine);
                    await ctx.Response.WriteAsync("data: " + json + "\n\n", ctx.RequestAborted);
                }

                await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
            }
        }
        catch (OperationCanceledException)
        {
            // The browser left. Nothing to report: the handle's disposal is what matters, and it is
            // what stops the follow when this was the last watcher.
        }
        finally
        {
            heartbeat.Dispose();
        }
    }
}
