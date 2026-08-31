using System.Diagnostics;
using System.Threading.Channels;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The live tail of this anchor's journal: <b>one</b> <c>journalctl -f</c> for however many people
/// are watching.
/// </summary>
/// <remarks>
/// <para>
/// <b>One follow, not one per viewer.</b> Three browsers on this page must not be three processes
/// reading the same journal — the first subscriber starts it, the last one to leave kills it, and an
/// unwatched page costs nothing. That is the shape kgsm-api's host-log bridge already has, for the
/// same reason.
/// </para>
/// <para>
/// <b><c>-n 0</c>, so the follow carries no backlog.</b> A viewer hydrates its scrollback with the
/// REST read and applies live lines from the next one on. Sending history here as well would show
/// every line twice on every attach.
/// </para>
/// <para>
/// <b>A slow viewer drops lines rather than holding anybody up.</b> Each subscriber has a bounded
/// queue that discards its oldest when it fills, so one browser on a bad connection cannot stall the
/// follow for the rest — and the journal is the durable record, which a reconnect re-reads.
/// </para>
/// </remarks>
internal sealed class UnitLogFollower(
    ConfigDescriptorStore descriptors,
    ILogger<UnitLogFollower> logger) : IDisposable
{
    private const string Journalctl = "/usr/bin/journalctl";
    private const int QueueDepth = 500;

    private readonly Lock _gate = new();
    private readonly List<Channel<UnitLogLine>> _subscribers = [];
    private Process? _follow;
    private CancellationTokenSource? _stop;

    /// <summary>
    /// Watch the journal. The reader is the caller's to drain; disposing the returned handle leaves,
    /// and the last one to leave stops the follow.
    /// </summary>
    public (ChannelReader<UnitLogLine> Lines, IDisposable Handle)? Watch()
    {
        if (descriptors.Current() is not { Unit.Length: > 0 } || !File.Exists(Journalctl))
            return null;

        var channel = Channel.CreateBounded<UnitLogLine>(new BoundedChannelOptions(QueueDepth)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });

        lock (_gate)
        {
            _subscribers.Add(channel);
            if (_subscribers.Count == 1)
                Start();
        }

        return (channel.Reader, new Leaver(this, channel));
    }

    private void Leave(Channel<UnitLogLine> channel)
    {
        lock (_gate)
        {
            if (!_subscribers.Remove(channel))
                return;

            channel.Writer.TryComplete();
            if (_subscribers.Count == 0)
                Stop();
        }
    }

    /// <summary>Called under the lock.</summary>
    private void Start()
    {
        if (descriptors.Current() is not { Unit.Length: > 0 } descriptor)
            return;

        try
        {
            var psi = new ProcessStartInfo(Journalctl)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-f");
            psi.ArgumentList.Add("-n");
            psi.ArgumentList.Add("0");
            psi.ArgumentList.Add("-u");
            psi.ArgumentList.Add(descriptor.Unit);
            psi.ArgumentList.Add("--no-pager");
            psi.ArgumentList.Add("-o");
            psi.ArgumentList.Add("json");

            Process? proc = Process.Start(psi);
            if (proc is null)
            {
                logger.LogWarning("could not start a journal follow for {Unit}", descriptor.Unit);
                return;
            }

            _follow = proc;
            _stop = new CancellationTokenSource();
            _ = Task.Run(() => Pump(proc, descriptor.Id, _stop.Token));
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "could not follow the journal for {Unit}", descriptor.Unit);
        }
    }

    /// <summary>Called under the lock.</summary>
    private void Stop()
    {
        try { _stop?.Cancel(); } catch { /* already gone */ }
        try { if (_follow is { HasExited: false }) _follow.Kill(entireProcessTree: true); }
        catch { /* it ended on its own */ }

        _follow?.Dispose();
        _follow = null;
        _stop?.Dispose();
        _stop = null;
    }

    private void Pump(Process proc, string source, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && proc.StandardOutput.ReadLine() is { } raw)
            {
                if (UnitLogReader.Parse(raw, source) is not { } line)
                    continue;

                lock (_gate)
                {
                    foreach (Channel<UnitLogLine> c in _subscribers)
                        c.Writer.TryWrite(line);
                }
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "the journal follow ended");
        }

        // The follow ended on its own — journalctl exited, or the journal became unreadable. Every
        // watcher is completed rather than left waiting on a stream that will never carry anything,
        // so each one closes its own connection and the panel says the tail stopped.
        lock (_gate)
        {
            foreach (Channel<UnitLogLine> c in _subscribers)
                c.Writer.TryComplete();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            foreach (Channel<UnitLogLine> c in _subscribers)
                c.Writer.TryComplete();
            _subscribers.Clear();
            Stop();
        }
    }

    private sealed class Leaver(UnitLogFollower owner, Channel<UnitLogLine> channel) : IDisposable
    {
        private int _left;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _left, 1) == 0)
                owner.Leave(channel);
        }
    }
}
