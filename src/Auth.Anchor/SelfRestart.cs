using System.Diagnostics;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// Bounces this daemon so a configuration change takes effect.
/// </summary>
/// <remarks>
/// <para>
/// <b>The ask has to outlive the asker.</b> <c>systemctl restart</c> without <c>--no-block</c> waits
/// for the job it queued, so systemd stops this process while <c>systemctl</c> is still waiting on
/// it and the job is left in whatever state the kill found. With <c>--no-block</c> the job is queued
/// and the command returns at once — systemd owns it from that moment, and this process going away
/// is the job proceeding rather than the job being lost.
/// </para>
/// <para>
/// <b>The answer still reaches the caller.</b> Queueing returns in milliseconds and systemd then
/// stops the unit with SIGTERM, which is a graceful shutdown: the host drains the requests already in
/// flight before the process ends, and the one that asked for this is one of them. So the restart is
/// queued BEFORE the response is written, which is what lets the response carry whether it was
/// accepted — a refusal is a change written and not in force, and that is a state a person has to be
/// told they are in rather than left to infer from a connection that closed.
/// </para>
/// <para>
/// The privilege is a scoped polkit rule for this unit and the restart verbs alone. Under
/// <c>deploy.sh</c> the service user and the deploying user are the same account, so the grant that
/// makes a headless deploy possible already covers this; a packaged install runs as its own account
/// and carries its own rule. Where neither is in place the surface reports itself uneditable rather
/// than writing a change that would never take effect.
/// </para>
/// </remarks>
internal sealed class SelfRestart(ILogger<SelfRestart> logger)
{
    private const string Systemctl = "/usr/bin/systemctl";

    /// <summary>
    /// Whether a change could be delivered at all, and why not when it could not. Asked before an
    /// edit is offered, because a form that saves into a daemon that will never read the value is
    /// worse than a form that is not offered.
    /// </summary>
    public bool Available(string? unit, out string? why)
    {
        if (string.IsNullOrWhiteSpace(unit))
        {
            why = "This anchor's descriptor names no systemd unit, so a change could not be applied.";
            return false;
        }

        if (!File.Exists(Systemctl))
        {
            why = "systemctl is not on this host, so a change could not be applied.";
            return false;
        }

        why = null;
        return true;
    }

    /// <summary>
    /// Queue the restart, after the answer has left. Returns whether systemd accepted the job —
    /// false is reported to the caller rather than swallowed, because a change that is written and
    /// not in force is a state a person needs to know they are in.
    /// </summary>
    public bool Schedule(string unit)
    {
        if (!Available(unit, out _))
            return false;

        try
        {
            var psi = new ProcessStartInfo(Systemctl)
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };
            psi.ArgumentList.Add("restart");
            psi.ArgumentList.Add("--no-block");
            psi.ArgumentList.Add(unit);

            using Process? proc = Process.Start(psi);
            if (proc is null)
            {
                logger.LogError("could not run systemctl to restart {Unit}", unit);
                return false;
            }

            // --no-block returns as soon as the job is enqueued, so this waits on the enqueueing and
            // not on the restart. A refusal here is polkit's, and it is the one worth reporting.
            if (!proc.WaitForExit(5000))
            {
                logger.LogError("systemctl did not return while queueing a restart of {Unit}", unit);
                return false;
            }

            if (proc.ExitCode != 0)
            {
                logger.LogError("systemctl refused to restart {Unit}: {Error}",
                    unit, proc.StandardError.ReadToEnd().Trim());
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "could not queue a restart of {Unit}", unit);
            return false;
        }
    }
}
