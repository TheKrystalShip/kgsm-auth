using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>One line of this anchor's journal, in the shape every KGSM log surface renders.</summary>
/// <remarks>
/// The shape is kgsm-api's, key for key, so the panel's console renders an anchor's journal and a
/// leaf's through one component. A node's journal is read by the API on that node; an anchor has no
/// node above it, so it reads its own — which is the same reason it serves its own configuration.
/// </remarks>
internal sealed record UnitLogLine(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("at")] string At,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("level")] string Level,
    [property: JsonPropertyName("text")] string Text);

internal sealed record UnitLogPage(
    [property: JsonPropertyName("data")] IReadOnlyList<UnitLogLine> Data);

/// <summary>
/// Reads this anchor's own journal, by shelling <c>journalctl</c> for its unit.
/// </summary>
/// <remarks>
/// <para>
/// <b>The unit is the descriptor's</b>, not a second setting: the descriptor already names the unit
/// that carries this daemon, and two records of one fact disagree the first time one is edited.
/// </para>
/// <para>
/// <b>Reading a journal needs to be granted.</b> Without membership of <c>systemd-journal</c>,
/// <c>journalctl</c> exits 0 having printed nothing — a success that looks exactly like a unit which
/// has logged nothing — so the unit carries <c>SupplementaryGroups=systemd-journal</c> and an empty
/// read is reported as empty rather than dressed up.
/// </para>
/// </remarks>
internal sealed class UnitLogReader(ConfigDescriptorStore descriptors, ILogger<UnitLogReader> logger)
{
    private const string Journalctl = "/usr/bin/journalctl";
    private const int MaxLines = 2000;
    private const int DefaultLines = 300;

    /// <summary>The last <paramref name="lines"/> of this unit's journal, oldest first. Null when
    /// there is no unit to read or no journalctl to read it with — which is a different answer from
    /// a unit that has logged nothing, and is reported as one.</summary>
    public IReadOnlyList<UnitLogLine>? Read(int? lines)
    {
        if (descriptors.Current() is not { Unit.Length: > 0 } descriptor)
            return null;

        if (!File.Exists(Journalctl))
            return null;

        int count = Math.Clamp(lines ?? DefaultLines, 1, MaxLines);

        try
        {
            var psi = new ProcessStartInfo(Journalctl)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-u");
            psi.ArgumentList.Add(descriptor.Unit);
            psi.ArgumentList.Add("-n");
            psi.ArgumentList.Add(count.ToString());
            psi.ArgumentList.Add("--no-pager");
            psi.ArgumentList.Add("-o");
            psi.ArgumentList.Add("json");

            using Process? proc = Process.Start(psi);
            if (proc is null)
                return null;

            var read = new List<UnitLogLine>(count);
            while (proc.StandardOutput.ReadLine() is { } raw)
            {
                if (Parse(raw, descriptor.Id) is { } line)
                    read.Add(line);
            }

            if (!proc.WaitForExit(10000))
            {
                logger.LogWarning("journalctl did not finish reading {Unit}", descriptor.Unit);
                return null;
            }

            return read;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "could not read the journal for {Unit}", descriptor.Unit);
            return null;
        }
    }

    /// <summary>
    /// One journald record. Parsed with <see cref="JsonDocument"/> rather than a generated type
    /// because the fields wanted are three of many and their names are journald's, not a shape worth
    /// declaring — and because it costs the AOT build no reflection either way.
    /// </summary>
    private static UnitLogLine? Parse(string raw, string source)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(raw);
            JsonElement root = doc.RootElement;

            if (!root.TryGetProperty("MESSAGE", out JsonElement message))
                return null;

            // journald stamps microseconds since the epoch, as a string.
            string at = root.TryGetProperty("__REALTIME_TIMESTAMP", out JsonElement stamp)
                        && long.TryParse(stamp.GetString(), out long micros)
                ? DateTimeOffset.FromUnixTimeMilliseconds(micros / 1000).UtcDateTime.ToString("o")
                : "";

            string priority = root.TryGetProperty("PRIORITY", out JsonElement p) ? p.GetString() ?? "6" : "6";
            string cursor = root.TryGetProperty("__CURSOR", out JsonElement c) ? c.GetString() ?? at : at;

            return new UnitLogLine(cursor, at, source, LevelOf(priority), Text(message));
        }
        catch
        {
            // A record this build cannot read is dropped rather than shown as a line of noise. It is
            // one line of a journal, and failing the whole read over it would lose the rest.
            return null;
        }
    }

    /// <summary>A MESSAGE is a string, or an array of bytes when it is not valid UTF-8.</summary>
    private static string Text(JsonElement message)
    {
        if (message.ValueKind == JsonValueKind.String)
            return message.GetString() ?? "";

        if (message.ValueKind != JsonValueKind.Array)
            return "";

        var bytes = new List<byte>();
        foreach (JsonElement b in message.EnumerateArray())
        {
            if (b.TryGetByte(out byte value))
                bytes.Add(value);
        }
        return System.Text.Encoding.UTF8.GetString([.. bytes]);
    }

    /// <summary>Syslog priority → the level word every KGSM log surface renders.</summary>
    private static string LevelOf(string priority) => priority switch
    {
        "0" or "1" or "2" or "3" => "error",
        "4" => "warn",
        "7" => "debug",
        _ => "info",
    };
}

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

        var reader = ctx.RequestServices.GetRequiredService<UnitLogReader>();
        if (reader.Read(lines) is not { } read)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "journal_unreadable",
                "This anchor's journal could not be read on this host.");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, new UnitLogPage(read),
            AnchorJsonContext.Default.UnitLogPage);
    }
}
