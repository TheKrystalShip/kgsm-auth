using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// This anchor's own journal — the read, and the live tail beside it.
/// </summary>
/// <remarks>
/// An anchor on the ordinary topology has no Control Panel on its machine, so the daemon that would
/// be read <i>about</i> is the one being asked. Both halves are therefore admin-only and both refuse
/// by name when the host cannot produce a journal at all: a surface that hangs instead is one a
/// person watches waiting for lines that were never coming.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class UnitLogTests(AnchorFixture anchor)
{
    private const string Long = "a long enough password";
    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string Unique(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<string> BearerAsync(KgsmTier tier)
    {
        string username = Unique("log");
        await anchor.SeedAsync(username, Long, tier);

        HttpResponseMessage response = await anchor.Client.PostAsJsonAsync(
            "/auth/sign-in", new { username, password = Long }, Wire);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return (await response.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("token").GetString()!;
    }

    private async Task<HttpResponseMessage> GetAsync(string path, string? bearer)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);

        return await anchor.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
    }

    [Theory]
    [InlineData("/auth/logs")]
    [InlineData("/auth/logs/stream")]
    public async Task Nobody_reads_this_journal_without_saying_who_they_are(string path)
    {
        using HttpResponseMessage response = await GetAsync(path, bearer: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/auth/logs")]
    [InlineData("/auth/logs/stream")]
    public async Task A_viewer_does_not_read_the_daemon_holding_everybody_s_account(string path)
    {
        // A daemon's log carries usernames, addresses and the shape of every failure it has had —
        // which is the account store described from the side, to somebody the store says may read
        // nothing about anybody else.
        using HttpResponseMessage response = await GetAsync(path, await BearerAsync(KgsmTier.Viewer));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("/auth/logs")]
    [InlineData("/auth/logs/stream")]
    public async Task A_host_with_no_journal_to_offer_says_so(string path)
    {
        // No descriptor is installed under a test root, so neither half can name a unit to read. The
        // answer has to be a refusal with a code on it: an empty page and a stream that opens and
        // stays silent both render as an anchor that has never logged anything.
        using HttpResponseMessage response = await GetAsync(path, await BearerAsync(KgsmTier.Admin));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);

        JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("journal_unreadable", body.GetProperty("error").GetProperty("code").GetString());
    }
}
