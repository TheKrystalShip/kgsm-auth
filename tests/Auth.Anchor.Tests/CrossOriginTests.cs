using System.Net;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// What a browser on another origin is allowed to read here.
/// </summary>
/// <remarks>
/// <para>
/// A registered client's origin reads the provider's published documents, the token exchange, the
/// account behind a bearer, the administration a panel drives and this anchor's own surface — without
/// credentials, since a session travels as a bearer. Nothing that reads the provider's cookie is ever
/// answered across origins, and an origin that is no client's is answered nothing at all.
/// </para>
/// <para>
/// Every refusal here happens in the browser, before this daemon sees the request, so a test is the only
/// place a missing allowance shows up as anything but a broken endpoint.
/// </para>
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class CrossOriginTests(AnchorFixture anchor)
{
    private async Task<HttpResponseMessage> PreflightAsync(
        string path, string origin, string method = "GET", string? headers = null)
    {
        using var preflight = new HttpRequestMessage(HttpMethod.Options, path);
        preflight.Headers.Add("Origin", origin);
        preflight.Headers.Add("Access-Control-Request-Method", method);
        if (headers is not null)
            preflight.Headers.Add("Access-Control-Request-Headers", headers);
        return await anchor.Client.SendAsync(preflight);
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/token")]
    [InlineData("/userinfo")]
    [InlineData("/auth/cluster/users")]
    [InlineData("/auth/identity")]
    [InlineData("/auth/config")]
    [InlineData("/auth/logs/stream")]
    public async Task A_client_origin_reads_what_a_client_reads_across_origins(string path)
    {
        HttpResponseMessage response = await PreflightAsync(path, AnchorFixture.PanelUrl);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(AnchorFixture.PanelUrl, response.Headers.GetValues("Access-Control-Allow-Origin").Single());

        // A bearer is what authorizes these, so an allowance with credentials would buy nothing but
        // the risk.
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
    }

    [Theory]
    [InlineData("/authorize/credentials")]
    [InlineData("/account/me")]
    [InlineData("/account/password")]
    [InlineData("/sign-out")]
    public async Task Nothing_that_reads_the_provider_cookie_is_answered_across_origins(string path)
    {
        HttpResponseMessage response = await PreflightAsync(path, AnchorFixture.PanelUrl, "POST");

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task An_origin_that_is_no_client_is_answered_nothing()
    {
        HttpResponseMessage response = await PreflightAsync("/auth/cluster/users", "https://elsewhere.test");

        // No allowance header at all, and never a wildcard on a surface that mints credentials.
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Every_method_a_door_here_answers_is_allowed()
    {
        HttpResponseMessage response = await PreflightAsync(
            "/auth/cluster/users/anything", AnchorFixture.PanelUrl, "DELETE");
        string allowed = response.Headers.GetValues("Access-Control-Allow-Methods").Single();

        // A method missing here is refused by the browser at the preflight, which this daemon never
        // sees and no log records. Deleting an account is a DELETE, changing this anchor's own
        // configuration a PUT, and both are reached from a panel on another origin.
        foreach (string method in new[] { "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" })
            Assert.Contains(method, allowed);
    }

    [Fact]
    public async Task A_header_a_client_intends_to_send_is_allowed_whatever_it_is_called()
    {
        HttpResponseMessage response = await PreflightAsync(
            "/auth/cluster/users", AnchorFixture.PanelUrl, headers: "authorization,x-krystal-device");
        string allowed = response.Headers.GetValues("Access-Control-Allow-Headers").Single();

        // A browser states exactly what it intends to send and refuses the request when the answer
        // omits one. A fixed list would have to grow every time any client grows a header, and each
        // omission would present itself as a broken endpoint.
        Assert.Contains("x-krystal-device", allowed, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("authorization", allowed, StringComparison.OrdinalIgnoreCase);

        // The answer depends on what was asked for, so a cache keyed on the URL and origin alone would
        // serve one client's allowance to another that asked for more.
        Assert.Contains("Access-Control-Request-Headers", response.Headers.GetValues("Vary"));
    }

    [Fact]
    public async Task A_preflight_that_names_no_headers_still_allows_the_ordinary_two()
    {
        HttpResponseMessage response = await PreflightAsync("/auth/cluster/users", AnchorFixture.PanelUrl);
        string allowed = response.Headers.GetValues("Access-Control-Allow-Headers").Single();

        // Reflecting nothing would answer with an empty allowance, which is a refusal spelled as a
        // permission.
        Assert.Contains("Authorization", allowed, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Content-Type", allowed, StringComparison.OrdinalIgnoreCase);
    }
}
