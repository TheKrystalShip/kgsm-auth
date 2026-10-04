namespace TheKrystalShip.Auth.Cluster.Tests;

/// <summary>
/// The two statements a provider and its surfaces must spell identically: what a surface's client id
/// is, and which origins the registered clients live at.
/// </summary>
public sealed class ClusterClientsTests
{
    [Theory]
    [InlineData("https://kgsm.thekrystalship.com", "kgsm.thekrystalship.com")]
    [InlineData("https://KGSM.Example.com/", "kgsm.example.com")]
    [InlineData("http://192.168.1.10:8080", "192.168.1.10-8080")]
    [InlineData("https://walter.nodes.example.com:443", "walter.nodes.example.com")]
    [InlineData("http://127.0.0.1:8080/signed-in", "127.0.0.1-8080")]
    public void A_surface_s_client_id_is_its_origin_s_host(string origin, string expected)
    {
        // A surface derives it from where it was loaded and the provider from the address it registered,
        // so a panel on a static host needs to be told nothing to sign in through any member.
        Assert.Equal(expected, ClusterClientAnnouncement.ClientIdFor(origin));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("kgsm.example.com")]
    [InlineData("ftp://kgsm.example.com")]
    [InlineData("http://[::1]:8080")]
    public void Something_that_is_not_an_http_origin_names_no_client(string? origin)
    {
        Assert.Null(ClusterClientAnnouncement.ClientIdFor(origin));
    }

    [Fact]
    public void The_origins_fact_is_sorted_and_unique_so_an_unchanged_registry_states_nothing_new()
    {
        string once = ClusterClientOrigins.ToJson(["https://b.test", "https://a.test/", "https://B.test"]);
        string again = ClusterClientOrigins.ToJson(["https://a.test", "https://b.test"]);

        Assert.Equal(once, again);
        Assert.Equal(["https://a.test", "https://b.test"], ClusterClientOrigins.Read(once));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{\"origins\":[]}")]
    public void A_fact_that_is_not_a_list_of_origins_admits_nothing(string? value)
    {
        Assert.Empty(ClusterClientOrigins.Read(value));
    }

    [Fact]
    public void An_origin_is_written_as_a_browser_sends_it()
    {
        // A browser sends scheme, host and a non-default port, lowercased, with no slash; anything else
        // stored would match no request and read as an origin admitted and not.
        Assert.Equal("https://kgsm.example.com", ClusterClientOrigins.Normalize("https://KGSM.example.com/"));
        Assert.Equal("http://10.44.0.4:8097", ClusterClientOrigins.Normalize("http://10.44.0.4:8097/api"));
        Assert.Null(ClusterClientOrigins.Normalize("kgsm.example.com"));
    }
}
