using System.Reflection;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.KGSM.Cluster.Membership;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// What this is, and what cluster it holds the accounts for.
/// </summary>
/// <remarks>
/// <para>
/// <b>A client is given one address and nothing else.</b> A panel deployed anywhere — a bucket, a
/// static host, a laptop — knows about no cluster until somebody types an address into it, and it has
/// to establish what is behind that address before it can do anything with it. These two answer that:
/// what this is, and once somebody has signed in, what the cluster contains.
/// </para>
/// <para>
/// <b>A member of a cluster answers neither.</b> Announcing the cluster is the anchor's job precisely
/// because the anchor is where a person signs in, so a client that has reached one has already
/// demonstrated it was told the right address. A node that offered the same answers would be a way to
/// discover a cluster's authority by finding any machine in it.
/// </para>
/// </remarks>
internal static class DiscoveryEndpoints
{
    private static readonly string Build =
        typeof(DiscoveryEndpoints).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion
        ?? typeof(DiscoveryEndpoints).Assembly.GetName().Version?.ToString()
        ?? "";

    /// <summary>What this daemon is.</summary>
    /// <remarks>
    /// Unauthenticated, because a caller with no session is exactly who is asking. It names a kind, a
    /// cluster and a build — never a member, never an address. What the cluster contains is behind a
    /// session, because knowing which machines exist is not something an address alone should buy.
    /// </remarks>
    internal static Task Identity(HttpContext ctx)
    {
        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        var role = ctx.RequestServices.GetRequiredService<AnchorRole>();

        return Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new AnchorIdentity(AnchorJournal.ProducerId, options.ClusterId, Build, role.IsAuthority),
            AnchorJsonContext.Default.AnchorIdentity);
    }

    /// <summary>Every member of this cluster, at addresses a browser can reach.</summary>
    /// <remarks>
    /// <para>
    /// Authenticated at the floor: any account may see the machines it might be able to drive, and
    /// what it may then <em>do</em> on each is that member's own answer per request. Gating this at a
    /// higher tier would leave somebody signed in and unable to see anything, which reads as a broken
    /// panel rather than as a permission.
    /// </para>
    /// <para>
    /// <b>Browser addresses, never peer-to-peer ones.</b> The roster carries both — the address this
    /// anchor proved it can reach across a switch, and the one a member says a browser should use —
    /// and only the second belongs in an answer to a browser. A secure page cannot fetch a plaintext
    /// origin at all, so handing over the first registers a connection that can only ever read as
    /// down, and a panel then reports a healthy machine as one that did not answer.
    /// </para>
    /// <para>
    /// A member advertising no browser address is <b>left out</b> rather than given its peer address.
    /// It is genuinely not drivable from a browser, and saying so by omission is honest where handing
    /// over an unusable address is a machine that appears present and never works.
    /// </para>
    /// </remarks>
    internal static async Task Roster(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.None) is null)
            return;

        AnchorOptions options = ctx.RequestServices.GetRequiredService<AnchorOptions>();
        IReadOnlyList<MemberRow> rows = await ctx.RequestServices
            .GetRequiredService<MembersStore>()
            .ListEnabledAsync(ctx.RequestAborted);

        var members = new List<ClusterMemberRecord>(rows.Count);
        foreach (MemberRow row in rows)
        {
            if (BrowserUrl(row) is not { Length: > 0 } url)
                continue;

            members.Add(new ClusterMemberRecord(
                row.MemberId,
                row.Kind,
                url,
                row.Nickname,
                row.Status,
                row.MembershipState));
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new ClusterRoster(options.ClusterId, members),
            AnchorJsonContext.Default.ClusterRoster);
    }

    /// <summary>
    /// The address a browser can reach a member at, or empty when it advertises none.
    /// </summary>
    /// <remarks>
    /// Deliberately no fallback to <see cref="MemberRow.Url"/>. That is the address <em>this member</em>
    /// proved it could reach, which on a real deployment is a LAN address a page served over HTTPS is
    /// forbidden to fetch — and a fallback would turn "not reachable from a browser" into "reachable,
    /// and permanently down".
    /// </remarks>
    private static string BrowserUrl(MemberRow row) =>
        MemberCandidates.ClientUrl(MemberCandidates.Decode(row.Candidates));
}
