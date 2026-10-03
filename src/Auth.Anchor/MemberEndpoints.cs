using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;
using TheKrystalShip.Api.Contracts;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// What this anchor serves to other <em>members</em>, as opposed to what it serves to people.
/// </summary>
/// <remarks>
/// <para>
/// A different door from everything in <see cref="Endpoints"/>: no person is on either end, the
/// caller is a member proving itself with a service token, and the answer is state rather than a
/// session. It carries no credential of anybody's — a replica is given who somebody is and what they
/// may do, never anything that could authenticate them.
/// </para>
/// <para>
/// The cluster package owns the protocol's own routes and authenticates them itself. This is a route
/// of this member's own, on the same terms — the token check and the enabled-member gate — because
/// what it answers is this member's accounts rather than any part of the cluster protocol.
/// </para>
/// </remarks>
internal static class MemberEndpoints
{
    /// <summary>
    /// Every account this anchor holds and everything that decides what they may do, each record at the
    /// version it was last written at, confirmed current as of this answer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What a member takes before it follows the stream, so a member added on Tuesday is not missing
    /// what happened on Monday.
    /// </para>
    /// <para>
    /// It needs no consistency with the stream beyond the version on each row. A change landing while
    /// this is being read arrives on the bus as well, and whichever is applied second is dropped if it
    /// is older — so the two paths cannot leave a replica holding a torn state however they interleave.
    /// </para>
    /// </remarks>
    internal static async Task Snapshot(HttpContext ctx)
    {
        // The cluster package's own check, not a second copy of it: the token's signature, then the
        // enabled-member gate. The gate matters as much as the signature, because members share one
        // secret — a member somebody removed can still mint a token that validates perfectly, and
        // only the roster says it is still welcome. A null answer has already written the refusal.
        if (await ClusterRequest.AuthenticateAsync(ctx) is null)
            return;

        AnchorAuthority authority = ctx.RequestServices.GetRequiredService<AnchorAuthority>();
        if (authority.Store is not { } store)
        {
            await Refuse(ctx, StatusCodes.Status503ServiceUnavailable, "authority_unavailable",
                authority.UnavailableReason ?? "The account store holds no authority.");
            return;
        }

        AuthorityReplicaSnapshot snapshot = await store.ExportAsync(
            ctx.RequestServices.GetRequiredService<AnchorOptions>().StalenessBound, DateTimeOffset.UtcNow,
            ctx.RequestAborted);

        ctx.Response.StatusCode = StatusCodes.Status200OK;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        await JsonSerializer.SerializeAsync(
            ctx.Response.Body, snapshot, AuthorityReplicationJson.Default.AuthorityReplicaSnapshot, ctx.RequestAborted);
    }

    private static Task Refuse(HttpContext ctx, int status, string code, string message)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(
            ctx.Response.Body, new ErrorEnvelope(new ErrorBody(code, message)),
            ApiContractsJson.Default.ErrorEnvelope, ctx.RequestAborted);
    }
}
