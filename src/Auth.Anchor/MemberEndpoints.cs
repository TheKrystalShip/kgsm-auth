using System.Text.Json;

using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster;

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
    /// Every account this anchor holds, each with the version it is at.
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
        // secret — a member an admin removed can still mint a token that validates perfectly, and
        // only the roster says it is still welcome. A null answer has already written the refusal.
        if (await ClusterRequest.AuthenticateAsync(ctx) is null)
            return;

        var store = ctx.RequestServices.GetRequiredService<IUserStore>();
        var versions = ctx.RequestServices.GetRequiredService<IAccountVersions>();

        IReadOnlyList<KgsmUser> users = await store.ListAsync(ctx.RequestAborted);
        IReadOnlyDictionary<string, long> held = await versions.AllAsync(ctx.RequestAborted);

        var accounts = new List<AccountChange>(users.Count);
        foreach (KgsmUser user in users)
        {
            IReadOnlyList<UserCredential> credentials =
                await store.ListCredentialsAsync(user.UserId, ctx.RequestAborted);

            // An account nobody has changed since this anchor started counting has no version row.
            // It is published at 1 rather than 0, because 0 is the value a replica holds for "never
            // heard of" and a change at 0 could never be newer than anything.
            long version = held.TryGetValue(user.UserId, out long v) ? v : 1;

            accounts.Add(new AccountChange(ReplicatedAccount.From(user, credentials), version));
        }

        ctx.Response.StatusCode = StatusCodes.Status200OK;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        await JsonSerializer.SerializeAsync(
            ctx.Response.Body, new AccountSnapshot(accounts),
            AccountReplicationJson.Default.AccountSnapshot, ctx.RequestAborted);
    }

    private static Task Refuse(HttpContext ctx, int status, string code, string message)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(
            ctx.Response.Body, new ErrorEnvelope(new ErrorBody(code, message)),
            AnchorJsonContext.Default.ErrorEnvelope, ctx.RequestAborted);
    }
}
