using Microsoft.AspNetCore.Http;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The gate in front of what this anchor answers about <b>itself</b> — its configuration, its unit,
/// its journal and the commands it declares.
/// </summary>
/// <remarks>
/// <para>
/// Admin, for the reason every account surface here is: the values name where the account store and
/// the signing key live, and the journal carries usernames, addresses and the shape of every failure
/// this daemon has had.
/// </para>
/// <para>
/// Authority first. A member that is not the one holding <c>auth</c> answers <c>503</c> and names the
/// holder, so a client routes to the member that can answer rather than retrying against one that
/// never will — and it does so before a tier is resolved, because resolving one needs the authority
/// this member does not have.
/// </para>
/// <para>
/// A filter rather than two calls at the top of each handler: the routes are the shared library's, so
/// there is no handler here to put them in, and a gate that has to be repeated is a gate that will
/// eventually be missed off one endpoint.
/// </para>
/// </remarks>
internal sealed class OwnSurfaceFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        HttpContext ctx = context.HttpContext;

        // Both helpers write their own refusal, so there is nothing left to return but the empty
        // result that stops the pipeline without writing over what they said.
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return Results.Empty;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return Results.Empty;

        return await next(context);
    }
}
