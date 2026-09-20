using TheKrystalShip.Api.Contracts;
using TheKrystalShip.KGSM.ComponentSurface;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// This anchor's own configuration surface — read and changed here, because there is nowhere else it
/// could be.
/// </summary>
/// <remarks>
/// <para>
/// A component owns its own configuration wherever it runs; what differs is the way a browser reaches
/// it. A leaf is reached through the node that runs it, which relays to the socket it already serves.
/// An anchor is a peer of every node rather than something one of them hosts, and is reached by
/// address from a browser that is usually nowhere near it — so it answers here, on the origin the
/// panel already talks to it on for accounts and sessions.
/// </para>
/// <para>
/// Everything below the transport is <see cref="ComponentConfigService"/>, the one implementation of
/// the descriptor's rules.
/// </para>
/// </remarks>
internal static class ConfigEndpoints
{
    /// <summary>
    /// <c>GET /auth/config</c> — what this anchor can be configured with, and what it is running on.
    /// Admin, like every account surface here: the values name where the account store and the signing
    /// key live.
    /// </summary>
    internal static async Task Read(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        var service = ctx.RequestServices.GetRequiredService<ComponentConfigService>();
        if (service.Read() is not { } config)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_descriptor",
                "This anchor has no config descriptor installed, so it describes no configuration surface.");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, config,
            ApiContractsJson.Default.ComponentConfigView);
    }

    /// <summary>
    /// <c>PUT /auth/config</c> — set or reset keys, then restart to pick them up.
    /// </summary>
    /// <remarks>
    /// The restart is queued before this answer is written, and the answer still arrives: systemd stops
    /// the unit with SIGTERM, the host drains the requests already in flight, and this is one of them.
    /// Queueing first is what lets the answer carry whether systemd accepted the job — a refused
    /// restart means the change is written and is NOT in force, which is a different state from one
    /// being applied and a person has to be told which they are in.
    /// </remarks>
    internal static async Task Apply(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        ComponentConfigUpdate? body =
            await Endpoints.ReadBodyAsync(ctx, ApiContractsJson.Default.ComponentConfigUpdate);
        if (body is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request",
                "The request body is not readable.");
            return;
        }

        var service = ctx.RequestServices.GetRequiredService<ComponentConfigService>();
        (ComponentApplyOutcome? outcome, string? error) = service.Apply(body);

        if (error is not null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_value", error);
            return;
        }

        if (outcome is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_descriptor",
                "This anchor has no config descriptor installed, so there is nothing to configure.");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, outcome.Result,
            ApiContractsJson.Default.ComponentConfigApplyResult);
    }

    /// <summary>
    /// <c>GET /auth/system</c> — what systemd reports about this anchor's own unit.
    /// </summary>
    /// <remarks>
    /// The row a node's API reads for each of its leaves, read here by the component itself because no
    /// node above it will. Same shape either way, so one panel component renders both.
    /// </remarks>
    internal static async Task System(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        var units = ctx.RequestServices.GetRequiredService<ComponentUnitReader>();
        if (await units.ReadAsync(ctx.RequestAborted) is not { } row)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_descriptor",
                "This anchor has no config descriptor installed, so it names no unit to report on.");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, row,
            ApiContractsJson.Default.ComponentService);
    }
}
