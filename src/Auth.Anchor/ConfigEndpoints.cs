namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// This anchor's own configuration surface — read and changed here, because there is nowhere else it
/// could be.
/// </summary>
/// <remarks>
/// A leaf is configured through the node that runs it: the node's API scans its disk for descriptors
/// and delivers a change to a process on the same machine. An anchor is a peer of every node rather
/// than something one of them hosts, and is reached by address from a browser that is usually nowhere
/// near it — so it answers for its own configuration, on the origin the panel already talks to it on
/// for accounts and sessions.
/// </remarks>
internal static class ConfigEndpoints
{
    /// <summary>
    /// <c>GET /auth/config</c> — what this anchor can be configured with, and what it is running on.
    /// Admin, like every account surface here: the values name where the account store and the
    /// signing key live.
    /// </summary>
    internal static async Task Read(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        var service = ctx.RequestServices.GetRequiredService<AnchorConfigService>();
        if (service.Read() is not { } config)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_descriptor",
                "This anchor has no config descriptor installed, so it describes no configuration surface.");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, config, AnchorJsonContext.Default.AnchorConfig);
    }

    /// <summary>
    /// <c>PUT /auth/config</c> — set or reset keys, then restart to pick them up.
    /// </summary>
    /// <remarks>
    /// The restart is queued before this answer is written, and the answer still arrives: systemd
    /// stops the unit with SIGTERM, the host drains the requests already in flight, and this is one
    /// of them. Queueing first is what lets the answer carry whether systemd accepted the job —
    /// <c>restarting: false</c> means the change is written and is NOT in force, which is a different
    /// state from a change that is being applied and a person has to be told which they are in.
    /// </remarks>
    internal static async Task Apply(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return;

        if (await Endpoints.RequireCaller(ctx, KgsmTier.Admin) is null)
            return;

        AnchorConfigUpdate? body = await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.AnchorConfigUpdate);
        if (body is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request",
                "The request body is not readable.");
            return;
        }

        var service = ctx.RequestServices.GetRequiredService<AnchorConfigService>();
        (AnchorConfigApplyResult? result, string? error) = service.Apply(body);

        if (error is not null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_value", error);
            return;
        }

        if (result is null)
        {
            await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_descriptor",
                "This anchor has no config descriptor installed, so there is nothing to configure.");
            return;
        }

        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK, result,
            AnchorJsonContext.Default.AnchorConfigApplyResult);
    }
}
