using TheKrystalShip.Auth.Access;

namespace TheKrystalShip.Auth.Anchor;

/// <summary>An application as the admin surface and the host command list it.</summary>
/// <param name="Id">Its id and action namespace.</param>
/// <param name="Name">What a person is shown.</param>
/// <param name="Audience">Its access tokens' audience.</param>
/// <param name="ManifestUrl">Where it serves its action manifest, or null.</param>
/// <param name="AccessLifetimeMinutes">Its access tokens' lifetime.</param>
/// <param name="DiscordApplications">The Discord applications its clients may present.</param>
/// <param name="ActForDiscord">Whether it may act for linked Discord users.</param>
/// <param name="ActionsClaim">The claim its access tokens list its actions in, or null for KGSM's, which list none.</param>
/// <param name="Source"><c>builtin</c> for KGSM, <c>admin</c> for one registered here.</param>
/// <param name="Created">When it was registered.</param>
/// <param name="Clients">The clients it signs people in through. Never a secret in any form.</param>
/// <param name="Manifest">What the last reading of its manifest came to, when this process has read it.</param>
internal sealed record ApplicationRecord(
    string Id,
    string Name,
    string Audience,
    string? ManifestUrl,
    int AccessLifetimeMinutes,
    IReadOnlyList<string> DiscordApplications,
    bool ActForDiscord,
    string? ActionsClaim,
    string Source,
    DateTimeOffset Created,
    IReadOnlyList<ApplicationClientRecord> Clients,
    ApplicationManifestRecord? Manifest);

/// <summary>A client of an application.</summary>
/// <param name="ClientId">Its id.</param>
/// <param name="RedirectUris">Where codes may be sent.</param>
/// <param name="PostLogoutRedirectUris">Where a signed-out browser may be returned.</param>
/// <param name="Confidential">Whether it authenticates with a secret.</param>
/// <param name="Source">Where it came from: <c>admin</c>, or for KGSM's, <c>member</c> or <c>config</c> too.</param>
/// <param name="MemberId">The member announcing it, for a member's surface.</param>
internal sealed record ApplicationClientRecord(
    string ClientId,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris,
    bool Confidential,
    string Source,
    string? MemberId);

/// <summary>What the last reading of an application's manifest came to.</summary>
internal sealed record ApplicationManifestRecord(DateTimeOffset At, bool Taken, string? Problem, int Actions);

/// <summary>Every application, KGSM's first.</summary>
internal sealed record ApplicationsPage(IReadOnlyList<ApplicationRecord> Data);

/// <summary>An application after a change, and every secret the change made — shown here and never again.</summary>
internal sealed record ApplicationAnswer(ApplicationRecord Application, IReadOnlyList<IssuedSecret> Secrets);

/// <summary>
/// The admin surface for the applications this provider signs people in to, on
/// <c>auth:applications.manage</c>.
/// </summary>
/// <remarks>
/// <para>
/// Every change goes through <see cref="ApplicationRegistry"/>, the path the host command takes too, and
/// is journaled there with the person who made it.
/// </para>
/// <para>
/// An answer that carries a client secret is the only time that secret is shown, and is marked
/// <c>no-store</c> so nothing between here and the person keeps a copy.
/// </para>
/// </remarks>
internal static class ApplicationEndpoints
{
    /// <summary>Where the applications are administered.</summary>
    internal const string Route = "/auth/cluster/applications";

    /// <summary>Map the routes, each declaring the action it requires.</summary>
    internal static void Map(WebApplication app)
    {
        var manage = new AuthAction(AuthActions.ApplicationsManage);
        app.MapGet(Route, List).WithMetadata(manage);
        app.MapPost(Route, Add).WithMetadata(manage);
        app.MapPatch(Route + "/{applicationId}", Set).WithMetadata(manage);
        app.MapDelete(Route + "/{applicationId}", Remove).WithMetadata(manage);
        app.MapPost(Route + "/{applicationId}/clients", AddClient).WithMetadata(manage);
        app.MapDelete(Route + "/{applicationId}/clients/{clientId}", RemoveClient).WithMetadata(manage);
        app.MapPost(Route + "/{applicationId}/clients/{clientId}/secret", RotateSecret).WithMetadata(manage);
    }

    /// <summary><c>GET /auth/cluster/applications</c>.</summary>
    internal static async Task List(HttpContext ctx)
    {
        if (await CallerAsync(ctx) is null)
            return;

        var registry = ctx.RequestServices.GetRequiredService<ApplicationRegistry>();
        var catalog = ctx.RequestServices.GetRequiredService<ApplicationCatalog>();
        await Endpoints.WriteJson(ctx, StatusCodes.Status200OK,
            new ApplicationsPage([.. registry.All.Select(a => ToRecord(a, registry, catalog))]),
            AnchorJsonContext.Default.ApplicationsPage);
    }

    /// <summary><c>POST /auth/cluster/applications</c>: register an application and its clients.</summary>
    internal static async Task Add(HttpContext ctx)
    {
        if (await CallerAsync(ctx) is not { } actor)
            return;

        if (await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.ApplicationRequest) is not { } body)
        {
            await MalformedAsync(ctx);
            return;
        }

        ApplicationResult result = await ctx.RequestServices.GetRequiredService<ApplicationRegistry>()
            .AddAsync(body, actor, AnchorJournal.OriginUi, ctx.RequestAborted);
        await AnswerAsync(ctx, result, StatusCodes.Status201Created);
    }

    /// <summary><c>PATCH /auth/cluster/applications/{applicationId}</c>: change an application's own fields.</summary>
    internal static async Task Set(HttpContext ctx)
    {
        if (await CallerAsync(ctx) is not { } actor)
            return;

        if (await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.ApplicationChange) is not { } body)
        {
            await MalformedAsync(ctx);
            return;
        }

        ApplicationResult result = await ctx.RequestServices.GetRequiredService<ApplicationRegistry>()
            .SetAsync(RouteValue(ctx,"applicationId"), body, actor, AnchorJournal.OriginUi, ctx.RequestAborted);
        await AnswerAsync(ctx, result, StatusCodes.Status200OK);
    }

    /// <summary><c>DELETE /auth/cluster/applications/{applicationId}</c>.</summary>
    internal static async Task Remove(HttpContext ctx)
    {
        if (await CallerAsync(ctx) is not { } actor)
            return;

        ApplicationResult result = await ctx.RequestServices.GetRequiredService<ApplicationRegistry>()
            .RemoveAsync(RouteValue(ctx,"applicationId"), actor, AnchorJournal.OriginUi, ctx.RequestAborted);
        await AnswerAsync(ctx, result, StatusCodes.Status204NoContent);
    }

    /// <summary><c>POST /auth/cluster/applications/{applicationId}/clients</c>: register one more client.</summary>
    internal static async Task AddClient(HttpContext ctx)
    {
        if (await CallerAsync(ctx) is not { } actor)
            return;

        if (await Endpoints.ReadBodyAsync(ctx, AnchorJsonContext.Default.ApplicationClientRequest) is not { } body)
        {
            await MalformedAsync(ctx);
            return;
        }

        ApplicationResult result = await ctx.RequestServices.GetRequiredService<ApplicationRegistry>()
            .AddClientAsync(RouteValue(ctx,"applicationId"), body, actor, AnchorJournal.OriginUi, ctx.RequestAborted);
        await AnswerAsync(ctx, result, StatusCodes.Status201Created);
    }

    /// <summary><c>DELETE /auth/cluster/applications/{applicationId}/clients/{clientId}</c>.</summary>
    internal static async Task RemoveClient(HttpContext ctx)
    {
        if (await CallerAsync(ctx) is not { } actor)
            return;

        ApplicationResult result = await ctx.RequestServices.GetRequiredService<ApplicationRegistry>()
            .RemoveClientAsync(RouteValue(ctx,"applicationId"), RouteValue(ctx,"clientId"), actor, AnchorJournal.OriginUi,
                ctx.RequestAborted);
        await AnswerAsync(ctx, result, StatusCodes.Status204NoContent);
    }

    /// <summary><c>POST /auth/cluster/applications/{applicationId}/clients/{clientId}/secret</c>: a new secret.</summary>
    internal static async Task RotateSecret(HttpContext ctx)
    {
        if (await CallerAsync(ctx) is not { } actor)
            return;

        ApplicationResult result = await ctx.RequestServices.GetRequiredService<ApplicationRegistry>()
            .RotateSecretAsync(RouteValue(ctx,"applicationId"), RouteValue(ctx,"clientId"), actor, AnchorJournal.OriginUi,
                ctx.RequestAborted);
        await AnswerAsync(ctx, result, StatusCodes.Status200OK);
    }

    /// <summary>An application as it is listed.</summary>
    internal static ApplicationRecord ToRecord(Application a, ApplicationRegistry registry, ApplicationCatalog catalog) =>
        new(
            a.Id, a.Name, a.Audience, a.ManifestUrl, (int)a.AccessLifetime.TotalMinutes, a.DiscordApplications,
            a.ActForDiscord, a.IsKgsm ? null : Minting.ApplicationClaims.Actions, a.Source, a.Created,
            [.. registry.ClientsOf(a).Select(c => new ApplicationClientRecord(
                c.ClientId, c.RedirectUris, c.PostLogoutRedirectUris, c.Confidential, c.Source, c.MemberId))],
            catalog.StateOf(a) is { } state
                ? new ApplicationManifestRecord(state.At, state.Taken, state.Problem, state.Actions)
                : null);

    /// <summary>The person acting, as the journal names them, or null with the refusal written.</summary>
    private static async Task<string?> CallerAsync(HttpContext ctx)
    {
        if (!await Endpoints.RequireAuthorityAsync(ctx))
            return null;

        return await Endpoints.RequireCaller(ctx, AuthAction.Of(ctx)) is { } caller ? Endpoints.ActorOf(caller) : null;
    }

    private static async Task AnswerAsync(HttpContext ctx, ApplicationResult result, int success)
    {
        switch (result.Outcome)
        {
            case ApplicationOutcome.Invalid:
                await Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "invalid_application", result.Problem!);
                return;
            case ApplicationOutcome.Taken:
                await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "application_taken", result.Problem!);
                return;
            case ApplicationOutcome.NotFound:
                await Endpoints.Refuse(ctx, StatusCodes.Status404NotFound, "no_such_application", result.Problem!);
                return;
            case ApplicationOutcome.BuiltIn:
                await Endpoints.Refuse(ctx, StatusCodes.Status409Conflict, "application_built_in", result.Problem!);
                return;
        }

        if (success == StatusCodes.Status204NoContent)
        {
            ctx.Response.StatusCode = success;
            return;
        }

        ctx.Response.Headers.CacheControl = "no-store";
        var registry = ctx.RequestServices.GetRequiredService<ApplicationRegistry>();
        var catalog = ctx.RequestServices.GetRequiredService<ApplicationCatalog>();
        Application application = registry.Find(result.Application!.Id) ?? result.Application;

        await Endpoints.WriteJson(ctx, success,
            new ApplicationAnswer(ToRecord(application, registry, catalog), result.Secrets ?? []),
            AnchorJsonContext.Default.ApplicationAnswer);
    }

    private static Task MalformedAsync(HttpContext ctx) =>
        Endpoints.Refuse(ctx, StatusCodes.Status400BadRequest, "malformed_request", "The request body is not readable.");

    private static string RouteValue(HttpContext ctx, string name) => (string?)ctx.Request.RouteValues[name] ?? "";
}
