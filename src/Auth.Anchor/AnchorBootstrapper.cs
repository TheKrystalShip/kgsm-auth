using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The administrator an anchor with no accounts creates for itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>An anchor holding an empty store is a door nobody can open.</b> Registration is off unless a
/// cluster turns it on, and an account made through it holds <c>none</c> and waits for an approval
/// that only an administrator can give — so the first person to arrive at a fresh anchor is stuck
/// behind an account nobody exists to approve.
/// </para>
/// <para>
/// It goes unnoticed wherever an anchor shares a machine with a Control Panel, because they share
/// one account store and the panel bootstrapped it first. An anchor on a machine of its own — which
/// nothing prevents and which is the deployment a small cluster wants — starts with nothing.
/// </para>
/// <para>
/// The same bootstrap a host's own API performs, from the same code, so the two cannot disagree about
/// what the first account is called, what the file holds, or when it is removed. Whichever of them
/// opens an empty store first creates the account; the other finds accounts and does nothing.
/// </para>
/// </remarks>
internal sealed class AnchorBootstrapper(
    IUserStore store,
    LocalSignInService signIn,
    AnchorOptions options,
    ILogger<AnchorBootstrapper> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        string? password;
        try
        {
            password = await FirstAdmin.CreateAsync(store, signIn, FirstAdmin.DefaultUsername, ct)
                .ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // An anchor nobody can administer is worth an error and is not worth refusing to start:
            // the surface that would report the problem is this same daemon.
            logger.LogError(e, "the first administrator could not be created in the account store");
            return;
        }

        // Accounts already exist, which is every start but the first.
        if (password is null)
            return;

        string path = options.InitialAdminPasswordPath;
        if (FirstAdmin.TryWritePasswordFile(path, FirstAdmin.DefaultUsername, password, out Exception? error))
        {
            logger.LogInformation(
                "this cluster had no accounts, so the administrator '{Username}' was created. Its "
                + "one-time password is in {Path} — read it, sign in, and change it; the file is "
                + "removed on that first sign-in.", FirstAdmin.DefaultUsername, path);
            return;
        }

        // The account exists either way and it is the account that matters, so the password is said
        // out loud here rather than leaving a cluster with an administrator nobody can be.
        logger.LogWarning(error,
            "the first administrator's password could not be written to {Path}. It is '{Password}' for "
            + "the account '{Username}', and is not recoverable once this line is gone.",
            path, password, FirstAdmin.DefaultUsername);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
