using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Cluster.Identity;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// Why a member-acting call was refused, as something a surface can branch on.
/// </summary>
/// <remarks>
/// Typed rather than left to the message, because these do not all mean the same thing to whoever reads
/// a log. <see cref="NoSuchAccount"/> is what a username collision looks like from the far end — a person
/// who exists in the cluster and resolves to nobody here, with everything else healthy — and it deserves
/// to be findable, while a token that failed to validate is ordinary noise. A surface that matched on the
/// message text to tell them apart would break on a reworded sentence.
/// </remarks>
public enum MemberActingRefusal
{
    /// <summary>Not a refusal: the call resolved to an account.</summary>
    None = 0,

    /// <summary>No member service token was presented, so the caller is not a member.</summary>
    NoToken,

    /// <summary>The token did not validate here — wrong secret, expired, or malformed.</summary>
    TokenNotValid,

    /// <summary>The caller is a member this one has switched off.</summary>
    MemberDisabled,

    /// <summary>The acting handle was absent or not a <c>provider:subject</c> handle.</summary>
    HandleNotQualified,

    /// <summary>This member's authority replica could not be read. An outage, never a denial.</summary>
    AccountsUnavailable,

    /// <summary>No account here matches the handle. The caller named somebody this member cannot answer for.</summary>
    NoSuchAccount,

    /// <summary>The account exists here and is disabled.</summary>
    AccountDisabled,

    /// <summary>The handle names a service account belonging to a member other than the caller.</summary>
    ServiceNotTheCallers,
}

/// <summary>
/// What a member-acting call resolved to against the authority replica: the account acted as, and the
/// member that asserted it, or why it was refused.
/// </summary>
/// <param name="AccountId">The account this call acts as — a person, or a service account of the caller's.</param>
/// <param name="Handle">The handle that named it.</param>
/// <param name="ActingMember">The member that asserted it, once its token validated.</param>
/// <param name="Failure">Why the call was refused, or <see langword="null"/>.</param>
/// <param name="Refusal">Which refusal this is.</param>
public sealed record MemberActingAccount(
    string? AccountId, string? Handle, string? ActingMember, string? Failure,
    MemberActingRefusal Refusal = MemberActingRefusal.None)
{
    /// <summary>Whether this call resolved to an account.</summary>
    public bool Succeeded => AccountId is not null && Failure is null;

    internal static MemberActingAccount Refused(
        MemberActingRefusal refusal, string reason, string? member = null, string? handle = null) =>
        new(null, handle, member, reason, refusal);
}

/// <summary>
/// Decides a member-acting call against the authority replica: one member calling another for a person,
/// or as one of its own service accounts.
/// </summary>
/// <remarks>
/// <para>
/// <b>The caller asserts who, never what.</b> Nothing about access travels with the call: the receiver
/// resolves the account from its own replica and evaluates it there, so a compromised member can act as
/// somebody it names and is bounded by what that account actually holds.
/// </para>
/// <para>
/// <b>A member acts as a service account only when that account belongs to it.</b> A handle
/// <c>svc:&lt;component&gt;@&lt;member&gt;</c> is accepted from <c>&lt;member&gt;</c> alone, so the
/// assistant on one anchor cannot borrow the reactor's reach on a node.
/// </para>
/// <para>
/// A person the receiver has never heard of is refused, never provisioned, and a disabled account acts
/// for nobody. A pending account resolves, and holds nothing when it is evaluated.
/// </para>
/// </remarks>
public sealed class MemberActingAccountResolver(
    IClusterTokenService tokens, IClusterMemberGate members, IReplicatedAuthority authority)
{
    /// <summary>Resolve the account a member is acting as.</summary>
    /// <param name="handle">The <c>provider:subject</c> handle, or a service account's <c>svc:</c> actor.</param>
    /// <param name="memberToken">The caller's member service token, without its scheme prefix.</param>
    /// <param name="snapshot">The replica's current snapshot, which a service account is looked up in.</param>
    public async Task<MemberActingAccount> ResolveAsync(
        string? handle, string? memberToken, AuthoritySnapshot snapshot, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        if (string.IsNullOrWhiteSpace(memberToken))
            return MemberActingAccount.Refused(MemberActingRefusal.NoToken, "a member-acting call must present a member service token");

        ClusterPrincipal? caller = await tokens.ValidateAsync(memberToken).ConfigureAwait(false);
        if (caller is null || string.IsNullOrEmpty(caller.MemberId))
            return MemberActingAccount.Refused(MemberActingRefusal.TokenNotValid, "the member service token is not valid here");

        if (!await members.IsEnabledAsync(caller.MemberId).ConfigureAwait(false))
            return MemberActingAccount.Refused(
                MemberActingRefusal.MemberDisabled, $"member '{caller.MemberId}' is disabled here", caller.MemberId);

        if (string.IsNullOrWhiteSpace(handle) || !KgsmActor.TryParse(handle, out string provider, out string name))
            return MemberActingAccount.Refused(
                MemberActingRefusal.HandleNotQualified, "the acting handle is not a 'provider:subject' handle", caller.MemberId);

        string? accountId;
        if (provider == ServiceIdentity.ActorProvider)
        {
            int at = name.LastIndexOf('@');
            string owner = at < 0 ? "" : name[(at + 1)..];
            if (!string.Equals(owner, caller.MemberId, StringComparison.Ordinal))
                return MemberActingAccount.Refused(
                    MemberActingRefusal.ServiceNotTheCallers,
                    $"'{handle}' is not a service account of member '{caller.MemberId}'", caller.MemberId, handle);

            ServiceIdentity service = new(name[..at], owner);
            accountId = snapshot.Accounts.Values.FirstOrDefault(a => a.Service == service)?.AccountId;
        }
        else
        {
            if (authority.Replica is not { } replica)
                return MemberActingAccount.Refused(
                    MemberActingRefusal.AccountsUnavailable,
                    authority.UnavailableReason ?? "this member's authority replica is unavailable", caller.MemberId, handle);

            try
            {
                accountId = await replica.FindAccountIdByHandleAsync(handle, ct).ConfigureAwait(false);
            }
            catch (Exception)
            {
                return MemberActingAccount.Refused(
                    MemberActingRefusal.AccountsUnavailable, "this member's authority replica could not be read", caller.MemberId, handle);
            }
        }

        if (accountId is null || !snapshot.Accounts.TryGetValue(accountId, out AccessAccount? account))
            return MemberActingAccount.Refused(
                MemberActingRefusal.NoSuchAccount, "no account here matches the acting handle", caller.MemberId, handle);

        if (account.Status == AccountStatus.Disabled)
            return MemberActingAccount.Refused(
                MemberActingRefusal.AccountDisabled, "that account is disabled here", caller.MemberId, handle);

        return new MemberActingAccount(accountId, handle, caller.MemberId, null);
    }
}
