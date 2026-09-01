using TheKrystalShip.KGSM.Auth.Users;
using TheKrystalShip.KGSM.Cluster.Identity;

namespace TheKrystalShip.KGSM.Auth.Cluster;

/// <summary>
/// The member's own read of the accounts a member-acting call is resolved against.
/// </summary>
/// <remarks>
/// A member supplies its store rather than the package opening one, for the same reason every other
/// piece here does: where the accounts live is the member's business, and a package that opened a file
/// would be a second answer to a question its host already answers.
/// </remarks>
public interface IMemberAccounts
{
    /// <summary>The accounts to resolve against, or <see langword="null"/> when they cannot be read.</summary>
    IUserStore? Store { get; }

    /// <summary>Why the store is unavailable, when it is. <see langword="null"/> when it is not.</summary>
    string? UnavailableReason { get; }
}

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
    /// <summary>Not a refusal: the call resolved to a person.</summary>
    None = 0,

    /// <summary>No member service token was presented, so the caller is not a member.</summary>
    NoToken,

    /// <summary>The token did not validate here — wrong secret, expired, or malformed.</summary>
    TokenNotValid,

    /// <summary>The caller is a member this one has switched off.</summary>
    MemberDisabled,

    /// <summary>The acting handle was absent or not a <c>provider:subject</c> handle.</summary>
    HandleNotQualified,

    /// <summary>This member's account store could not be read. An outage, never a denial.</summary>
    AccountsUnavailable,

    /// <summary>No account here matches the handle. The caller named somebody this member cannot answer for.</summary>
    NoSuchAccount,

    /// <summary>The account exists here and is disabled.</summary>
    AccountDisabled,
}

/// <summary>
/// What a member-acting call resolved to: the person acted for and the member that asserted them, or
/// why it was refused.
/// </summary>
/// <remarks>
/// A refusal carries a reason and never a partial identity, so a caller cannot act on half an answer.
/// The message is for the member's own log and its own error envelope — every surface has one already,
/// and one shape imposed on all of them is a second wire contract kept in step for no reader.
/// <para>
/// <see cref="ActingMember"/> is set as soon as the token validates, refusal or not, so a member can say
/// <em>who</em> asked for something it would not do. Refusing without naming the caller is the shape that
/// leaves an operator with a rejection and nothing to look at.
/// </para>
/// </remarks>
/// <param name="Person">The account this call acts for.</param>
/// <param name="Handle">The <c>provider:subject</c> handle that named them.</param>
/// <param name="ActingMember">The member that asserted the identity, once its token validated.</param>
/// <param name="Failure">Why the call was refused, or <see langword="null"/> when it was not.</param>
/// <param name="Refusal">Which refusal this is, for a surface that reports them differently.</param>
public sealed record MemberActingResult(
    KgsmUser? Person, string? Handle, string? ActingMember, string? Failure,
    MemberActingRefusal Refusal = MemberActingRefusal.None)
{
    /// <summary>Whether this call resolved to a person.</summary>
    public bool Succeeded => Person is not null && Failure is null;

    internal static MemberActingResult Refused(
        MemberActingRefusal refusal, string reason, string? member = null, string? handle = null) =>
        new(null, handle, member, reason, refusal);
}

/// <summary>
/// Decides a member-acting call: one member calling another for somebody who is not signed in to it.
/// </summary>
/// <remarks>
/// <para>
/// One implementation for every member. The assistant answers about servers on machines it does not
/// run, and somebody asking it something in Discord holds no session anywhere — so a member calls
/// another <b>as a member</b>, names the person it is acting for, and the receiver decides what that
/// person may do by reading its own replica of the cluster's accounts. Two implementations of that
/// would be two surfaces disagreeing about who somebody is.
/// </para>
/// <para>
/// <b>The caller asserts who, never what.</b> No tier crosses the wire in either direction. What a
/// compromised member could do is act as somebody it names, bounded by what that person actually
/// holds — narrower than a shared secret that forwards an authority along with an identity, and the
/// same boundary every member-to-member call already sits on.
/// </para>
/// <para>
/// <b>A person the receiver has never heard of is refused, not invented.</b> Provisioning an account
/// from an assertion would let any member create accounts here, and the refusal is exactly what a
/// username collision looks like from the far end.
/// </para>
/// <para>
/// This decides and returns; it reads no request and writes no response. How the handle and the token
/// were carried, and what a refusal looks like on the wire, belong to the surface.
/// </para>
/// </remarks>
public sealed class MemberActingResolver(
    IClusterTokenService tokens, IClusterMemberGate members, IMemberAccounts accounts)
{
    /// <summary>
    /// Resolves the person a member is acting for.
    /// </summary>
    /// <param name="handle">The <c>provider:subject</c> handle the caller named.</param>
    /// <param name="memberToken">The caller's member service token, without its scheme prefix.</param>
    public async Task<MemberActingResult> ResolveAsync(
        string? handle, string? memberToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(memberToken))
            return MemberActingResult.Refused(
                MemberActingRefusal.NoToken,
                "a member-acting call must present a member service token");

        ClusterPrincipal? caller = await tokens.ValidateAsync(memberToken).ConfigureAwait(false);
        if (caller is null || string.IsNullOrEmpty(caller.MemberId))
            return MemberActingResult.Refused(
                MemberActingRefusal.TokenNotValid, "the member service token is not valid here");

        // The disable-list, which is the one local override to the shared-secret trust boundary. A
        // member somebody has switched off must not act for anybody, however good its token is.
        if (!await members.IsEnabledAsync(caller.MemberId).ConfigureAwait(false))
            return MemberActingResult.Refused(
                MemberActingRefusal.MemberDisabled, $"member '{caller.MemberId}' is disabled here",
                caller.MemberId);

        if (string.IsNullOrWhiteSpace(handle) || !KgsmActor.TryParse(handle, out _, out _))
            return MemberActingResult.Refused(
                MemberActingRefusal.HandleNotQualified,
                "the acting handle is not a 'provider:subject' handle", caller.MemberId);

        IUserStore? store = accounts.Store;
        if (store is null)
            return MemberActingResult.Refused(
                MemberActingRefusal.AccountsUnavailable,
                accounts.UnavailableReason ?? "this member's account store is unavailable",
                caller.MemberId, handle);

        KgsmUser? person;
        try
        {
            person = await store.FindByCredentialAsync(handle, ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return MemberActingResult.Refused(
                MemberActingRefusal.AccountsUnavailable,
                "this member's account store could not be read", caller.MemberId, handle);
        }

        if (person is null)
            return MemberActingResult.Refused(
                MemberActingRefusal.NoSuchAccount, "no account here matches the acting handle",
                caller.MemberId, handle);

        if (person.Status == UserStatus.Disabled)
            return MemberActingResult.Refused(
                MemberActingRefusal.AccountDisabled, "that account is disabled here",
                caller.MemberId, handle);

        return new MemberActingResult(person, handle, caller.MemberId, null);
    }
}
