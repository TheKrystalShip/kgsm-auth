using System.Collections.Concurrent;

namespace TheKrystalShip.KGSM.Auth;

/// <summary>A link in flight: which account started it, and the handshake it must come back with.</summary>
/// <param name="UserId">The account the arriving identity will be attached to.</param>
/// <param name="SessionId">The session that started it.</param>
/// <param name="Handshake">The <c>state</c> the provider echoes back, and the PKCE verifier.</param>
/// <param name="Expires">When this ticket stops being redeemable.</param>
public sealed record LinkTicket(
    string UserId, string SessionId, OAuthHandshake Handshake, DateTimeOffset Expires);

/// <summary>
/// The links that have been started and not yet come back.
/// </summary>
/// <remarks>
/// <para>
/// A login can be stateless — the state and verifier ride an HttpOnly cookie and the callback needs
/// nothing else. A <em>link</em> cannot: it has to know which account to attach the arriving identity
/// to, and the callback is a top-level navigation from the provider that carries no bearer. Putting
/// the account id in the cookie would make the browser the authority on whose account is being
/// changed, so the cookie carries an opaque ticket instead and the account stays here.
/// </para>
/// <para>
/// Single-use and short-lived: redeeming removes the ticket, so a callback replayed from history or a
/// log attaches nothing. In memory, deliberately: a restart drops links in flight, which costs a click
/// and cannot grant anything.
/// </para>
/// <para>
/// Here rather than in a provider package or a surface, for the same reason
/// <see cref="OAuthHandshake"/> is: a link ticket is a property of the authorization-code flow, not
/// of any one provider and not of whichever component happens to run the flow.
/// </para>
/// </remarks>
public sealed class LinkTicketStore
{
    /// <summary>How long a browser has to finish a link it started.</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

    private const int SweepAbove = 256;

    private readonly ConcurrentDictionary<string, LinkTicket> _tickets = new(StringComparer.Ordinal);

    /// <summary>Start a link, returning the opaque ticket the browser carries in its cookie.</summary>
    /// <param name="userId">The account the arriving identity will attach to.</param>
    /// <param name="sessionId">The session starting it.</param>
    /// <param name="handshake">The state and PKCE pair this link must come back with.</param>
    /// <returns>The opaque ticket id.</returns>
    public string Issue(string userId, string sessionId, OAuthHandshake handshake)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string ticketId = Guid.NewGuid().ToString("N");
        _tickets[ticketId] = new LinkTicket(userId, sessionId, handshake, now + Ttl);

        if (_tickets.Count > SweepAbove)
        {
            foreach (KeyValuePair<string, LinkTicket> entry in _tickets)
            {
                if (entry.Value.Expires <= now)
                    _tickets.TryRemove(entry.Key, out _);
            }
        }

        return ticketId;
    }

    /// <summary>
    /// Take a ticket back, if it exists, has not expired, and the state the provider echoed matches
    /// the one it was issued with. Removes it either way — a ticket is worth one attempt.
    /// </summary>
    /// <param name="ticketId">The opaque id from the browser's cookie.</param>
    /// <param name="state">The state the provider echoed back.</param>
    /// <returns>The ticket, or null when it does not redeem.</returns>
    public LinkTicket? Redeem(string? ticketId, string? state)
    {
        if (string.IsNullOrEmpty(ticketId) || !_tickets.TryRemove(ticketId, out LinkTicket? ticket))
            return null;

        return ticket.Expires > DateTimeOffset.UtcNow && ticket.Handshake.MatchesState(state)
            ? ticket
            : null;
    }
}
