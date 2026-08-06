# kgsm-auth

The shared authorization model for the KGSM ecosystem: **one definition of who may do what**, used by
every surface onto a host, so the same person gets the same authority through the Control Panel, the
assistant and the Discord bot alike.

## Packages

| package | contents | taken by |
|---|---|---|
| **`TheKrystalShip.KGSM.Auth`** | the tier model, the Discord role map, claim and relay-header names, the actor convention. **No I/O, no dependencies, AOT-safe.** | kgsm-api, kgsm-llm, kgsm-bot |
| **`TheKrystalShip.KGSM.Auth.Discord`** | the one chokepoint to `discord.com`: the OAuth login flow, identity verification, and the bot-token role lookup. `HttpClient` only — no web framework. | kgsm-api, kgsm-llm |

## The model

Three ordered tiers — a higher one subsumes the lower (`admin ⊇ operator ⊇ viewer`):

| tier | holds |
|---|---|
| `viewer` | reads: status, listings, whether a server is running |
| `operator` | acts: start, stop, restart, install, uninstall, backup, update |
| `admin` | host settings, audit configuration, session revocation, reading other people's conversations |

Two rules decide every request:

- **Guild membership is the access gate.** Not a member ⇒ `none` ⇒ a terminal denial. Re-authenticating
  cannot change the answer, so it is never retried.
- **A verified member floors at `viewer`.** The admin and operator role ids elevate from there. There is
  no viewer role list, because it would grant what every member already has.

```csharp
KgsmRoleMap map = options.ToRoleMap();

// A REST caller, roles fetched with the bot token. null == not a member.
KgsmTier tier = map.Resolve(member?.Roles);

// A gateway client that already holds the member object.
KgsmTier tier = map.ResolveSnowflakes(guildUser?.Roles.Select(r => r.Id));

if (tier < KgsmTier.Operator)
    return Deny();
```

`null` and an empty collection mean different things and must not be conflated: `null` is *not a
member*, an empty collection is *a member holding only `@everyone`*. Never pass an empty collection to
stand in for a failed lookup — that turns an outage into a silent grant. Report the failure and deny.

## Configuration

Bound from the `KgsmAuth` section. The package owns the section and property names, so every surface
binds the same keys by construction and one file can configure all of them:

```
KgsmAuth__GuildId=…
KgsmAuth__ClientId=…
KgsmAuth__ClientSecret=…        # environment only
KgsmAuth__BotToken=…            # environment only
KgsmAuth__RoleAdminIds=…        # comma-separated
KgsmAuth__RoleOperatorIds=…     # comma-separated
```

Roles come from the **bot token** (`GET /guilds/{guild}/members/{user}`) — the only path to them, since
the `identify guilds` user scopes do not carry roles. A surface that resolves authority therefore needs
a bot token even when it runs no bot of its own.

## Why it is dependency-free

Every surface takes this assembly, including the Discord bot — whose deploy is tuned for footprint —
and the CLI, whose startup a user feels directly. Anything referenced here would reach all of them, so
the tier model stays a pure library: no HTTP, no configuration binder, no ORM. Transports that need
those live in sibling packages that only the surfaces needing them take.

## Development

```bash
dotnet build kgsm-auth.slnx
dotnet test kgsm-auth.slnx
dotnet pack src/Auth/Auth.csproj -c Release
cp src/Auth/bin/Release/TheKrystalShip.KGSM.Auth.<v>.nupkg /home/heisen/local-nuget/
```

A consumer pins a version from the local feed, so a change here needs a repack and a version bump on
both sides — a same-version repack is served stale from the NuGet cache, which is keyed by id+version.

## The login flow

One handshake carries both halves of the defence, in one HttpOnly cookie:

```csharp
// /auth/start
var handshake = OAuthHandshake.Create();
Response.Cookies.Append("kgsm_oauth_state", handshake.ToCookieValue(), new CookieOptions
{
    HttpOnly = true,
    Secure = Request.IsHttps,
    SameSite = SameSiteMode.Lax,   // NOT Strict — Strict suppresses the cookie on the way back
    Path = "/auth",
});
return Redirect(directory.BuildAuthorizeUrl(handshake.State, handshake.CodeChallenge, "none"));

// /auth/callback
if (!OAuthHandshake.TryParse(Request.Cookies["kgsm_oauth_state"], out var handshake)
    || !handshake.MatchesState(state))
    return BadRequest();   // forged, expired, or another browser's login

var principal = await directory.ResolveAsync(code, handshake.CodeVerifier, ct);
```

**`state` and PKCE are not alternatives.** `state` stops login CSRF — without it an attacker starts
their own login, sends the victim a callback link carrying the attacker's `code`, and the victim's
browser is handed a session for the *attacker's* identity. PKCE stops code interception, because a
`code` rides back in a URL and URLs leak.

**The state has to be bound to the browser, and only the cookie binds it.** Checking a returned state
against a server-side set of issued states proves that *some* login started on this host — which is
true of the attacker's login too, so it admits the exact request it was meant to refuse. Single-use
consumption stops replay, not CSRF.

Carrying the verifier in the same cookie is what lets a surface run PKCE with **no server-side pending
store**, so a login survives a restart and works across nodes.

## Honest failure

The role lookup answers three different things and they must not be collapsed:

| Discord says | means | tier |
|---|---|---|
| `404` on the member | not in the guild | `none` — a terminal denial |
| member, `roles: []` | in the guild, no roles | `viewer` — the floor |
| `429`, `5xx`, unreachable | **unknown** | `DiscordAuthException` |

The third is the one that matters. "We could not ask" is not "the answer is no": a surface that reads
an outage as an empty role list quietly demotes an admin mid-incident, and one that reads it as
membership lets a stranger in. Both are worse than a `502`.
