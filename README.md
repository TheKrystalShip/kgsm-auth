# kgsm-auth

The shared authorization model for the KGSM ecosystem: **one definition of who may do what**, used by
every surface onto a host, so the same person gets the same authority through the Control Panel, the
assistant and the Discord bot alike.

## Packages

| package | contents | taken by |
|---|---|---|
| **`TheKrystalShip.KGSM.Auth`** | the tier model, the Discord role map, claim and relay-header names, the actor convention. **No I/O, no dependencies, AOT-safe.** | kgsm-api, kgsm-llm, kgsm-bot |
| **`TheKrystalShip.KGSM.Auth.Discord`** | the one chokepoint to `discord.com`: the OAuth login flow, identity verification, and the bot-token role lookup. `HttpClient` only — no web framework. | kgsm-api, kgsm-llm |
| **`TheKrystalShip.KGSM.Auth.Sessions`** | access + refresh JWTs, `sid` stable across rotation, `jti` reuse detection, the cached per-request validator, and the GC worker. Storage is a seam. | kgsm-api, kgsm-llm |
| **`TheKrystalShip.KGSM.Auth.Users`** | KGSM's own accounts: local passwords, the credentials that prove an account, and the tier it holds. One SQLite file per host. | kgsm-api, kgsm-llm |

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

## Sessions

A stateless JWT can say who someone is; it cannot say whether their session is still alive. That one
fact is what `ISessionRegistry` holds, and it is the only reason a surface needs storage at all.

```csharp
var tokens = new SessionTokenService(new SessionTokenOptions(
    HostId: "hotrod", SigningKey: secret,
    AccessLifetime: TimeSpan.FromMinutes(15),
    RefreshLifetime: TimeSpan.FromDays(30),
    Issuer: "kgsm-api"));

MintedToken access  = tokens.MintAccess(identity, tier, sid);
MintedToken refresh = tokens.MintRefresh(identity, tier, sid);
await registry.CreateAsync(new SessionRegistration(
    sid, identity.UserId, hostId, DateTimeOffset.UtcNow, refresh.ExpiresAt, userAgent, refresh.Jti));
```

**The storage is a seam, and two implementations behind it is the seam working.** What a session is,
how it rotates and when it dies are the ecosystem's; where the rows go is each surface's own — an EF
table next to an audit log, raw SQLite, or memory.

**`RefreshLifetime` is written once and used twice** — the token's expiry and the registry row's. It
is a setting rather than a constant precisely so there is no second copy to drift, because the drift
is invisible until a token outlives its own row or the reverse.

**`Issuer` changes are breaking.** It is validated, so changing it on a running host 401s every token
already issued and forces everyone to log in again. A surface that already mints keeps the value it
has; the neutral default is for a surface that has never minted one.

### Rotation and reuse

Every refresh mints a new pair and stores the new `jti`. A refresh presenting any other `jti` is a
replay of a token that has already been rotated away — `RotateAsync` returns false, and the caller
refuses. It cannot tell a stale client from a stolen token, so it refuses both and lets the real
holder authenticate again.

### The cache is the revocation bound

`SessionValidator` caches the registry's answer, so the hot path does not query per request. A revoke
evicts, making the kill immediate; the TTL is the backstop for what cannot evict. Expiration is
**absolute, never sliding** — a sliding window is extended by every hit, so the busiest session, the
one most worth revoking, would be the one that never re-checks. A "no" is cached too, because a
revoked session still presenting its token is exactly what a stolen one does.

## Accounts

**KGSM owns users.** An account exists on its own — a local password is enough to sign in, with no
external provider configured at all. A Discord, GitHub or Google identity is one *credential attached
to* an account, never the source of one, and never a source of authority.

```csharp
var store  = new SqliteUserStore(new UserStoreOptions());          // /var/lib/kgsm/auth/users.db
var signIn = new LocalSignInService(store, new IdentityPasswordHasher(), new UserStoreAuthority(store));

LocalSignInResult result = await signIn.SignInAsync(username, password, DateTimeOffset.UtcNow);
if (result.Outcome == LocalSignInOutcome.Success)
    Mint(result.Principal!.Identity, result.Principal.Tier);
```

**A credential answers "which account is this"; the account answers "what may they do".** Nothing
else contributes. That is what lets a provider be added with no authority story of its own, and it is
why `UserStoreAuthority` is an `IAuthorityProvider` like any other — the login path does not change
shape when the source of authority does.

**One file, several services, all of them direct.** The Control Panel API and the assistant each open
`/var/lib/kgsm/auth/users.db` themselves. It is a shared host *resource*, in the same category as
`/var/lib/kgsm/leaves/` — not a service, so nothing here can be down, and no leaf ends up
authenticating through a sibling.

### The schema rule is the opposite of everywhere else

Elsewhere in the ecosystem a schema change means wiping the database. **That cannot apply here**:
wiping this one is every account, every password and every link, with nothing to re-derive them from.
Two services also deploy separately, so at any moment one may be a version ahead of the other.

So changes are **additive only** — add tables, add nullable columns, add indexes; never drop, rename,
or change what a stored value means. The file carries a `schema_version`, and a store written by a
build newer than the one opening it is **refused outright** rather than half read.

### What a password costs

- **An unknown username and a wrong password are one outcome at one cost.** Distinguishable answers
  are a username oracle, and so is a faster one — an unmatched username still spends a hash
  verification against a decoy.
- **Lockout is exponential from a threshold, not a hard cap.** A hard cap hands anyone who knows a
  username a denial of service against its owner; doubling delays cost an attacker orders of
  magnitude within a handful of attempts.
- **The file is `0600`, and `-wal`/`-shm` with it.** SQLite gives those two the mode the database had
  when it created them, so the store sets the mode *before* enabling WAL.
- **It lives in a directory the service user owns**, not directly under the root-owned
  `/var/lib/kgsm/`. SQLite writes `-wal` and `-shm` *beside* the database, so WAL needs write
  permission on the **directory**, not just the file — the same reason `events/` and `leaves/` are
  their own directories.
- **No SMTP, anywhere.** A reset is admin-initiated. Adding a mail dependency to the thing whose
  purpose is removing outside dependencies would be self-defeating.
