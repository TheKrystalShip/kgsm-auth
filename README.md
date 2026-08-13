# kgsm-auth

The shared authorization model for the KGSM ecosystem: **one definition of who may do what**, used by
every surface onto a host, so the same person gets the same authority through the Control Panel, the
assistant and the Discord bot alike.

## Packages

| package | contents | taken by |
|---|---|---|
| **`TheKrystalShip.KGSM.Auth`** | the tier model, the identity and authority seams, claim and relay-header names, the actor convention. **No I/O, no dependencies, AOT-safe.** | kgsm-api, kgsm-llm, kgsm-bot |
| **`TheKrystalShip.KGSM.Auth.Discord`** | the one chokepoint to `discord.com`: the OAuth login flow and identity verification. `HttpClient` only — no web framework. | kgsm-api, kgsm-llm |
| **`TheKrystalShip.KGSM.Auth.Sessions`** | access + refresh JWTs, `sid` stable across rotation, `jti` reuse detection, the cached per-request validator, and the GC worker. Storage is a seam. | kgsm-api, kgsm-llm |
| **`TheKrystalShip.KGSM.Auth.Users`** | KGSM's own accounts: local passwords, the credentials that prove an account, and the tier it holds. One SQLite file per host. | kgsm-api, kgsm-llm, kgsm-bot |

## The model

Three ordered tiers — a higher one subsumes the lower (`admin ⊇ operator ⊇ viewer`):

| tier | holds |
|---|---|
| `viewer` | reads: status, listings, whether a server is running |
| `operator` | acts: start, stop, restart, install, uninstall, backup, update |
| `admin` | host settings, audit configuration, session revocation, reading other people's conversations |

One rule decides every request:

- **The KGSM account carries the tier**, and nothing outside it contributes. A provider proves you are
  an account this host already has; an identity attached to no account holds `none`, whatever group or
  guild it belongs to elsewhere.

```csharp
KgsmTier tier = await authority.ResolveTierAsync(identity, ct);   // UserStoreAuthority, in production

if (tier < KgsmTier.Operator)
    return Deny();
```

**Every surface answers it the same way, including kgsm-bot.** The bot has no login of its own, so the
Discord account the gateway hands it *is* the identity — and the tier is whatever KGSM account that
identity is attached to, exactly as it is for a browser that signed in with a password:

```csharp
KgsmTier tier = await authority.ResolveTierAsync(
    new KgsmIdentity(KgsmActorProvider.Discord, discordUserId, username), ct);
```

An identity attached to no account holds `none`. A group or a guild role is a fact about somewhere
else and is not consulted anywhere. A store that cannot be read **throws** rather than resolving to
`none`: "we could not ask" is not "the answer is no", and reporting the first as the second demotes an
admin mid-incident.

## Configuration

Bound from the `KgsmAuth` section. The package owns the section and property names, so every surface
binds the same keys by construction and one file can point a whole host at the same applications:

```
KgsmAuth__Providers__discord__ClientId=…        # one OAuth application, at one provider
KgsmAuth__Providers__discord__ClientSecret=…    # environment only
KgsmAuth__Providers__github__ClientId=…         # a second provider is two more keys
KgsmAuth__Providers__github__ClientSecret=…
```

That is the whole section. Adding a provider to a host is a pair of keys and no code anywhere:
`options.For("github")` answers with an unconfigured application when nobody wired one up, so a
provider a host does not offer and a provider it has never heard of are one answer, and
`ConfiguredProviders()` is the set a login page may draw a button for.

A surface that signs people in needs an application and its own redirect URI; a surface that only
authorizes needs neither, because the account store answers it.

## Why it is dependency-free

Every surface takes this assembly, including the Discord bot — whose deploy is tuned for footprint —
and the CLI, whose startup a user feels directly. Anything referenced here would reach all of them, so
the tier model stays a pure library: no HTTP, no configuration binder, no ORM. Transports that need
those live in sibling packages that only the surfaces needing them take.

## Development

```bash
dotnet build kgsm-auth.slnx
dotnet test kgsm-auth.slnx
../scripts/publish-packages.sh kgsm-auth     # pack + push to the org's GitHub Packages feed
```

A consumer pins a version from that feed, so a change here needs a version bump, a publish, and then
the pin moved on the consumer. A published version is immutable — pushing one again is a `409` the
script reports as already published — so the change a consumer restores is always the one you built.

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

A login answers three different things and they must not be collapsed:

| what happened | means | result |
|---|---|---|
| the code exchanged, `users/@me` answered | a verified identity | the account it proves, or an unapproved one created for it |
| `4xx` from the token endpoint | an expired, replayed or forged code | `null` — a `401`, start again |
| `5xx`, unreachable, malformed | **unknown** | `DiscordAuthException` — a `502` |

The third is the one that matters. "We could not ask" is not "the answer is no": a surface that reads
an outage as a verdict either locks out someone who really does hold the role or admits someone who
does not. The same rule holds one layer down — a store that cannot be read throws rather than
resolving to `none`.

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
