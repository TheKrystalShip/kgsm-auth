# kgsm-auth

The shared authorization model for the KGSM ecosystem: **one definition of who may do what**, used by
every surface onto a host, so the same person gets the same authority through the Control Panel, the
assistant and the Discord bot alike.

Four libraries and one daemon. The libraries are what every surface compiles against; the daemon —
**`kgsm-auth-anchor`** — is what holds a whole cluster's accounts and signs people in to all of it at
once. A standalone host runs no daemon and reads the same file through the same libraries.

## Packages

| package | contents | taken by |
|---|---|---|
| **`TheKrystalShip.KGSM.Auth`** | the tier model, the identity and authority seams, claim and relay-header names, the host's relay secret, the actor convention. **No dependencies, AOT-safe.** | kgsm-api, kgsm-llm, kgsm-bot |
| **`TheKrystalShip.KGSM.Auth.Discord`** | the one chokepoint to `discord.com`: the OAuth login flow and identity verification. `HttpClient` only — no web framework. | kgsm-api, kgsm-llm |
| **`TheKrystalShip.KGSM.Auth.Sessions`** | access + refresh JWTs, `sid` stable across rotation, `jti` reuse detection, the cached per-request validator, and the GC worker. Storage is a seam. | kgsm-api, kgsm-llm |
| **`TheKrystalShip.KGSM.Auth.Users`** | KGSM's own accounts: local passwords, the credentials that prove an account, and the tier it holds. One SQLite file per host. | kgsm-api, kgsm-llm, kgsm-bot |
| **`TheKrystalShip.KGSM.Auth.Cluster`** | what a cluster *member* does about identity: verify a session it cannot mint, refuse the doors whichever member holds the accounts owns, apply `account.*` and `session.revoke` from the bus, and take its first full copy from the holder. Also what it tells others: the host file its machine's leaves verify against (`HostProviderFile`, read back by `HostSessionKeys`), and the document naming its sign-in provider (`ProtectedResourceMetadata`). | kgsm-api, kgsm-llm, kgsm-bot, kgsm-dns |

The deployable is **`kgsm-auth-anchor`** (`src/Auth.Anchor`), built from those libraries and shipped
as a pacman package and a systemd unit. It publishes nothing to NuGet.

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

## The auth anchor

`kgsm-auth-anchor` is the member of a cluster that holds the accounts. One store, one writer, one
address a person signs in to — and a session it mints is valid on **every** member, because its
audience is the cluster rather than a machine. The design and its phases are
`../cluster-auth-plan.md`; this is what the daemon serves.

| | |
|---|---|
| `GET /health` | the ecosystem's liveness probe |
| `POST /auth/sign-in` | verify a KGSM password, mint a cluster-scoped session |
| `POST /auth/session/refresh` | rotate both tokens, re-reading standing from the store |
| `POST /auth/session/sign-out` | end a session, by refresh token or by bearer |
| `GET /auth/session` | who the caller is, resolved on this request |
| `GET /auth/cluster/users` | every account, admin only |
| `GET /auth/cluster/public-key` | the verification key set |

**Sessions are signed asymmetrically, and that is the whole point.** The anchor holds the private
key; every member verifies with the published public one. A member that could mint what it verifies
could mint itself an admin session, so it holds only what checks a signature.

```
GET /auth/cluster/public-key
{"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…","alg":"ES256","use":"sig","kid":"…"}]}
```

The key is a set so rotation has somewhere to go: publish the incoming key beside the outgoing one,
let every verifier pick up both, then move the signer. `kid` is the key's own RFC 7638 thumbprint,
so two holders of one key compute one id.

**The private key is generated once and never replaced by accident.** It lives at
`/var/lib/kgsm-auth-anchor/session-signing.pem`, `0600`, created with that mode rather than chmod'd
after — the gap between the two is the window the whole mode exists to close. A file that exists and
cannot be read stops the daemon: replacing it invalidates every session in the cluster and leaves
every member checking against a key nothing signs with, so "this anchor has no key yet" and "this
anchor's key is unreadable" must not take the same path. The public half is served at
`/auth/cluster/public-key` and `/.well-known/jwks.json`, and gossiped to every member.

**Authority is read on every request, never off the token.** The tier claim is what was true at mint
time; a demotion has to land at the caller's next request, so the store's answer overwrites it. The
same read happens on refresh, and a withdrawn account has its session ended there rather than being
left to run out its bearer.

**Nothing on the serving path leaves the machine.** Signature checks are local and the standing read
is a local point query, which is what lets a member keep serving and keep refreshing while the
anchor is unreachable.

### The OpenID Connect provider

The anchor is also the cluster's OpenID Connect provider — authorization code with PKCE (S256), public
clients, no consent screen — served at its issuer. `Anchor__Issuer` has to be the anchor's
browser-facing URL (`https://auth.anchors.example.com`); with anything else every door below answers
`no_issuer` and mints nothing. The design is `../hosted-sign-in-plan.md`.

| | |
|---|---|
| `GET /.well-known/openid-configuration` | discovery |
| `GET /.well-known/jwks.json` | the key set every session and `id_token` is signed with |
| `GET /authorize` | validate and hold the request, then answer a recognised browser or show the sign-in page |
| `POST /authorize/credentials` | a password against the request in flight, same-origin only; a code, never a session |
| `GET /authorize/wait` | an account awaiting approval, polled by a refresh or, with `Accept: application/json`, by the page |
| `GET /authorize/context` | what the pages draw for the request in flight: the client, the providers, whether registration is open |
| `POST /authorize/register` | make an account against the request in flight, same-origin only; the wait follows |
| `GET /authorize/{provider}` | an external provider's round trip for the request in flight |
| `POST /token` | `authorization_code` or `refresh_token`; access, refresh and `id_token` |
| `GET /userinfo` | the account behind a bearer |
| `GET /sign-out`, `POST /sign-out` | end a browser's sign-in and everything minted under it; asks without a hint |
| `GET/POST /auth/cluster/clients`, `DELETE /auth/cluster/clients/{id}` | the client registry, admin only |

**Two cookies on the anchor's own origin, both `HttpOnly; SameSite=Lax; Path=/`.** `kgsm_authz` names
the request in flight, held here for ten minutes so the page and its form carry no request field.
`kgsm_anchor` names the browser's provider session, a row in the session registry beside the sessions
minted under it; a second surface comes back signed in on the strength of it. Each holds a random
secret and the row is found by its hash.

**Every session minted through the provider records its provider session**, so signing out ends all of
them, a second account on the same browser ends the first's, and the same account proving itself again
keeps them. The sessions page lists the provider session with `kind: provider`; ending it there is
signing out.

**Clients come from three places.** A member serving a surface states the `auth.client` fact — paths
only, joined to the browser address its roster row carries — and appears with no operator step; it
leaves when the member does. A Control Panel on a static host, which no member can announce, is declared
in `Anchor__PanelOrigins`: one client per origin, id the origin's host, at the paths every panel lands on
(`ClusterClientAnnouncement.ControlPanel`), never stored and never removable through the registry.
Anything else is registered by an admin. Redirects are matched exactly and must be HTTPS, or HTTP where
the cluster itself accepts plaintext — this machine, a private network or a local name — so a cluster of
one on a LAN has somewhere to send a code. A registered client's origin may read discovery, the key set,
`/token`, `/userinfo` and the admin API across origins, without credentials; nothing that reads the
anchor's cookie answers another origin.

**The floor.** The sign-in page is a plain document with a working form and the provider links, under a
content security policy with no inline script or style and `form-action` naming the one client the
request returns to. It signs somebody in with scripting off.

### The pages and the account page

The pages people see are `kgsm-web`'s, packaged as **`kgsm-web-auth`** and read from `Anchor__UiPath`
(`/usr/share/kgsm-web-auth`) on every request, their assets served at `/ui/`. Each is a document with
its own floor — the sign-in form, a wait that refreshes only with scripting off — which the application
replaces on mount; the anchor fills in the provider links and nothing else. Absent, the anchor renders
the floor itself and names the package, and a plain form post that fails is always answered on that
built-in page with the reason.

| | |
|---|---|
| `GET /account` | the account page, or its sign-in when this browser holds none |
| `GET /account/sign-in` | sign in at the anchor to reach the account page; no code is minted |
| `GET /account/me` | the account, its identities, its sessions and until when the last proof is recent |
| `POST /account/reauth` | the password again; `GET /account/reauth/{provider}` for an account with none |
| `POST /account/password` | set its own password |
| `POST /account/identities/{provider}/start`, `DELETE /account/identities/{id}` | attach or detach an identity |
| `POST /account/sessions/revoke`, `POST /account/sign-out` | end a session, all of them, or this browser's sign-in |

Every call is authenticated by `kgsm_anchor` and every write is same-origin only. **Changing how
somebody signs in needs a recent proof** — the provider session's last credential inside
`Anchor__ReauthWindowMinutes` — and the page asks for the password (or a round trip to a provider the
account already holds) when it is older. A provider round trip for that purpose accepts only an identity
already attached to the same account; it never signs anybody in and never makes an account.

**A browser signs in here directly, so the origin list is load-bearing.** The Control Panel is served
from a different origin; without an entry in `Anchor__AllowedOrigins` the browser discards the
anchor's answer before the sign-in code reads it. There is deliberately no wildcard — this surface
mints credentials.

### One member of a cluster

The anchor joins a cluster **directly** — not through a node, not through an API — as a member of
kind `anchor`. It needs the shared secret in `/etc/kgsm/kgsm-cluster.env` and nothing else; a machine
with no secret is not part of a cluster, which is a state rather than a misconfiguration.

**Which member holds the accounts is cluster state, not configuration.** When nobody holds them, the
anchor on the machine that founded the cluster claims them — the machine whose founding record,
`/etc/kgsm/cluster-founded`, names the secret it holds. An anchor anywhere else never claims: an empty
assignment there means gossip has not reached it yet, and a claim made in that window competes with the
real holder. Only an admin's reassignment moves the accounts afterwards. Nothing promotes itself — an
anchor that did so during a partition would produce two members issuing conflicting statements about
who may do what.

That gives an anchor three standings, and the first is what leaves a standalone install alone:

| standing | when | what it serves |
|---|---|---|
| **standalone** | no cluster secret | everything. Its accounts are this machine's and there is no assignment to read |
| **holder** | the assignment names it | everything |
| **standing by** | the assignment names somebody else, or nobody yet | `503 not_the_anchor`, naming the holder in the message and on an `X-Kgsm-Auth-Holder` header |

A member standing by is a **promotion candidate, not a second authority**: the sessions it could mint
would be signed with a key no member verifies against. Signing out stays open even then — it takes
authority away rather than granting it, and refusing would strand whoever is signed in to a member
that has since become a candidate.

**The key reaches other members as a gossiped fact** the anchor publishes about itself, which a reader
resolves *through the holder* — so a key stated by a member that does not hold the capability is never
consulted. A leaf, which does not join the cluster, reads the host file the node on its machine writes
from that same read (`Auth.Cluster`'s `HostProviderFile`).

### Running one

```bash
./deploy/setup.sh          # once per host, asks for sudo
./deploy/deploy.sh         # every deploy, no sudo, no prompts
```

Its whole configurable surface is `src/Auth.Anchor/kgsm-auth-anchor.settings.json`, which the build
generates `deploy/kgsm-auth-anchor.anchor.json` from — so the Control Panel renders the page from the
same declaration the daemon binds. Edit the settings class, never the JSON.

The pacman package installs it **switched off**. A cluster has one anchor and which machine holds it
is a decision, so installing the package claims nothing: a second machine with it installed and
stopped is a promotion candidate rather than a second authority.

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
