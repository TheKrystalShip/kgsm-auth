# kgsm-auth

The shared authorization model for the KGSM ecosystem: **one definition of who may do what**, used by
every surface onto a host, so the same person gets the same authority through the Control Panel, the
assistant and the Discord bot alike.

Five libraries, a test package and one daemon. The daemon — **`kgsm-auth-anchor`** — is the cluster's
sign-in provider: it holds the accounts, signs people in, and mints every session, and every install
runs one. The libraries are what every other component compiles against to verify those sessions and
decide what the person holding one may do. None of them can mint a session.

## Packages

| package | contents | taken by |
|---|---|---|
| **`TheKrystalShip.KGSM.Auth`** | the identity, the failure of an identity or account source, the session claim names, the actor convention. **No dependencies, AOT-safe.** | every surface |
| **`TheKrystalShip.KGSM.Auth.Access`** | the access model — actions, permissions, ranked roles, assignments scoped to the cluster, a node or an instance, service accounts and their requirements — the evaluator every access question goes through (`AccessEvaluator.Allows`), the rules deciding who may change any of it (`AuthorityRules`), and what `/me/access` answers (`AccessReport`). **No dependencies, AOT-safe.** | every member |
| **`TheKrystalShip.KGSM.Auth.Users`** | KGSM's own accounts — local passwords, the credentials that prove an account — and the authority over them, in one SQLite file (`SqliteAuthorityStore`): the anchor's authoritative copy and every member's replica. | kgsm-api, kgsm-llm, kgsm-bot, kgsm-dns |
| **`TheKrystalShip.KGSM.Auth.Journal`** | the account events, named and written in one place for every writer. | the anchor, kgsm-api |
| **`TheKrystalShip.KGSM.Auth.Cluster`** | everything a member or a leaf does about identity as a resource server of the anchor: verify a session it cannot mint (`ClusterSessionValidation`) and read who holds it (`SessionClaims`), read the published key set (`SessionKeys`), admit the provider's registered clients (`IClientOrigins`), honour a session somebody ended (`SessionRevokeHandler`, `ClusterSessionRevocations`), replicate the authority (`AddAuthorityReplica`) and answer for a person from it (`MemberAccess`), write and read the host file a machine's leaves verify against (`HostProviderFile`, `HostSessionKeys`), and name the sign-in provider (`ProtectedResourceMetadata`). | kgsm-api, kgsm-llm, kgsm-bot, kgsm-dns |
| **`TheKrystalShip.KGSM.Auth.Testing`** | the anchor's session minter and signer, compiled from the anchor's own source, so a test presents a session exactly as the anchor would mint it. | test projects only |

The deployable is **`kgsm-auth-anchor`** (`src/Auth.Anchor`), built from those libraries and shipped
as a pacman package and a systemd unit. It publishes nothing to NuGet: minting, the session registry,
the Discord round trip and the OAuth handshake are its own code, so no other component can compile
them.

## The model

Components declare the **actions** they perform (`kgsm:server.start`, `auth:roles.edit`); actions are
filed into **permissions**, permissions into ranked **roles**, and a role is **assigned** to an account
at a scope — the cluster, a node, or one server. Owner holds everything; `everyone` is what every active
person holds. The full model and its rules are `kgsm-docs/plans/permissions.md`.

One function decides every request, on the anchor and on every member from its own replica:

```csharp
AccessDecision decision = evaluator.Allows(accountId, "kgsm:server.start", AccessScope.ForInstance(node, id, nonce));
if (!decision.Allowed)
    return Deny(decision.Reason);
```

**A session proves who, never what.** The token names an identity; a member finds the account that
identity is a credential of in its replica and evaluates it there, so a change of access lands on the
next request with no session ended.

**Every surface answers it the same way, including kgsm-bot.** The bot has no login of its own, so the
Discord account the gateway hands it *is* the identity — resolved to whatever KGSM account it is
attached to, exactly as for a browser that signed in with a password. An identity attached to no
account holds nothing. A group or a guild role is a fact about somewhere else and is not consulted
anywhere. A store that cannot be read **throws** rather than answering: "we could not ask" is not "the
answer is no", and reporting the first as the second locks an Owner out mid-incident.

## Configuration

The anchor reads the external providers it offers from the `KgsmAuth` section, keyed by provider name:

```
KgsmAuth__Providers__discord__ClientId=…        # one OAuth application, at one provider
KgsmAuth__Providers__discord__ClientSecret=…    # environment only
KgsmAuth__Providers__github__ClientId=…         # a second provider is two more keys
KgsmAuth__Providers__github__ClientSecret=…
```

A provider with both keys set is offered on the sign-in page; one with either missing, and one nobody
has heard of, are the same answer — not offered. No other component holds an application: they
authorize, and the account store answers that.

## Why it is dependency-free

Every surface takes this assembly, including the Discord bot, whose deploy is tuned for footprint.
Anything referenced here would reach all of them, so it stays a pure library: no HTTP, no
configuration binder, no ORM. Transports that need those live in sibling packages that only the
surfaces needing them take.

## Development

```bash
dotnet build kgsm-auth.slnx
dotnet test kgsm-auth.slnx
../scripts/publish-packages.sh kgsm-auth     # pack + push to the org's GitHub Packages feed
```

A consumer pins a version from that feed, so a change here needs a version bump, a publish, and then
the pin moved on the consumer. A published version is immutable — pushing one again is a `409` the
script reports as already published — so the change a consumer restores is always the one you built.

## An external provider's round trip

When the anchor sends a browser to Discord, one handshake carries both halves of the defence, in one
HttpOnly cookie:

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

KgsmIdentity? identity = await directory.VerifyAsync(code, handshake.CodeVerifier, ct);
```

**`state` and PKCE are not alternatives.** `state` stops login CSRF — without it an attacker starts
their own login, sends the victim a callback link carrying the attacker's `code`, and the victim's
browser is handed a session for the *attacker's* identity. PKCE stops code interception, because a
`code` rides back in a URL and URLs leak.

**The state has to be bound to the browser, and only the cookie binds it.** Checking a returned state
against a server-side set of issued states proves that *some* login started here — which is
true of the attacker's login too, so it admits the exact request it was meant to refuse. Single-use
consumption stops replay, not CSRF.

Carrying the verifier in the same cookie is what lets the anchor run PKCE with **no server-side
pending store**, so a round trip survives a restart.

## Honest failure

A login answers three different things and they must not be collapsed:

| what happened | means | result |
|---|---|---|
| the code exchanged, `users/@me` answered | a verified identity | the account it proves, or an unapproved one created for it |
| `4xx` from the token endpoint | an expired, replayed or forged code | `null` — a `401`, start again |
| `5xx`, unreachable, malformed | **unknown** | `DiscordAuthException` — a `502` |

The third is the one that matters. "We could not ask" is not "the answer is no": a door that reads
an outage as a verdict either locks out someone who really does hold the role or admits someone who
does not. The same rule holds one layer down — a store that cannot be read throws rather than
resolving to `none`.

## Sessions

The anchor mints every session. A stateless JWT can say who someone is; it cannot say whether their
session is still alive, and that one fact is what the anchor's session registry holds.

```csharp
var tokens = new SessionTokenService(
    new SessionTokenOptions(
        Audience: clusterId,
        AccessLifetime: TimeSpan.FromMinutes(15),
        RefreshLifetime: TimeSpan.FromDays(30),
        Issuer: "https://auth.anchors.example.com"),
    signer);

MintedToken access  = tokens.MintAccess(identity, sid);
MintedToken refresh = tokens.MintRefresh(identity, sid);
```

**`RefreshLifetime` is written once and used twice** — the token's expiry and the registry row's. It
is a setting rather than a constant precisely so there is no second copy to drift, because the drift
is invisible until a token outlives its own row or the reverse.

**The audience and the issuer are validated everywhere.** Changing either on a running cluster makes
every member refuse every session already issued, and everybody signs in again.

**A member verifies and never mints.** `ClusterSessionValidation.Accepting` takes what the anchor
publishes — its key set, its audience, its issuer — and pins ES256, so the public key a member holds
can never be offered back to it as an HMAC secret. A member that has not heard from the anchor accepts
nothing. A session somebody ended arrives as `session.revoke` over the cluster bus and is held on the
member's own deny-list until its bearer could no longer be presented.

**A test mints through `Auth.Testing`.** A test project that needs a signed-in caller takes the anchor's
`SessionTokenService` and `EcdsaSessionSigner` from that package, and hands the member under test the
signer's public half in place of what gossip would have delivered. The member then verifies exactly as
it does in production.

### Rotation and reuse

Every refresh mints a new pair and stores the new `jti`. A refresh presenting any other `jti` is a
replay of a token that has already been rotated away — `RotateAsync` returns false, and the caller
refuses. It cannot tell a stale client from a stolen token, so it refuses both and lets the real
holder authenticate again.

### The cache is the revocation bound

The anchor's `SessionValidator` caches the registry's answer, so the hot path does not query per request. A revoke
evicts, making the kill immediate; the TTL is the backstop for what cannot evict. Expiration is
**absolute, never sliding** — a sliding window is extended by every hit, so the busiest session, the
one most worth revoking, would be the one that never re-checks. A "no" is cached too, because a
revoked session still presenting its token is exactly what a stolen one does.

## The auth anchor

`kgsm-auth-anchor` is the member of a cluster that holds the accounts. One store, one writer, one
address a person signs in at — an OpenID Connect provider every browser surface is a client of — and
a session it mints is valid on **every** member, because its audience is the cluster rather than a
machine. The identity design is `../cluster-auth-plan.md` and the sign-in's is
`../hosted-sign-in-plan.md`; this is what the daemon serves.

| | |
|---|---|
| `GET /health` | the ecosystem's liveness probe |
| `GET /authorize`, `POST /token`, `GET /sign-out` | the OpenID Connect doors; the only way a session is minted, renewed or ended by its holder |
| `GET /auth/cluster/users` | every account, to a caller holding any `auth:*` action |
| `GET /auth/cluster/users/{id}/sessions` | an account's live sessions, on `auth:accounts.disable` |
| `GET /auth/cluster/public-key` | the verification key set |

**Sessions are signed asymmetrically, and that is the whole point.** The anchor holds the private
key; every member verifies with the published public one. A member that could mint what it verifies
could mint itself an Owner's session, so it holds only what checks a signature.

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

**Access is evaluated on every request, never read off the token.** The token carries no claim about
it, so a change of access lands at the caller's next request. The account's standing is re-read on
refresh too, and a withdrawn account has its session ended there rather than being left to run out
its bearer.

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
| `GET/POST /auth/cluster/clients`, `DELETE /auth/cluster/clients/{id}` | the client registry, to a caller holding any `auth:*` action |

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
Anything else is registered through the registry. Redirects are matched exactly and must be HTTPS, or HTTP where
the cluster itself accepts plaintext — this machine, a private network or a local name — so a cluster of
one on a LAN has somewhere to send a code. A registered client's origin may read discovery, the key set,
`/token`, `/userinfo` and the account API across origins, without credentials; nothing that reads the
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

**A client's origin is what is admitted across origins, and nothing else.** A surface on another
origin reads the discovery document, exchanges its code and drives the administration with the bearer
it holds, so every registered client's origin is answered on those paths — without credentials, and
never on anything that reads the provider's cookie. There is deliberately no wildcard: this surface
mints credentials. The same origins are published as `auth.origins` for every member to admit.

### One member of a cluster

The anchor joins a cluster **directly** — not through a node, not through an API — as a member of
kind `anchor`. It needs the shared secret in `/etc/kgsm/kgsm-cluster.env` and nothing else; a machine
with no secret is not part of a cluster, which is a state rather than a misconfiguration.

**Which member holds the accounts is cluster state, not configuration.** When nobody holds them, the
anchor on the machine that founded the cluster claims them — the machine whose founding record,
`/etc/kgsm/cluster-founded`, names the secret it holds. An anchor anywhere else never claims: an empty
assignment there means gossip has not reached it yet, and a claim made in that window competes with the
real holder. Only a reassignment under `api:members.manage` moves the accounts afterwards. Nothing promotes itself — an
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
var store  = new SqliteAuthorityStore(new UserStoreOptions());     // the anchor's account store
var signIn = new LocalSignInService(store, new IdentityPasswordHasher());

LocalSignInResult result = await signIn.SignInAsync(username, password, DateTimeOffset.UtcNow);
if (result.Outcome == LocalSignInOutcome.Success)
    Mint(result.Identity!);
```

**A credential answers "which account is this"; the account's roles answer "what may they do".**
Nothing else contributes. That is what lets a provider be added with no access story of its own — the
login path is the same shape whichever credential proved the account.

**One writer, and a replica on every member.** The anchor's store is the authority; every other member
holds a read-only replica in its own file, built from the anchor's snapshot and kept current by the
changes it sends, and evaluates every request from that. A member's replica is a host *resource*, not a
service, so nothing on the serving path can be down, and no leaf ends up authenticating through a
sibling.

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
- **No SMTP, anywhere.** A reset is set by somebody holding `auth:accounts.create`. Adding a mail dependency to the thing whose
  purpose is removing outside dependencies would be self-defeating.
