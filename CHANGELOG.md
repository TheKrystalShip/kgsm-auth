# Changelog

All notable changes to `kgsm-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — a public vhost, and loopback for the daemon itself (`1.2.0`)

A person signs in against the anchor directly, once, for the whole cluster — so unlike a leaf's unix
socket this is a public surface and needs a name a browser can reach. `deploy/nginx/kgsm-auth-anchor.conf`
is that vhost, installed by `setup.sh` alongside the polkit grant and skipped cleanly on a host with
no nginx. The anchor owns its vhost and nothing else: the `:80` ACME block and the certificate
lifecycle stay host-level, because a component that claimed them would make every other one on the
box depend on it.

**The daemon now listens on `127.0.0.1` rather than every interface.** TLS is terminated by the proxy
in front of it, which is where the certificate lives; binding the world would put an unencrypted
sign-in on the network beside the encrypted one.

`Anchor__PublicBaseUrl` states the address browsers and other members reach it at. A daemon behind a
proxy sees only the loopback hop and cannot work this out for itself, and it is what the cluster
roster carries — so an unset or wrong value means members pinning an address that answers nobody.


### Added — the anchor is a cluster member (`1.1.0`)

`kgsm-auth-anchor` consumes `TheKrystalShip.KGSM.Cluster` and joins a cluster as a member of kind
`anchor` — directly, needing no kgsm-api on its machine. Its roster, outbox and inbox live under its
own `StateDirectory=`, so a node and an anchor on one machine share nothing that would make one's
membership depend on the other's process.

Which member holds the cluster's accounts is **cluster state**, not configuration. The first anchor in
a cluster with none claims it set-if-absent; only an admin's versioned reassignment overwrites one
that exists. Nothing promotes itself, because an anchor that did so during a partition would produce
two members issuing conflicting statements about who may do what.

The key members verify sessions with is a **fact the anchor publishes about itself**, gossiped with
its card. A reader resolves the holder first and takes the fact off that member alone, so a key stated
by a member that does not hold the capability is never consulted.

**Three standings, and the first is what leaves a standalone install untouched.** A machine with no
cluster secret has no assignment to read, holds its own accounts, and serves everything as before.
A member the assignment names serves everything. A member it does not name **stands down**: it mints
no session, extends none and answers for no account, replying `503 not_the_anchor` with the holder
named in the message and on an `X-Kgsm-Auth-Holder` header. Signing out stays open — it takes
authority away rather than granting it, and refusing would strand whoever is signed in to a member
that has since become a candidate.

`Anchor__MemberId` names this anchor to the cluster, deriving one from the machine name when blank —
a machine can run more than one member, so it is deliberately not the machine's name.
`Anchor__PublicBaseUrl` states an address for a machine that cannot see its own.

### Fixed — only the holder writes the shared verification key

`/var/lib/kgsm/cluster/auth-public-key.json` is written by the member holding the capability and by
nobody else. A filesystem path carries no statement about who wrote it — unlike the gossiped fact,
which a reader scopes to the holder — so an anchor standing by that wrote there would hand every
member on that machine a key verifying nothing anybody signed with.

A member withdraws only a file whose contents are its own key, never one holding somebody else's, and
the holder reconciles the file on every pass rather than writing it once. That is what closes the
window a second anchor on the same machine opens: it claims while isolated, publishes, then learns the
holder, stands down and withdraws its own key, and the holder restores the file within one gossip
interval.


### Added — `kgsm-auth-anchor`, the daemon that holds a cluster's accounts (`1.0.0`)

The first deployable this repo produces. It serves the account store the libraries already own — one
sign-in for a whole cluster, at one address — and publishes the key every member verifies a session
with. Native AOT with `CreateSlimBuilder` and minimal APIs, `Microsoft.Data.Sqlite` under both
stores, and a config descriptor generated from its settings class like every other configurable KGSM
component. Authority is `../cluster-auth-plan.md`.

The surface:

| | |
|---|---|
| `GET /health` | the ecosystem's liveness probe |
| `POST /auth/sign-in` | verify a KGSM password, mint a cluster-scoped session |
| `POST /auth/session/refresh` | rotate both tokens, re-reading standing from the store |
| `POST /auth/session/sign-out` | end a session, by refresh token or by bearer |
| `GET /auth/session` | who the caller is, resolved on this request |
| `GET /auth/cluster/users` | every account, admin only, never a secret in any form |
| `GET /auth/cluster/public-key` | the verification key set, unauthenticated |

A session's audience is the **cluster**, not a machine, which is what makes one sign-in valid on
every member of it. Authority is read from the store on every request rather than from the token, so
a demotion takes effect at the caller's next request. Nothing on the refresh path leaves the machine.

The private signing key is generated once, on a machine that has none, at `0600` inside the unit's
state directory, and the public half is published to `/var/lib/kgsm/cluster/auth-public-key.json`
for the other members on that machine. A key file that exists and cannot be read stops the daemon
rather than being replaced — silently generating a new one would invalidate every session in the
cluster and leave every member verifying against something nothing signs with.

Deployed the ecosystem way: `deploy/setup.sh` once, `deploy/deploy.sh` forever after, plus a pacman
package. The package is preset-**disabled**: a cluster has one anchor, and which machine holds it is
a decision rather than a default, so installing it claims nothing.

### Added — asymmetric session signing (`Auth.Sessions` 2.1.0)

`ISessionSigner`, and `EcdsaSessionSigner` over P-256/ES256. `SessionTokenService` takes one and
signs with it; without one it signs and verifies with the shared HMAC secret exactly as before, so
every surface that mints and checks its own tokens is untouched.

This is what lets a session be verified somewhere it cannot be minted. A member holding the
published key checks a signature and cannot produce one, so a compromised surface can read what its
tier allows and cannot promote itself. `ValidAlgorithms` is pinned on validation for the same
reason: a public verification key offered as an HMAC secret would make the key everybody holds the
key everybody can sign with.

A key is published as a JWK set — `EcdsaSessionSigner.PublicKeysJson`, read back with `ReadKeys` and
turned into verification keys with `VerificationKeysFrom`. A set rather than one key because
rotation needs an overlap: the incoming key is published beside the outgoing one, every verifier
picks up both, and only then does the signer move. The `kid` is the key's own RFC 7638 thumbprint,
so two holders of one key compute one id and a rotated key cannot reuse the previous one's.


### Added — `KgsmRelaySecret`, the secret a host mints for itself (`Auth` 3.2.0)

`KgsmRelaySecret.Resolve(configured, path?)` returns the secret a trusted relay proves itself with:
a value the host pinned deliberately, or the contents of `/var/lib/kgsm/auth/relay-secret`, minting
that file when it is not there yet. It sits beside the account store because `/var/lib/kgsm` itself is
root-owned on a host provisioned from a checkout — `auth/` is the directory in the shared tree these
surfaces own on every host, and therefore the only one they can mint into. The first surface to ask creates it and the rest read what it wrote,
so the assistant, the Control Panel API and the Discord bot hold the same string with nothing asked
of an operator.

Creation is exclusive and the file is owner-only from the instant it exists, so concurrent first
starts cannot mint two different secrets and the value is never world-readable for an instant.
Every failure path yields an empty secret, which each consumer already reads as "the relay path is
off" rather than as "no secret required".

### Added — `Passwords`, the one password floor (`Auth.Users` 1.3.0)

`Passwords.MinLength` (12) and `Passwords.IsAcceptable`. Every door that sets a password reads the
same constant — registration, an admin resetting one, and a holder changing their own — because a
floor checked separately in three callers is three places for it to drift low. Length is the whole
rule: a composition requirement measures a shape rather than an amount of guessing.

### Changed — the pending sweep reads provenance, not whether a password is set (`Auth.Users` 1.3.0)

`IdentityLinkService.ExpirePendingAsync` removes an unapproved account past the TTL when its tier is
`TierSource.Derived` — it arrived on its own. An account an admin created or approved carries
`TierSource.Granted` and is spared however long it waits.

**This changes what gets swept.** An account that holds a password is no longer spared for that
reason alone. A self-registered account has one and no admin has ever looked at it, so sparing every
password-bearing account would let self-registrations accumulate against `PendingPolicy.Cap` until
the host refuses every new arrival — a queue nobody can drain, indistinguishable from outside from a
host that is simply closed. A host running with self-registration open should size
`PendingUserTtlDays` to how long an admin may reasonably take to look.

### Changed — package license metadata is GPL-3.0-or-later

`PackageLicenseExpression` now matches the repo's own `LICENSE` on every published package. Already
published versions keep the metadata they were built with, since a published version is immutable —
the correction reaches consumers on the next version bump.

### Changed

- **`KgsmAuthOptions` holds a host's applications by provider name** (`Auth` 3.0.0, breaking):
  `Providers["discord"].ClientId`, bound from `KgsmAuth__Providers__discord__ClientId`. Adding a
  provider to a host is a pair of environment keys and no code anywhere, and nothing above the type
  names one. `For(provider)` answers with an unconfigured application rather than null, so a provider
  nobody wired up and a provider nobody has heard of are one answer and a caller needs no existence
  check; `ConfiguredProviders()` is the set a login page may draw a button for. Lookup is
  case-insensitive, because a provider name is written in an environment key, in a route and in a
  credential handle.
- **`DiscordDirectory` takes one `KgsmOAuthApplication`** (`Auth.Discord` 4.0.0, breaking) instead of
  the host's whole set. It needs one application, and a composition that hands it one cannot hand it
  another provider's by accident.

### Removed

- **`KgsmRoleMap` is gone, and with it `KgsmAuthOptions.GuildId`, `BotToken`, `RoleAdminIds`,
  `RoleOperatorIds`, `ToRoleMap()` and `CanResolveRoles`** (`Auth` 2.0.0, breaking). kgsm-bot was the
  last surface reading a guild role, and it now resolves the Discord account it is handed against the
  KGSM account store like every other surface — so no authority anywhere derives from a group, a
  guild or a role, and a host that sets a role id grants nothing by it. `KgsmAuthOptions` keeps
  `ClientId` and `ClientSecret`: the application people sign in through, and nothing else.
- **`DiscordDirectory` no longer implements `IAuthorityProvider`** (`Auth.Discord` 3.0.0, breaking).
  Guild membership and guild roles are not an answer to what a person may do on a KGSM host, so the
  provider answers who someone is and nothing else: `ResolveTierAsync`, `GetGuildRolesAsync`,
  `GetGuildMemberAsync`, the `DiscordMember` record and the `KgsmRoleMap` constructor argument are
  gone, and it no longer reads a guild id or a bot token.

### Added

- **`IdentityLinkService.UnlinkAsync`** (`Auth.Users` 1.2.0) — detaching a credential, scoped to the
  account it is on: an id copied from somewhere else is `NotFound`, the same answer as one that does
  not exist, so the outcome never says whether an id is real. The last credential is refused, because
  an account with nothing attached is one its own holder cannot sign in to.
- **`IdentityLinkService`** — the step between a verified external identity and an account. It finds
  the account an identity proves, or creates an unapproved one for it to prove: signing in at a
  provider establishes who somebody is and never that they belong here, so a first arrival lands at
  `Pending`/`None` for an admin to decide on. Idempotent, so a login path calls it on every sign-in
  rather than only the first, and two callers racing on one identity end with one account because
  the credential handle is unique in the database. Never auto-links on a matching email or username:
  providers disagree about what "verified" means, and matching on one is a documented
  account-takeover route.
- **`PendingPolicy`** — a cap on how many unapproved accounts a host holds, and a TTL that keeps the
  cap from becoming a lockout. Expiry only ever removes an account that arrived on its own, is still
  unapproved, and has no password.
- **`UserStoreAuthority.ResolveAsync`** returns the three answers a surface has to tell apart —
  the account may be used, there is no account, the account is switched off — because only the third
  is a reason to end a live session. Answers are cached for a caller-chosen TTL, which is therefore
  the staleness bound on a demotion; a read failure still throws and is never cached, so a moment of
  unavailability cannot become a full-TTL lockout.
- **`Usernames.Sanitize`** — the nearest usable username to a provider's, for the one case where a
  name is not typed by a person. Returns null rather than inventing one when nothing usable survives.
- **`DiscordDirectory.GetGuildMemberAsync`** — the member behind a user id: their name and the roles
  they hold, from the one lookup that already carried both. `GetGuildRolesAsync` is unchanged and
  reads through it, and the three answers (not a member ⇒ null, a member with no roles ⇒ empty, a
  failed lookup ⇒ throw) stay three answers.

### Added

- **`TheKrystalShip.KGSM.Auth.Users`** — KGSM owns identity. A local account is the primary object:
  it exists on its own, carries the tier, and an external provider becomes one way to prove you are
  an account KGSM already knows about rather than the source of one.
  - `KgsmUser` / `UserStatus` / `TierSource`: the account, whether it may be used, and whether its
    tier was granted by an admin or derived from a mapping. An account that is not active resolves
    to `None` whatever is written on it.
  - `UserCredential` / `CredentialKind`: what proves an account — a local password, a linked
    external identity, and a typed column so a third kind costs a row rather than a migration. One
    unique index on the handle both stops an identity being linked to two accounts and holds an
    account to a single password.
  - `IUserStore` / `SqliteUserStore`: a host-level SQLite file at `/var/lib/kgsm/auth/users.db`, `0600`,
    WAL with a busy timeout, read and written directly by every surface on the host so no leaf
    depends on a sibling to authenticate anyone. Schema changes are additive only, the file carries
    a `schema_version`, and a store written by a newer build is refused rather than half read.
  - `LocalSignInService`: username and password, with an unknown username and a wrong password
    giving one answer at one cost, exponential per-account lockout, and rehash-on-upgrade so a
    change of hash format migrates accounts as their owners sign in.
  - `UserStoreAuthority`: the `IAuthorityProvider` that answers from the account. An identity linked
    to nobody holds nothing; a store that cannot be read is an outage and never a denial.
  - `IUserPasswordHasher` / `IdentityPasswordHasher`: `PasswordHasher<T>` behind a seam, so the hash
    format can be replaced without a forced reset.

### Changed

- **Identity is provider-agnostic.** `KgsmIdentity(Provider, Subject, …)` replaces `DiscordIdentity`
  across the shared packages, and `Auth.Sessions` no longer references `Auth.Discord` at all — the
  token layer mints and reads whatever provider a host signed someone in through. A session subject is
  `provider:subject`, which for a Discord login is the same `discord:<id>` string as before, so no
  issued token or stored session row changes meaning.
- **Who someone is and what they may do are separate seams.** `IIdentityProvider` verifies an identity;
  `IAuthorityProvider` resolves the tier it holds; `ISignInService`/`SignInService` compose the two, so
  either can be replaced without touching the other or the login path. `DiscordDirectory` implements
  both, and `IDiscordDirectory` is gone.
- **`OAuthHandshake` and the tier cache moved into the dependency-free core** (`KgsmTierCache`,
  keyed by the provider-qualified handle). Neither was ever Discord's: the state+PKCE handshake is a
  property of the authorization-code flow, and a per-user tier cache is a property of re-deriving
  authority.
- **`DiscordAuthException` derives from `KgsmAuthProviderException`**, so a caller that treats any
  provider's outage the same way catches the base type and knows nothing about Discord.
- **`KgsmActor.Discord` is removed** — `KgsmIdentity.ActorString` builds the same `provider:username`
  string from the identity that already knows its provider.

### Added

- **`TheKrystalShip.KGSM.Auth.Sessions`** — session tokens and the storage seam.
  - `SessionTokenService`: HMAC-SHA256 access + refresh JWTs, `sid` stable across rotation, a fresh
    `jti` per mint. Lifetimes and issuer are settings, so one value drives both the token's expiry and
    the registry row's, and a surface that already mints keeps its issuer rather than 401ing every
    live token.
  - `ISessionRegistry` / `SessionRegistration`: create, liveness, rotate-with-reuse-detection, revoke,
    GC. Storage is each surface's own.
  - `SessionValidator`: the cached per-request check. Absolute expiry, denials cached, namespaced keys.
  - `SessionCleanupWorker`: startup catch-up pass plus a timer; a failed sweep never kills the worker.

- **`TheKrystalShip.KGSM.Auth.Discord`** — the ecosystem's single chokepoint to `discord.com`.
  - `IDiscordDirectory` / `DiscordDirectory`: the OAuth exchange, `/users/@me` identity verification,
    and the bot-token guild-role lookup that resolves a tier. Not-a-member, a member with no roles,
    and a failed lookup stay three distinct answers.
  - `OAuthHandshake`: CSRF `state` + PKCE verifier in one HttpOnly cookie, so a surface runs PKCE with
    no server-side pending store and the state is bound to the browser that started the login.
  - `DiscordTierCache`: short-TTL per-user tier cache for surfaces that re-derive authority per
    request. Caches denials too.

## [1.0.0]

### Added

- `TheKrystalShip.KGSM.Auth` — the shared authorization model, dependency-free and AOT-safe.
  - `KgsmTier` / `KgsmTiers`: the ordered viewer/operator/admin ladder and its wire form, with
    fail-closed parsing.
  - `KgsmRoleMap`: Discord role ids → tier. Guild membership is the access gate; a verified member
    floors at viewer. `Resolve` for string snowflakes, `ResolveSnowflakes` for the numeric form a
    gateway client holds.
  - `KgsmAuthOptions`: the `KgsmAuth` configuration section every surface binds.
  - `KgsmAuthClaims` / `KgsmTokenKind` / `KgsmRelayHeaders`: session claim and relay header names.
  - `KgsmActor` / `KgsmActorProvider`: the `provider:name` actor convention.
