# CLAUDE.md — kgsm-auth

Guidance for Claude Code working in **kgsm-auth**. Read `README.md` for the model itself; this file is
the "what you must not break".

## What this is

The shared authorization model for the ecosystem. `TheKrystalShip.KGSM.Auth` is consumed by kgsm-api,
kgsm-llm and kgsm-bot, so a change here changes who can do what on every surface at once.

**Identity and authority are two seams, not one.** `IIdentityProvider` answers *who is this* (the
OAuth bounce and the code exchange); `IAuthorityProvider` answers *what may they do* (the tier);
`ISignInService`/`SignInService` composes them into one login. The two halves come from two different
places: an identity provider answers the first, and `Auth.Users` answers the second for everyone,
however they signed in. **`IAuthorityProvider` has exactly one implementation that ships: the account
store.** A provider package implements the identity half and nothing else, which is what lets one be
added with no authority story of its own. Nothing above the seams names a provider.

**KGSM owns the accounts.** `Auth.Users` holds them in one file per host: a local account exists on
its own with a password, and an external identity is a credential attached to it. So the two seams
have two different sources — a provider verifies who someone is, and the account store alone says
what they may do.

**The repo also holds one deployable.** `src/Auth.Anchor` builds `kgsm-auth-anchor`, the cluster
member that holds the accounts and signs people in to the whole cluster at once. It is built from
these libraries and publishes nothing to NuGet, so a change to a library is a compile break here
before it is anything else.

This file is the authority for the auth design; the account-store design is also covered by
**`../auth-internal-users-plan.md`**, and the anchor's own design by **`../cluster-auth-plan.md`**.

## Locked decisions (do not relitigate)

- **`TheKrystalShip.KGSM.Auth` has ZERO package dependencies and stays AOT-safe.** Every surface takes
  it, including the footprint-tuned bot deploy and the CLI. No `HttpClient`, no configuration binder,
  no ORM, no logging abstraction. `IsAotCompatible` and the trim analyzer are on and must stay green.
  Anything needing I/O belongs in a sibling package that only its consumers take.
- **A subject is unique only within its provider.** `KgsmIdentity` carries both, and `Handle` is
  `provider:subject`. Never key a user, a session or a link on the subject alone: two providers can
  hand out the same string for two different people, and collapsing them gives one of them the
  other's authority. `Handle` also never falls back to the username — a username is renameable at
  most providers, and keying on one detaches a person from their own sessions the day they rename.
- **`ActorString` and `Handle` are different strings on purpose.** The handle keys things; the actor
  string (`provider:username`) is what a human reads in an audit log. Do not merge them.
- **Three ordered tiers, and the ordering is load-bearing.** `admin ⊇ operator ⊇ viewer` is what lets a
  viewer requirement admit an operator. Do not add a tier between them without walking every
  consumer's gate, and do not add a parallel boolean axis — a permission the tier ladder cannot express
  lets surfaces answer the same question differently.
- **No surface derives authority from a group, a guild or a role.** `KgsmAuthOptions` carries the
  host's OAuth applications and nothing else; the account store is the single authority on what
  anyone may do, including for kgsm-bot, whose caller is a Discord account with no login behind it.
  Do not add a role map: an authority source that lives outside the account lets surfaces disagree
  about one person.
- **Parsing is fail-closed.** `KgsmTiers.Parse` maps anything unrecognised — absent, misspelled, or a
  tier invented by a newer peer — to `None`. Never add a permissive fallback.
- **A provider is a key in a map, never a property.** `KgsmAuthOptions.Providers` is keyed by
  provider name, so wiring a host to a new provider is a pair of environment keys and no code — and
  no type above it names one. Do not add a per-provider property beside the map: an asymmetry there
  is how one provider ends up with a login path the others do not have. `For()` returns an
  unconfigured application rather than null on purpose, so an unwired provider and an unknown one are
  one answer and no caller writes an existence check that could disagree with the configured check.

## `Auth.Discord` — locked decisions

- **It answers who, and only who.** `DiscordDirectory` is an `IIdentityProvider` and stays the only
  chokepoint to `discord.com`. It takes **one** `KgsmOAuthApplication`, not the host's set, so a
  composition cannot hand it another provider's by accident. It holds no guild, reads no role and
  takes no bot token: what a person
  may do is the account store's answer, and a login here proves one fact — that the caller holds this
  subject at Discord. `DiscordAuthException` derives from `KgsmAuthProviderException` so a caller
  handles any provider's outage identically.
- **The caller's token buys one thing and is dropped.** It is presented to `users/@me` and never
  stored, so a completed login leaves the host holding no credential at Discord at all.
- **Register it transient, and resolve it once per composition.** It is a typed `HttpClient`; holding
  one in a singleton pins a handler for the process lifetime and silently stops the factory rotating
  it, so DNS changes never land. The composition resolves the client once and hands the same instance
  to both halves, so one sign-in uses one client.

- **A bad code is `null`; an outage throws.** A 4xx from the token endpoint is an expired or replayed
  code — the caller's problem, a `401`, start again. A 5xx or an unreachable host is
  `DiscordAuthException`, which is a `502`. Collapsing them reports one as the other and sends a
  browser round a retry loop that cannot succeed.
- **`OAuthHandshake` is in the core, not here.** The state+PKCE pair is a property of the
  authorization-code flow, not of Discord, and every provider's login uses it unchanged.
- **`state` and PKCE ride one cookie and neither is optional.** `state` stops login CSRF and only
  works because the cookie binds it to the browser that started the login; a server-side set of issued
  states admits the attacker's own state. PKCE stops code interception. Do not "simplify" either away.
- **`SameSite=Lax`, never `Strict`.** Strict suppresses the cookie on the top-level redirect back from
  Discord, which breaks every login.
- **No web framework dependency.** The package hands the host a cookie *value*; the host writes the
  cookie. Taking a dependency on ASP.NET to save three lines would put it in every consumer and make
  the handshake untestable without standing up a server.

## `Auth.Sessions` — locked decisions

- **The token layer knows nothing about providers.** It mints and reads whatever `provider:subject`
  it is handed. A Discord login produces the subject `discord:<id>` —
  `SessionTokenServiceTests` pins that string, because changing its spelling is a flag day that
  invalidates every live token and orphans every stored session row at once.
- **The registry is a seam, not an implementation.** Two surfaces storing sessions differently behind
  one contract is the contract working. Don't add a "default" store that consumers drift onto.
- **`RefreshLifetime` and `Issuer` are settings, and both are load-bearing.** The lifetime is written
  once and used for both the token and the row, so there is no second copy to drift. The issuer is
  validated, so changing it on a running host logs everyone out — the neutral default is only for a
  surface that has never minted a token.
- **The validator's cache is absolute, never sliding, and caches denials.** Sliding would exempt the
  busiest session from ever re-checking; not caching "no" would let a revoked token query the registry
  on every request it makes.
- **A per-surface switch belongs at composition, not in the package.** kgsm-api's inert-sessions mode
  is a validator it substitutes and a worker it does not register — the shared types know nothing
  about a flag one surface has.

## `Auth.Users` — locked decisions

- **The account is the primary object; a credential only identifies.** A `KgsmUser` exists on its
  own and carries the tier. A password, a Discord subject and a GitHub subject are all just
  credentials attached to one. Nothing outside the account contributes to authority — that is what
  lets a provider be added with no authority story of its own, and it is the rule to check any
  change here against.
- **A credential handle is unique across the whole table, and that constraint is load-bearing.** It
  is simultaneously "an external identity belongs to exactly one account" and "an account has at
  most one password" (a password is filed under `local:<user id>`). Both rules are enforced by the
  database rather than by a check a second service could be written without.
- **Keyed by the opaque `usr_` id, never by the username.** A username is renameable and
  enumerable; keying on one detaches a person from their own sessions, links and audit trail the day
  they change it.
- **Additive-only schema, and the version is a floor.** The ecosystem's `EnsureCreated`-and-wipe rule
  does not apply to this one file: wiping it is every account and every password, and two
  independently deployed services share it, so one is routinely a version ahead. Add tables, add
  nullable columns, add indexes — never drop, rename, or repurpose. A file newer than the build
  opening it is **refused**, because half-understood accounts is the failure mode here that grants
  access quietly.
- **`0600`, set before WAL is enabled.** SQLite stamps `-wal`/`-shm` with the mode the database had
  when it created them, so chmod-after would leave two world-readable files carrying the same pages.
- **An unknown username and a wrong password are one outcome at one cost.** Distinguishable answers
  are a username oracle and so is a faster one — the unmatched path still spends a hash verification
  against a decoy. Do not add a "no such user" result for the sake of a nicer error.
- **The store fails closed on every parse**, the same rule as `KgsmTiers.Parse`: an unrecognised
  status reads as `disabled`, an unrecognised provenance as `derived`, an unrecognised credential
  kind as `identity`. Enums are stored as words, never ordinals, so reordering one cannot silently
  repoint every row.
- **A store that cannot be read throws, and never resolves to `None`.** "We could not ask" is not
  "the answer is no".
- **Lockout is exponential from a threshold, never a hard cap.** A hard cap hands anyone who knows a
  username a denial of service against its owner. The policy is a value applied inside the same
  transaction that records the failure, so the count and the lock it implies cannot disagree.
- **`PasswordHasher<T>` from `Microsoft.Extensions.Identity.Core`, behind `IUserPasswordHasher`.**
  Do not hand-roll, and do not reach for `UserManager`/EF Identity — this package owns its own schema
  and its own store. The seam plus the rehash-on-upgrade path is what lets the format be replaced
  later with no forced reset.
- **No SMTP, and no password reset by email.** A mail dependency in the package whose purpose is
  removing outside dependencies would be self-defeating. Resets are admin-initiated.
- **The store is the only production `IAuthorityProvider`.** An external provider proves you are an
  account this host already has and contributes nothing else, which is what lets a provider be added
  with no authority story of its own.
- **Three answers, never one tier.** `UserStoreAuthority.ResolveAsync` reports *usable*, *no account*
  and *disabled* separately, because only the third is a reason to end a live session and the first
  covers a pending account (which authenticates at `None`). Its cache TTL is the staleness bound on a
  demotion; a read failure throws and is never cached, or a moment of unavailability becomes a
  full-TTL lockout for somebody who really does hold the role.
- **Linking is scoped to an account, and the last credential is refused.** `UnlinkAsync` takes the
  account as well as the credential id, because the id is the whole of what a caller supplies and an
  unscoped one copied from elsewhere would detach a stranger's identity — "not yours" and "not real"
  are one answer for the same reason. An account with nothing attached is one its own holder cannot
  sign in to, so the rule lives here rather than in each caller; the store itself refuses nothing and
  only reports what happened.
- **An arriving identity is provisioned unapproved, never auto-linked.** `IdentityLinkService` creates
  a `Pending`/`None` account for a subject nobody has claimed. It never matches on an email or a
  username: providers disagree about what "verified" means, and matching on one is a documented
  account-takeover route. Provisioning is reachable by anyone who can complete a login at a configured
  provider, so `PendingPolicy` caps it and expires what nobody looks at — and expiry only ever removes
  an account that arrived on its own and is still unapproved. Provenance is what it reads, not whether
  a password is set: an account an admin created or approved carries `TierSource.Granted` and is
  spared however long it waits, while a self-registered one holds a password and must still expire,
  or the cap fills with a queue nobody can drain.
- **A password is at least `Passwords.MinLength` characters, and length is the whole rule.** Every
  door that sets one — registration, an admin reset, a holder changing their own — reads the same
  constant, because a floor checked in three callers is three places for it to drift low.

## `Auth.Journal` — locked decisions

- **It has ZERO package dependencies, and that is the whole design.** It is a wire shape two
  components must agree on, and one of them is a Native AOT daemon holding a cluster's account store.
  Anything that needs a logger, a container or a journal writer belongs in the caller.
- **The names and the payload writers live together and are called, never copied.** kgsm-api writes
  these lines on a host that holds its own accounts; the anchor writes them when a cluster's accounts
  are held by one. A reader deserializes into a fixed shape, so a field spelled differently by one
  writer does not throw — it lands as a null and the row renders with a name missing and nothing
  reported. That failure is why one implementation exists rather than two descriptions of it.
- **An absent value is a real null, never an empty string.** "Nobody looked this up" and "this is
  blank" are different facts, and a reader that meets `""` cannot tell which it has.
- **Facts, not sentences.** No summary, no severity, no formatted value: a reader builds those at read
  time, which is what lets one fact be worded one way in a Control Panel and another in a chat
  surface, and what keeps a wording improvement from applying only to rows written after it.
- **It never takes a password parameter.** What is recorded is that a credential was set and by whom —
  the only signal an account takeover leaves — and the credential is not part of that fact.

## `Auth.Anchor` — locked decisions

- **A session's audience is the CLUSTER, not a machine.** That single value is what makes one
  sign-in valid on every member, and changing `Anchor__ClusterId` on a running cluster invalidates
  every token at once. It is `SessionTokenOptions.HostId` because that field has always been the
  audience; what moved is what the audience names.
- **Signing is asymmetric and the verification key is published.** A member must be able to check a
  session it cannot mint — one that could mint what it verifies could mint itself an admin session.
  `ValidAlgorithms` is pinned for the same reason: a public key offered as an HMAC secret would make
  the key everybody holds the key everybody can sign with.
- **The private key is generated exactly once, on a machine that has none.** Every member in the
  cluster verifies against its public half, so a key that changed would invalidate every session and
  leave every member checking against something nothing signs with. A file that exists and cannot be
  read stops the daemon; it is never a reason to generate. It is created with mode `0600` rather than
  chmod'd after — the gap between write and chmod is exactly what the mode exists to close.
- **Authority is read from the store on every request, never off the token.** The tier claim is what
  was true at mint time. The same read happens on refresh, and a withdrawn account has its session
  revoked there rather than left to run out its bearer's lifetime.
- **A store that cannot be read is `503`, never `403`.** "We could not find out what this person may
  do" is a different fact from "they may do nothing", and reporting the first as the second locks out
  an admin mid-incident. It is the same rule `Auth.Users` states for the store itself.
- **Every endpoint is a plain `RequestDelegate` and every wire shape has source-generated metadata.**
  The routing overloads that bind an arbitrary delegate reflect over its parameters, which no
  Native-AOT service can do, and the failure appears at publish time rather than at build time. The
  same goes for a shape missing from `AnchorJsonContext`: it throws at runtime, not at build.
- **The CORS allowance is per configured origin and never a wildcard.** A person signs in here from
  a browser, so this is a surface that mints credentials; a wildcard invites any page to drive
  somebody's sign-in from their own browser.
- **The package is preset-disabled.** A cluster has one anchor and which machine holds it is an
  administrator's decision. A second machine with the package installed and the unit stopped is a
  promotion candidate, not a second authority.
- **Three standings, and collapsing the first into the third breaks every standalone install.** A
  machine with no cluster secret is not "not the holder" — there is no assignment to read, its
  accounts are its own, and it serves everything. `AnchorRole` is where that lives, and a clustered
  anchor starts at `StandingBy` rather than assuming it holds the capability until told otherwise:
  the optimistic default would make it the authority for exactly the window in which it does not know
  whether it is one.
- **`TryClaimAsync` returning true is not holding it.** It is compare-and-set against what *this*
  member currently knows, so two isolated anchors both succeed; the tie resolves when their gossip
  meets. Every claim is followed by a re-read, and a member that finds itself not the holder stands
  down. Measured: a second anchor claims, publishes, then stands down within one gossip round.
- **Only the holder writes `/var/lib/kgsm/cluster/auth-public-key.json`, and it reconciles rather
  than writes once.** The gossiped fact is scoped by its reader, which resolves the holder first; a
  filesystem path is scoped by nothing. A member withdraws only a file whose contents are its own
  key — one holding a different key belongs to whoever holds the capability, and removing it would
  break every member reading it.
- **The anchor writes its own event journal, and it is the only witness there is.** Signing in,
  creating an account and moving somebody's authority happen here for the whole cluster, so a line the
  anchor does not write is a fact that exists nowhere. The producer id has to be the name in the
  unit's `StateDirectory=`, because a reader establishes the producer from the path it read a line out
  of — a journal written anywhere else is not reported as misplaced, it is simply never found, and
  looks exactly like a daemon that recorded nothing. A test run relocates it with
  `KGSM_JOURNAL_STATE_ROOT`; left at its default, a suite that signs people in appends invented
  sign-ins to a live audit page.
- **A sign-in is recorded where a session is minted, which is one place.** Every door — a password, a
  registration, a provider redirect — goes through `MintSessionFor`, and they differ only in how they
  answer. A second mint site is a second place to forget the line, and forgetting is silent: the
  person is signed in and nothing says so.
- **One line per fact that changed, never one per request**, and only when the action actually
  happened. A patch moving both a tier and a status writes two lines; one moving neither writes none;
  a sign-out for a session that had already ended writes none. An access review reads for one fact at
  a time, and a line per request fills it with rows saying nothing.
- **Changing what proves an account asks for the credential again; nothing else here does.** Holding
  a session is not the same as having proved you own it, and attaching an identity outlives the
  session that attached it — afterwards whoever holds that provider account signs in as this one.
  Detaching carries the same gate, because it is the half that locks somebody out. Signing in counts
  as proving it, stamped at the one mint site, and a proof dies with its session.
- **Attaching and detaching ship together or not at all.** Signing in again with a provider you just
  detached does not give the account back: nothing claims that handle, so it provisions a second
  account and the person is a stranger on it.
- **The link callback is a different address from the sign-in one.** One mints a session for whoever
  comes back; the other attaches whoever comes back to an account already signed in. One address for
  both lets a link return through the sign-in door and mint a session instead. Both have to be
  registered against the provider's application, or the bounce is refused where no log here sees it.
- **Freshness is checked when a link STARTS, never on the way back.** The bounce takes as long as it
  takes, and re-checking fails a link somebody legitimately began while adding nothing — the ticket is
  already one-use, short-lived and unforgeable.
- **Sessions are listed and ended HERE, because they exist only here.** A member verifies a cluster
  session offline against a published key and stores nothing, so a member asked what devices an
  account holds answers honestly with none — an empty card rather than a wrong question. They are
  looked up under **every credential handle the account holds**: a session is keyed by the handle
  somebody arrived with, so one account signed in with a password and with Discord has two keys.
  Ending one is never gated on holding the capability, for the same reason sign-out is not.
- **The session registry is the anchor's own, on its own file.** `Auth.Sessions` deliberately ships
  no default store, and sessions are not accounts: a member replicating the cluster's accounts
  replicates none of the sign-ins.

## Conventions

- Namespace `TheKrystalShip.KGSM.Auth`; package id matches. The daemon is
  `TheKrystalShip.KGSM.Auth.Anchor`, and its binary and unit are `kgsm-auth-anchor`.
- Doc comments say what the code does now and why that rule exists — never what it replaced.

## Version tracking

Each package versions on its own clock, and the daemon on one of its own. `deploy/version.sh` reads
the daemon's, because that is the one the pacman package ships.

**Tags carry the prefix of the thing they version**, since one repo's commits move several numbers:
`auth-v*`, `sessions-v*`, `users-v*`, `discord-v*`, `journal-v*` for the packages, and a bare `v*`
for the daemon.
Only the bare `v*` fires the release workflow, which asserts the tag against `deploy/version.sh` — so
a package tag can never publish a pacman package by accident.

- **Version source:** `<Version>` in `src/Auth/Auth.csproj`.
- Bump on any user-facing change; patch for fixes, minor for additions, major for a breaking change.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Consumers pin a version from the org's GitHub Packages feed, so shipping a change means **bump the
  version, publish, then bump the pin** — `../scripts/publish-packages.sh kgsm-auth`. A published
  version is immutable, so there is no same-version republish to get wrong.

## Gotchas

- A change to how a tier is resolved changes live authority on four running surfaces at once. The
  tests in `tests/Auth.Users.Tests/` are the specification — extend them before the code.
- The package is referenced by projects in three other repos. Build those before declaring work done.

## Documentation & comments: present-tense canon only

Prose in this repo — every doc, `README`/`CLAUDE.md` section, and in-code comment — describes
**how the thing works right now**, nothing else. History lives in the `CHANGELOG` and git
history; never duplicate it into docs or code.

- **No transitions.** Never "was X, now Y", "used to…", "changed from…", "no longer…", or any
  before/after framing. State the current rule flat: a sentence that only makes sense to a reader
  who knows what the code *used to* do is dead weight, because that "before" no longer exists
  anywhere in the code.
- **Tombstones leave no marker.** When something is removed — dying naturally as part of the work,
  or explicitly asked to be deleted — the removal is silent: no *"removed X"*, no *"X is gone"*,
  no *"deprecated, use Y instead"* pointing at a corpse. The prose reads as if it never was. Code
  kept while the thing that justified it was deleted gets a live present-tense reason to exist —
  or goes too.
- **No residue of the active work.** References only meaningful *during* a piece of work don't
  survive it: *"temporary shim for the rework"*, *"added to satisfy the new requirement"*,
  milestone/phase labels (*"per M2"*, *"the Phase 1 step"*). If a line's justification is the work
  that produced it rather than the system as it now stands, it goes.
- **No volatile numbers.** Counts and versions that drift — how many projects/files/tests/
  partials exist, a dependency's pinned version, a file's line count — never go in prose: they are
  stale the moment anything changes, and nothing fails to remind anyone. Name the authoritative
  source instead (the csproj, the directory, the barrel file). A number belongs in prose only when
  it *is* the contract (a port, a timeout, a cap) or a measured fact that is itself the reason a
  design exists.
- **Edits are replacements, not appends.** When changing an existing feature, rewrite the affected
  doc/comment fresh as if writing it for the first time — never append a correction under the
  stale version, and never leave the stale version standing beside the new. The current revision
  does not converse with prior revisions.

A reader six months from now should learn the system from the doc without knowing what it
replaced. If you catch yourself explaining a change, stop — that sentence belongs in the commit
message. When touching prose that already violates this, rewrite it to present-tense canon in
passing.
