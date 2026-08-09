# CLAUDE.md — kgsm-auth

Guidance for Claude Code working in **kgsm-auth**. Read `README.md` for the model itself; this file is
the "what you must not break".

## What this is

The shared authorization model for the ecosystem. `TheKrystalShip.KGSM.Auth` is consumed by kgsm-api,
kgsm-llm and kgsm-bot, so a change here changes who can do what on every surface at once.

**Identity and authority are two seams, not one.** `IIdentityProvider` answers *who is this* (the
OAuth bounce and the code exchange); `IAuthorityProvider` answers *what may they do* (the tier);
`ISignInService`/`SignInService` composes them into one login. Discord implements both, and that is
the only pair wired today — but a host can replace either half alone, which is the entire point of
their being separate. Nothing above the seams names a provider.

**KGSM owns the accounts.** `Auth.Users` holds them in one file per host: a local account exists on
its own with a password, and an external identity is a credential attached to it. So the two seams
have two different sources — a provider verifies who someone is, and the account store alone says
what they may do.

Authority for the wider effort: **`../auth-unification-plan.md`** and
**`../auth-internal-users-plan.md`**.

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
  is how the surfaces diverged in the first place.
- **`null` ≠ empty in `Resolve`.** `null` is *not a member of the guild* (a terminal denial); an empty
  collection is *a member holding only `@everyone`* (the viewer floor). Collapsing them either locks
  out every plain member or lets a failed lookup through as a grant.
- **A failed role lookup is never passed in as empty.** The caller reports the failure and denies. This
  is the security analog of the ecosystem's never-fabricate-a-status rule: authorize on measured
  membership and roles, or deny.
- **Parsing is fail-closed.** `KgsmTiers.Parse` maps anything unrecognised — absent, misspelled, or a
  tier invented by a newer peer — to `None`. Never add a permissive fallback.
- **No viewer role list.** Guild membership already grants viewer, so a list of ids granting it would
  grant what everyone has. Do not reintroduce one for symmetry.
- **`ResolveSnowflakes` is named apart from `Resolve` deliberately.** As an overload, an empty
  collection expression binds to neither and fails to compile at every call site passing one.

## `Auth.Discord` — locked decisions

- **It implements both seams; nothing else may.** `DiscordDirectory` is `IIdentityProvider` +
  `IAuthorityProvider`, and it stays the only chokepoint to `discord.com`. `DiscordAuthException`
  derives from `KgsmAuthProviderException` so a caller handles any provider's outage identically.
- **Register it transient, and resolve it once per composition.** It is a typed `HttpClient`; holding
  one in a singleton pins a handler for the process lifetime and silently stops the factory rotating
  it, so DNS changes never land. The composition resolves the client once and hands the same instance
  to both halves, so one sign-in uses one client.

- **The three lookup answers stay three answers.** `404` (not a member) ⇒ `null`, a member with no
  roles ⇒ empty, and a failed lookup ⇒ `DiscordAuthException`. Never collapse the third into either of
  the others: an outage read as "no roles" demotes an admin mid-incident, and read as "member" lets a
  stranger in.
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
  it is handed. A Discord login still produces the subject `discord:<id>` exactly as it always has —
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
- **A store that cannot be read throws, and never resolves to `None`.** Same rule as a failed Discord
  role lookup: "we could not ask" is not "the answer is no".
- **Lockout is exponential from a threshold, never a hard cap.** A hard cap hands anyone who knows a
  username a denial of service against its owner. The policy is a value applied inside the same
  transaction that records the failure, so the count and the lock it implies cannot disagree.
- **`PasswordHasher<T>` from `Microsoft.Extensions.Identity.Core`, behind `IUserPasswordHasher`.**
  Do not hand-roll, and do not reach for `UserManager`/EF Identity — this package owns its own schema
  and its own store. The seam plus the rehash-on-upgrade path is what lets the format be replaced
  later with no forced reset.
- **No SMTP, and no password reset by email.** A mail dependency in the package whose purpose is
  removing outside dependencies would be self-defeating. Resets are admin-initiated.

## Conventions

- Namespace `TheKrystalShip.KGSM.Auth`; package id matches.
- Role ids are Discord snowflakes held as **strings**, compared **ordinally**. Discord's member object
  carries them as strings, so comparing as strings never risks a parse.
- Doc comments say what the code does now and why that rule exists — never what it replaced.

## Version tracking

- **Version source:** `<Version>` in `src/Auth/Auth.csproj`.
- Bump on any user-facing change; patch for fixes, minor for additions, major for a breaking change.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Consumers pin a version from `/home/heisen/local-nuget`, so shipping a change means **repack + bump
  on both sides** — a same-version repack is served stale from the NuGet cache (keyed by id+version).

## Gotchas

- A change to the resolve matrix changes live authority on a running guild. The tests in
  `tests/Auth.Tests/KgsmRoleMapTests.cs` are the specification — extend them before the code.
- The package is referenced by projects in three other repos. Build those before declaring work done.
