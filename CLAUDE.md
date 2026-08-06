# CLAUDE.md — kgsm-auth

Guidance for Claude Code working in **kgsm-auth**. Read `README.md` for the model itself; this file is
the "what you must not break".

## What this is

The shared authorization model for the ecosystem. `TheKrystalShip.KGSM.Auth` is consumed by kgsm-api,
kgsm-llm and kgsm-bot, so a change here changes who can do what on every surface at once.

Authority for the wider effort: **`../auth-unification-plan.md`**.

## Locked decisions (do not relitigate)

- **`TheKrystalShip.KGSM.Auth` has ZERO package dependencies and stays AOT-safe.** Every surface takes
  it, including the footprint-tuned bot deploy and the CLI. No `HttpClient`, no configuration binder,
  no ORM, no logging abstraction. `IsAotCompatible` and the trim analyzer are on and must stay green.
  Anything needing I/O belongs in a sibling package that only its consumers take.
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

- **The three lookup answers stay three answers.** `404` (not a member) ⇒ `null`, a member with no
  roles ⇒ empty, and a failed lookup ⇒ `DiscordAuthException`. Never collapse the third into either of
  the others: an outage read as "no roles" demotes an admin mid-incident, and read as "member" lets a
  stranger in.
- **`state` and PKCE ride one cookie and neither is optional.** `state` stops login CSRF and only
  works because the cookie binds it to the browser that started the login; a server-side set of issued
  states admits the attacker's own state. PKCE stops code interception. Do not "simplify" either away.
- **`SameSite=Lax`, never `Strict`.** Strict suppresses the cookie on the top-level redirect back from
  Discord, which breaks every login.
- **No web framework dependency.** The package hands the host a cookie *value*; the host writes the
  cookie. Taking a dependency on ASP.NET to save three lines would put it in every consumer and make
  the handshake untestable without standing up a server.

## `Auth.Sessions` — locked decisions

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
