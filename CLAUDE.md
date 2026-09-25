# CLAUDE.md — kgsm-auth

Guidance for Claude Code working in **kgsm-auth**. Read `README.md` for the model itself; this file is
the "what you must not break".

## What this is

The shared authorization model for the ecosystem, and the cluster's sign-in provider. The packages are
consumed by kgsm-api, kgsm-llm, kgsm-bot and kgsm-dns, so a change here changes who can do what on
every surface at once.

**The packages match the roles.** The anchor is the provider: it mints every session, and minting,
the session registry, the Discord round trip and the OAuth handshake are its own code, published to no
feed. Every other component is a resource server and takes `Auth.Cluster`, which verifies and reads a
session and cannot produce one. `Auth.Testing` compiles the anchor's minter for test projects, so a
test presents exactly the session the anchor would mint; no production project references it.

**Identity and authority are two seams, not one.** The anchor's `IIdentityProvider` answers *who is
this* (the OAuth bounce and the code exchange); `IAuthorityProvider` answers *what may they do* (the
tier). An identity provider answers the first, and `Auth.Users` answers the second for everyone,
however they signed in. **`IAuthorityProvider` has exactly one implementation that ships: the account
store.** A provider implements the identity half and nothing else, which is what lets one be added
with no authority story of its own.

**KGSM owns the accounts.** `Auth.Users` holds them in one file per host: a local account exists on
its own with a password, and an external identity is a credential attached to it.

**The repo also holds one deployable.** `src/Auth.Anchor` builds `kgsm-auth-anchor`, the cluster
member that holds the accounts and signs people in to the whole cluster at once. It is built from
these libraries by project reference, so a change to a library is a compile break here before it is
anything else.

**The access model that replaces the tiers is `Auth.Access`** — actions declared by components,
permissions, ranked roles, assignments scoped to the cluster, a node or an instance, and service
accounts — with its authority `kgsm-docs/plans/permissions.md`. The account store holds it at schema
version 2 (`SqliteAuthorityStore`), and `UserStoreUpgrade` brings a version 1 file there. Every surface
enforces the tiers until that plan's cutover.

**Each package's locked decisions live in a `CLAUDE.md` beside it**: `src/Auth.Access/`,
`src/Auth.Users/`, `src/Auth.Journal/`, `src/Auth.Cluster/`, `src/Auth.Anchor/` (the daemon, the Discord
round trip, the OIDC provider) and `src/Auth.Anchor/Minting/`. This repo is the authority for the auth design; the
account-store design is also covered by `../auth-internal-users-plan.md`, and the anchor's by
`../cluster-auth-plan.md`.

## Locked decisions for the model (do not relitigate)

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
- **No surface derives authority from a group, a guild or a role.** An OAuth application carries the
  application and nothing else; the account store is the single authority on what anyone may do,
  including for kgsm-bot, whose caller is a Discord account with no login behind it. Do not add a role
  map: an authority source that lives outside the account lets surfaces disagree about one person.
- **Parsing is fail-closed.** `KgsmTiers.Parse` maps anything unrecognised — absent, misspelled, or a
  tier invented by a newer peer — to `None`. Never add a permissive fallback.
- **A provider is a key, never a property.** The anchor reads `KgsmAuth:Providers:<name>:ClientId`
  and `ClientSecret`, so wiring it to a new provider is a pair of environment keys and no code. Do not
  add a per-provider setting beside that pattern: an asymmetry there is how one provider ends up with
  a sign-in path the others do not have. An unwired provider and an unknown one are one answer — not
  offered — so no caller writes an existence check that could disagree with the configured check.

## Conventions

- Namespace `TheKrystalShip.KGSM.Auth`; package id matches. The daemon is
  `TheKrystalShip.KGSM.Auth.Anchor`, and its binary and unit are `kgsm-auth-anchor`.

## Version tracking

Each package versions on its own clock, and the daemon on one of its own. `deploy/version.sh` reads
the daemon's, because that is the one the pacman package ships.

**Tags carry the prefix of the thing they version**, since one repo's commits move several numbers:
`auth-v*`, `access-v*`, `users-v*`, `journal-v*`, `cluster-v*`, `testing-v*` for the packages, and a bare `v*` for
the daemon. Only the bare `v*` fires the release workflow, which asserts the tag against
`deploy/version.sh` — so a package tag can never publish a pacman package by accident.

- **Version source:** each package's `<Version>` in its own csproj; the daemon's in
  `src/Auth.Anchor/Anchor.csproj`.
- Bump on any user-facing change; patch for fixes, minor for additions, major for a breaking change,
  with a `CHANGELOG.md` entry under `## [Unreleased]`.
- Consumers pin a version from the org's GitHub Packages feed, so shipping a change means **bump the
  version, publish, then bump the pin** — `../scripts/publish-packages.sh kgsm-auth`.

## Gotchas

- A change to how a tier is resolved changes live authority on four running surfaces at once. The
  tests in `tests/Auth.Users.Tests/` are the specification — extend them before the code.
- The packages are referenced by projects in four other repos — kgsm-api, kgsm-llm, kgsm-bot and
  kgsm-dns. Build those before declaring work done.
