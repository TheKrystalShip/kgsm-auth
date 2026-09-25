# `Auth.Users` — locked decisions

The account store: one file per host, the only production `IAuthorityProvider`. The tests in
`tests/Auth.Users.Tests/` are the specification — extend them before the code.

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
  with no forced reset.
- **No SMTP, and no password reset by email.** A mail dependency in the package whose purpose is
  removing outside dependencies would be self-defeating. Resets are admin-initiated.
- **The store is the only production `IAuthorityProvider`.** An external provider proves you are an
  account this host already has and contributes nothing else.
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
- **A store with no accounts gets one administrator, and `FirstAdmin` is where that lives.** Both a
  host's API and a cluster's anchor open account stores, and both must agree on what the first account
  is called, what the one-time password file holds and when it is removed — so there is one
  implementation and whichever opens an empty store first wins. It reports failures rather than
  logging them: this package holds no logger and should not, or every surface that opens a store takes
  one too.
- **A password is at least `Passwords.MinLength` characters, and length is the whole rule.** Every
  door that sets one — registration, an admin reset, a holder changing their own — reads the same
  constant, because a floor checked in three callers is three places for it to drift low.

The account-store design is also covered by `../auth-internal-users-plan.md` at the workspace root.
