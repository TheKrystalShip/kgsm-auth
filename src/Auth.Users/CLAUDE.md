# `Auth.Users` — locked decisions

The account store: one file per host, holding the accounts and the authority over them. The tests in
`tests/Auth.Users.Tests/` are the specification — extend them before the code.

- **The account is the primary object; a credential only identifies.** A `KgsmUser` exists on its
  own. A password, a Discord subject and a GitHub subject are all just credentials attached to one.
  What an account may do is the roles assigned to it in the same file, and nothing outside the account
  contributes to that — which is what lets a provider be added with no access story of its own, and it
  is the rule to check any change here against.
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
- **The store fails closed on every parse**: an unrecognised
  status reads as `disabled`, an unrecognised origin as `arrived`, an unrecognised credential
  kind as `identity`. Enums are stored as words, never ordinals, so reordering one cannot silently
  repoint every row.
- **A store that cannot be read throws, and never resolves to "no account".** "We could not ask" is
  not "the answer is no".
- **Lockout is exponential from a threshold, never a hard cap.** A hard cap hands anyone who knows a
  username a denial of service against its owner. The policy is a value applied inside the same
  transaction that records the failure, so the count and the lock it implies cannot disagree.
- **`PasswordHasher<T>` from `Microsoft.Extensions.Identity.Core`, behind `IUserPasswordHasher`.**
  Do not hand-roll, and do not reach for `UserManager`/EF Identity — this package owns its own schema
  and its own store. The seam plus the rehash-on-upgrade path is what lets the format be replaced
  with no forced reset.
- **No SMTP, and no password reset by email.** A mail dependency in the package whose purpose is
  removing outside dependencies would be self-defeating. A reset is set by somebody holding
  `auth:accounts.create`.
- **An external provider proves you are an account this host already has and contributes nothing
  else.** Neither does a password: `LocalSignInService` answers who, and access is evaluated wherever a
  request is decided.
- **Three answers about an account.** `AccountResolver.ResolveAsync` reports *usable*, *no account*
  and *disabled* separately, because only the third is a reason to end a live session and the first
  covers a pending account (which authenticates holding nothing). Its cache TTL is how long a switched-off
  account is still found usable; a read failure throws and is never cached, or a moment of
  unavailability becomes a full-TTL lockout.
- **Linking is scoped to an account, and the last credential is refused.** `UnlinkAsync` takes the
  account as well as the credential id, because the id is the whole of what a caller supplies and an
  unscoped one copied from elsewhere would detach a stranger's identity — "not yours" and "not real"
  are one answer for the same reason. An account with nothing attached is one its own holder cannot
  sign in to, so the rule lives here rather than in each caller; the store itself refuses nothing and
  only reports what happened.
- **An arriving identity is provisioned unapproved, never auto-linked.** `IdentityLinkService` creates
  a `Pending` account for a subject nobody has claimed. It never matches on an email or a
  username: providers disagree about what "verified" means, and matching on one is a documented
  account-takeover route. Provisioning is reachable by anyone who can complete a login at a configured
  provider, so `PendingPolicy` caps it and expires what nobody looks at — and expiry only ever removes
  an account that arrived on its own and is still unapproved. The origin is what it reads, not whether
  a password is set: an account somebody created or approved carries `AccountOrigin.Admitted` and is
  spared however long it waits, while a self-registered one holds a password and must still expire,
  or the cap fills with a queue nobody can drain.
- **A store with no accounts gets one account, the Owner, and `FirstAdmin` is where that lives:** what
  the first account is called, what the one-time password file holds and when it is removed. It
  reports failures rather than logging them: this package holds no logger and should not, or every
  surface that opens a store takes one too.
- **A password is at least `Passwords.MinLength` characters, and length is the whole rule.** Every
  door that sets one — registration, a reset on somebody's behalf, a holder changing their own — reads the same
  constant, because a floor checked in three callers is three places for it to drift low.

## Schema version 2 — the access model

- **One reader, `SqliteAuthorityStore`, for version 2.** Accounts carry `origin` and `kind`, and the
  file also holds permissions, roles, assignments, service accounts, requirements, the catalog, member
  reports and the authority version. A file at any other version is refused.
- **`SqliteAuthorityStore` is the account store too.** It implements `IUserStore` for person accounts,
  so sign-in, provisioning and linking read it. Every account write goes through the authority's write
  path — versioned, owed to the cluster — and a failed sign-in or a touched credential is bookkeeping
  that moves no version.
- **Every authority write is checked and applied in one immediate transaction.** The snapshot
  `AuthorityRules` judges is loaded under the write lock, so no second writer moves the state between
  the check and the change. A write names the version it was made against and is refused with
  `StaleAuthorityException` when the store has moved past it.
- **A cascade is reported one change at a time.** Foreign keys delete a role's assignments, an
  account's assignments and requirements, and a permission's links — and the store reads each of those
  first and reports it, so the journal carries every assignment that ended.
- **The system's writes bypass the rules and are never reachable from a request**: the catalog,
  service accounts and their declared requirements, and Owner granted from the host's shell.
- **A service account's username is `<component>@<member>`**, which `Usernames` never accepts from a
  person, so no person can register a service's name.
- **Bookkeeping is not authority.** A member's stored report is written with `Writer.Record`, which
  commits without advancing the authority version; only a change to who may do what (`Writer.Execute`)
  advances it. Every member re-reports on an interval, and a version that moved on each of those would
  have every replica re-apply a catalog that did not change. A report identical in effect to the last
  one writes no authority row at all, and a report older than the one held (by its sequence) is ignored.
- **The catalog is the union of stored reports, recomputed on every report and every removal.** A
  member that is merely offline keeps its report; only `ForgetMemberAsync` — the member removed from the
  cluster — drops one.
- **Every write owes the cluster what it changed, in the same transaction.** `WriteAsync` files each
  record stamped with the write's version, and each one it reported removed, in `authority_outbox`
  before it commits. A new write path needs nothing more than stamping `version = $v` on what it
  touches; a row it changes without stamping is a change no replica ever hears about.
- **A replica applies each record whole, on its own version, in any order.** The version held for a
  record is its row's or its tombstone's, whichever is higher, and anything not newer is dropped. A
  replica writes with foreign keys off, on an unpooled connection, because the bus does not order
  delivery: a record naming one not yet here grants nothing until it arrives. A unique name or handle
  still held by another record defers the change for the bus to deliver again, never resolves it.
- **A replica is current only as its last confirmation says.** A heartbeat confirms only a replica
  holding its version, as of when it was sent; a snapshot confirms as of when it was taken. The
  generation, advanced by every write and every applied change, is what `AuthoritySource` caches
  against — there is no time-to-live.
- **A requirement a person decided stays as they left it.** Only one the account has never held is
  approved automatically; one the manifest stops listing is kept with `declared = 0` and grants nothing
  until listed again.

The account-store design is also covered by `../auth-internal-users-plan.md` at the workspace root.
