# `Auth.Access` — locked decisions

The access model and the one function that answers every access question. Design authority:
`kgsm-docs/plans/permissions.md`. The tests in `tests/Auth.Access.Tests/` are the specification —
extend them before the code.

- **ZERO package dependencies, AOT-safe, and it reads no file.** Every member evaluates with this,
  including Native AOT leaves checking their own service accounts. A snapshot is built by whoever
  holds the data — `Auth.Users`' `SqliteAuthorityStore` on the anchor and on a replica — and handed
  in. `IsAotCompatible` and the trim analyzer are on and must stay green.
- **`AccessEvaluator` asks its questions in one order, and the order is the contract**: account
  status, staleness (reads only, Owners included), Owner, self actions, the union of grants, and the
  author of an automation. Do not reorder them, and do not add a step that denies: access is only ever
  added, so "why may Alice do this" is always a list of grants.
- **The target is widened to the action's scope kind before matching.** That single step is what
  keeps an assignment at a narrower scope from granting a wider-kind action. Never match an
  assignment against the raw target.
- **Every wire parse fails closed.** An unknown scope kind reads as `cluster` (only a cluster-wide
  grant reaches it), an unknown effect as `write` (a stale member refuses it), an unknown role kind as
  `custom`, an unknown requirement state as `revoked`, a malformed scope as no scope at all. Never add a
  permissive fallback.
- **An action the snapshot does not know is an Owner's alone.** A newer build's action has no effect
  anybody vouched for and no permission anybody filed it into.
- **`AuthorityRules` is pure and is the only place the administration rules live.** Subset, ranking,
  the permission-edit rule, Owner-only and the last active Owner are decided there, against a snapshot,
  and the store applies a change only after `Check` returns null in the same transaction. A caller that
  checks some rule itself instead is a second implementation that will drift.
- **An Owner's exemption is evaluated, never read off an assignment.** A disabled Owner, or one on a
  stale replica, is exempt from nothing.
- **Owner is held by people, at cluster scope, and only an Owner grants, revokes or acts on it.**
  `everyone` is never assigned. Service accounts hold no `everyone` and no self actions, and their
  requirements grant only while approved and still declared.
- **The catalog is a union, and the order reports arrive in never changes it.** `CatalogUnion` records
  every member and version declaring an action, and takes the wording from the highest version, then
  the member id that sorts first. A member's report carries a sequence because the bus does not order
  delivery.
- **Names are compared through `AuthorityRules.NameKey`** — trimmed, lower-case — everywhere a role or
  permission name is checked for uniqueness, including the store's `name_key` column.
