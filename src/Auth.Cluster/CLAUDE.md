# `Auth.Cluster` — locked decisions

What a **member** or a **leaf** does about identity, as opposed to what the anchor does. The anchor
holds the accounts and mints the sessions; everybody else verifies, resolves and applies. That half
runs on kgsm-api, the assistant, the bot and the DNS anchor, so it is one package rather than one
implementation each.

- **A member verifies what it cannot mint.** `ClusterSessionValidation.Accepting` takes the anchor's
  published keys, audience and issuer and pins ES256. The key set a member holds is public points
  (`SessionKeys`), so a verifier built from it cannot sign, and a public key offered as an HMAC secret
  is refused before its signature is looked at. `ClockSkew` is the one tolerance, shared with the mint.
- **A published fact is read through the capability's holder, never off whichever member states it.**
  `ClusterFacts.FromHolderAsync`, for the keys, the audience and the issuer alike. A key taken from any
  member would let any member substitute the one sessions are verified against.
- **Knowing nothing fails closed.** A member with no cluster, or one that has not heard who holds the
  accounts, accepts no cluster session at all. Guessing would accept a token minted for a different
  cluster.
- **Who holds the accounts is read from cluster state, not from a setting.** `AnchorHeldGate` reads
  the assignment, so an anchor joining or being reassigned needs no reconfiguration anywhere.
- **The origins a member admits are the provider's registered clients, read through the holder.**
  `IClientOrigins`, implemented by `ClusterSessionKeys` from the `auth.origins` fact and by
  `HostSessionKeys` from the host file, so no member is configured with a list: registering a client at
  the provider is what admits it everywhere. A member answers them without credentials — a session is
  a bearer, and nothing a member serves reads a cookie.
- **An ended session is held to a deny-list.** A session is verified against a published key and
  needs no row to be accepted, so the one thing a member stores is that somebody ended it —
  `IClusterSessionDenyList`, filled by `SessionRevokeHandler` from `session.revoke` and read through
  `ClusterSessionRevocations`, whose cache an end evicts.
- **No handler throws.** A `500` is the only answer that keeps a message in the sender's outbox, so it
  is reserved for a transient failure. A stale change never becomes newer and a username conflict never
  resolves itself, so both are logged and acknowledged; throwing would wedge the sender's queue behind
  a message it can never deliver, taking every later account change with it, including a disable.
- **A leaf verifies what its machine's member verified, through the host file.** A leaf joins no
  cluster, so it cannot resolve the holder; the node writes `HostProviderFile` from its own read
  through the holder, and `HostSessionKeys` reads it back. One writer per machine, the node. The file
  is removed when the member has read the cluster and the holder states nothing — a file naming a
  cluster the machine has left would have its leaves accept that cluster's sessions — and left alone
  before the member's first read, so a restart costs no leaf its sessions.
- **The provider is named only when it is a URL.** `ProtectedResourceMetadata` answers with the
  issuer a member verifies against, or with `no_issuer`; a surface given a value it cannot navigate
  to would try to.
- **A member reports what it is responsible for from disk, and a leaf gains nothing from being
  reported.** `AuthorityReporter` reads the manifests a node's leaves installed and sends them to the
  holder of the accounts. It sends again on a change, on a new holder and on an interval, and a report
  replaces the last one, so sending twice is always safe. A member that holds the accounts itself hands
  the report to its own `IAuthorityIntake` rather than across the bus to itself. A manifest that cannot
  be read is left out and logged: a component shipping no readable manifest declares nothing.
- **The authority is taken from the holder of the accounts and nobody else.** Every handler
  `AddAuthorityReplica` registers drops a message from any other member, and throws only for a deferral
  — a name another record holds until a message in flight moves it — which the sender's retry is what
  resolves. `AuthoritySnapshotWorker` takes the whole state on joining and whenever the replica has gone
  stale; the stream alone carries only changes.
- **A member acts as a service account only when that account is its own.** `MemberActingAccountResolver`
  accepts `svc:<component>@<member>` from `<member>` alone, and like every member-acting call it asserts
  who, never what: the receiver evaluates the account from its own replica.
- **A member answers for a person from its own replica, and says so when it cannot.** `MemberAccess`
  reads nothing about access off a token; `AuthorityReplicaFile` opens the member's account store only
  once it is at schema version 2 and never creates it, and until then every answer is
  `authority_unavailable` — an outage, never a denial.
- **Two seams, and the package owns neither:** `IReplicatedAuthority` is the member's authority
  replica — accounts and who may do what in one file — and `IClusterSessionDenyList` its own record of
  ended sessions. Opening a file and serving a route stay the member's business.
