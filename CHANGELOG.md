# Changelog

All notable changes to `kgsm-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — deciding a member-acting call, once for every member (`Auth.Cluster 1.0.0-dev.5`)

`MemberActingResolver` decides one member calling another for somebody who is not signed in to it:
validate the caller's service token, refuse a member the roster has disabled, parse the
`provider:subject` handle, and resolve it against this member's own replica of the cluster's accounts.
A person this member has never heard of is refused rather than provisioned, which is exactly what a
username collision looks like from the far end; an unreadable store refuses and says so, because an
outage is never a denial.

**The caller asserts who, never what.** No tier crosses the wire in either direction — the tier comes
from the replica on every call. What a compromised member could do is act as somebody it names, bounded
by what that person actually holds, which is narrower than a shared secret that forwards an authority
along with an identity.

A refusal carries a typed reason as well as a message, because they do not all mean the same thing to
whoever reads a log: `NoSuchAccount` is what a username collision looks like from the far end — a person
who exists in the cluster and resolves to nobody here, with everything else healthy — and it has to be
findable, while a token that failed to validate is ordinary noise. A surface matching on message text to
tell them apart would break on a reworded sentence. The acting member is named as soon as its token
validates, refusal or not, so a member can report *who* asked for something it would not do.

It decides and returns: it reads no request and writes no response. How the handle and the token were
carried, and what a refusal looks like on the wire, belong to the surface — every one of which has its
own error envelope already, and one shape imposed on all of them is a second wire contract kept in step
for no reader. A member supplies its own accounts through `IMemberAccounts`, so this opens no file.

The header spellings themselves are `TheKrystalShip.KGSM.Cluster`'s: a surface that only ever *sends* an
acting handle needs the spelling and nothing about accounts at all, and making it take the account stack
for a string constant is the coupling this split exists to avoid.


### Fixed — an account change and the announcement owed for it are one write (`1.17.0`)

The change was applied to the accounts and the announcement enqueued onto the cluster bus afterwards,
in a different database. A crash in the gap left a member changed and the cluster never told — the
change was not lost, only the telling of it, and nothing detected that. A member repaired it by taking
a snapshot, which it does when it joins and never again.

`account_announcements` lives in the accounts' own file and is written **in the same transaction as
the version that orders the change**, so a change cannot exist at a version with nothing owed for it.
That is the only place such a table can be: two databases cannot be made atomic however carefully the
writes are sequenced.

`AccountBroadcast` drains what is recorded rather than announcing what it was handed, and deletes a
row only once the bus has taken the message — so a crash between the two costs a redelivery, which
every replica drops as stale, rather than a change nobody hears about. A write path still drains
immediately, so the cluster hears within the moment; `AccountBroadcastWorker` drains at startup and on
a timer, so nothing depends on that having happened.

Pending announcements collapse to the highest version per account, because an announcement carries the
account's whole current state — sending an older one first would put the current state on the wire
under an earlier version's name — and a removal supersedes a change it followed.

Like `account_versions`, a table older builds have never heard of, so `UserSchema.Version` does not
move and no surface reading the shared account store is refused.

### Added — the journal is followed, not just read (`1.16.0`)

`GET /auth/logs/stream`, server-sent events, admin. The REST read is the scrollback and this carries
lines from the next one on, so a viewer sees its own journal the way every other log console in the
ecosystem is seen — live, with nothing to press.

**One `journalctl -f` for however many people are watching.** The first subscriber starts it and the
last one to leave kills it, so an unwatched page costs nothing and three browsers are not three
processes reading one journal. Each watcher has a bounded queue that drops its oldest when full: one
browser on a bad connection cannot stall the follow for the rest, and the journal on disk is the
durable record a reconnect re-reads.

`fetch`-read rather than `EventSource` on the client's side, for the reason every authenticated
stream here is: `EventSource` sends no `Authorization` header, and a daemon holding the cluster's
accounts does not take its token in a query string.

### Added — `TheKrystalShip.KGSM.Auth.Cluster`, what a member does about identity

Every member of a cluster verifies a session the anchor minted, resolves the person from its own
replica, refuses the auth doors that belong to whichever member holds the accounts, and applies what
the bus delivers about both. All of it existed once, inside kgsm-api, where the assistant and the bot
could not reach it — and two surfaces answering "who is this" differently is the one disagreement
identity cannot survive.

- `AnchorHeldGate` reads who holds the `auth` capability from cluster state, so a member closes its
  own doors when an anchor joins and opens them when one is reassigned, with nothing reconfigured.
  `AnchorHeld` names the refusal's code and header once; the response body stays each surface's, which
  already has its own error envelope.
- `ClusterSessionKeys` follows the anchor's published keys, audience and issuer **through the holder**
  of the capability, so a member that states a key for accounts it does not hold is never consulted.
- `ClusterSessionRevocations` over `IClusterSessionDenyList` — the deny-list a session nobody here
  minted is held to, cached on the request path and evicted by an arriving revoke.
- `SessionRevokeHandler` ends both kinds of session without having to know which it was handed. Its
  `user` scope names a person by handle, and reads a bare Discord id as the Discord identity it is.
- `AccountReplicationHandler`, `AccountRemovalHandler` and `AccountSnapshotWorker` — the stream and the
  first full copy, applied through `AccountReplica` so every member reads the rules identically.

A member supplies three seams: `IReplicatedAccounts` for its own store, `IClusterSessionAuthority` for
its own sessions, and `ISessionValidator` as before. Nothing here opens a file or serves a route.

### Added — the anchor's journal, live (`1.16.0`)

`GET /auth/logs/stream`, admin, server-sent events. The read above is the scrollback and this carries
lines from the next one on, so nothing arrives twice on an attach. Read with `fetch` rather than
`EventSource`, because that sends no `Authorization` header and a daemon holding the cluster's
accounts does not take its token in a query string.

**One `journalctl -f` however many people are watching** — the first subscriber starts it, the last
one to leave stops it, and an unwatched page costs nothing. A slow viewer drops its own oldest lines
rather than stalling the follow for everyone else; the journal on disk is the durable record, and a
reconnect re-reads it.

An idle journal and a dropped connection look identical on screen, so the stream opens with a comment
line and heartbeats every 20 seconds: the first is what makes a proxy release the response, and the
rest are what let a viewer show a tail that has stopped as stopped.

### Fixed — the test suite read the live host (`1.16.0`)

`ConfigDescriptorPath` and `ConfigOverridePath` are the two absolute defaults the anchor fixture left
alone, so a run read the descriptor the deployed daemon carries — naming the live unit, and following
its journal. A suite that passes only on a host where the thing under test is already installed is
measuring the host.

### Added — the anchor serves its own journal (`1.15.0`)

`GET /auth/logs?lines=N`, admin, in the shape every KGSM log surface renders — so an anchor's journal
and a leaf's are read through one component in the panel. A node's journal is read by the API running
on that node; an anchor has no node above it, which is the same reason it serves its own
configuration.

The unit it reads is the descriptor's, not a second setting. It carries
`SupplementaryGroups=systemd-journal`, without which `journalctl` exits 0 having printed nothing — a
success indistinguishable from a unit that has logged nothing. An unreadable journal answers 503 and
an empty one answers an empty list, because those are different facts.

### Added — the anchor serves its own configuration surface (`1.14.0`)

`GET /auth/config` and `PUT /auth/config`, admin, on the origin a panel already reaches this daemon
at. Nothing else could offer them: a leaf is configured through the node that runs it, and an anchor
is a peer of every node rather than something one of them hosts — on the ordinary topology there is
no node beside it to ask.

The surface is the descriptor this build generated, joined with what the host's deploy files set and
what an administrator has overridden, in three tiers that are reported separately because resetting a
key restores a different thing in each. Values are checked against the descriptor's own type, enum
and bounds — the same declarations `AnchorSettings` clamps to — so the panel cannot accept a value
this daemon would refuse or silently move. A change is written to `ConfigOverridePath`, fed back by a
systemd drop-in ordered after everything else the unit loads, and picked up by a restart.

**There is no canary and no rollback**, and that is the situation rather than a gap: the process that
would watch the restart and put the old values back is the process being restarted. So every value is
checked before anything is written, and the path to remove is logged before the bounce — deleting
that file returns every knob to what the deploy set.

The restart is queued with `systemctl restart --no-block`, which returns as soon as systemd owns the
job, so this process ending is the job proceeding rather than the job being lost. The answer is
written after, and reaches the caller because SIGTERM drains the requests already in flight — which
is what lets it carry whether the restart was accepted. A refusal means the change is written and is
NOT in force, and that is a different state from one being applied.

### Fixed — the browser refused every `PUT` to this anchor (`1.14.0`)

`PUT` was missing from the CORS allow-methods list, so a browser refused the preflight before the
request was made. There is no status code and no log line for that: it surfaces as an endpoint that
appears not to exist.

### Changed — the anchor is described in `/var/lib/kgsm/anchors/` (`1.13.0`)

It declares `[assembly: Anchor(...)]` and its descriptor is written as `.anchor.json`, which is what
routes it: a node's leaves live in `/var/lib/kgsm/leaves/` and nothing that administers a node's
services reads the anchors directory. This daemon serves one capability to the whole cluster and is a
peer of every node in it; sharing a machine with one is a deployment coincidence, and the ordinary
topology puts it on its own.

The generator refuses to write an anchor's descriptor to a `.leaf.json` path, so this cannot reach
the wrong directory without failing the build, and a deploy clears the file it left in the other
directory. Needs `TheKrystalShip.KGSM.ComponentConfig` 3.0.0, which is what the pin moves to.

### Changed — the anchor is a cluster member, not a node's leaf (`1.12.0`)

Its descriptor declares `anchor: true`, so kgsm-api leaves it off the service board of whatever node
it happens to share a machine with. It serves one capability to the whole cluster and is a peer of
every node in it; sharing a machine with one is a deployment coincidence, and the ordinary topology
puts it on its own. The Control Panel reaches it as the member it is — the anchor's own page, off the
cluster's Anchors card — and nowhere else.

The flag needs `TheKrystalShip.KGSM.LeafConfig` 2.3.0-dev.2, which is what the pin moves to.

### Fixed — a fresh anchor was a door nobody could open (`1.11.0`)

An anchor whose account store is empty creates the administrator `admin` and leaves a one-time
password in `initial-admin-password`, beside the session store. The file is removed the moment that
account signs in with a password, and only by that account: a host can grow other accounts from a
shell first, and somebody else's first sign-in must not tidy away a credential nobody has used.

**Without it there was no way in at all.** Registration is off unless a cluster turns it on, and an
account made through it holds `none` and waits for an approval only an administrator can give — so the
first person to arrive was stuck behind an account nobody existed to approve, and the only way through
was SQL against the account store.

It goes unnoticed wherever an anchor shares a machine with a Control Panel: they share one account
store and the panel bootstrapped it first. An anchor on a machine of its own — which nothing prevents,
and which is what a small cluster wants — starts with nothing.

**One implementation, not two.** `FirstAdmin` moved into `TheKrystalShip.KGSM.Auth.Users`, where the
accounts are, so a host's API and a cluster's anchor cannot disagree about what the first account is
called, what the file holds, or when it is removed. Whichever opens an empty store first creates the
account and the other finds accounts and does nothing.

### Changed — the account store still takes no logger (`TheKrystalShip.KGSM.Auth.Users` 1.4.0-dev.5)

`FirstAdmin` reports what happened and each surface words it: `TryWritePasswordFile` and
`TryConsumePasswordFile` hand back the failure instead of logging it. A caller that cannot write the
file says the password out loud in its own log rather than leaving a host with an administrator nobody
can be — and an account store that took a logger would take one into every surface that opens the
store.

### Added — what this is, and what the cluster contains (`1.10.0`)

`GET /auth/identity` and `GET /auth/cluster/members`. A panel deployed anywhere — a bucket, a static
host, a laptop — knows about no cluster until somebody types an address into it, and these are how it
finds out what it has been given.

**`/auth/identity` is unauthenticated**, because a caller with no session is exactly who is asking. It
names a kind, a cluster and a build, and says whether this anchor currently holds the accounts — a
second installation is a promotion candidate rather than a second authority, and answering otherwise
would send somebody to sign in at a door that refuses them. It exists because `/auth/providers`
answers on an anchor and on a standalone node alike, so that question cannot tell the two apart, and
guessing wrong sends somebody to sign in at a machine that does not hold their account.

It carries **no member and no address**. Knowing which machines exist is behind a session; an address
alone does not buy it.

**`/auth/cluster/members` is the only place a client learns what a cluster contains**, and it is
authenticated at the floor: any account may see the machines it might drive, and what it may then do
on each is that member's own answer per request. A member of a cluster tells nobody what cluster it is
in, so a panel signs in here and drives the roster it is handed rather than holding a list of its own
— which would be a second answer able to disagree with this one about which machines exist.

**Browser addresses, never peer-to-peer ones.** The roster carries both, and only the address a member
says a browser should use belongs in an answer to a browser: a secure page cannot fetch a plaintext
origin at all, so handing over the other registers a connection that can only ever read as down and
reports a healthy machine as broken. A member advertising no browser address is **left out** rather
than given its peer address — genuinely not drivable from a browser, and saying so by omission is
honest where an unusable address is a machine that appears present and never works.

Nodes and other anchors are both listed, with `kind`. A cluster holds more than one anchor as
capabilities are added and exactly one of them holds the accounts, so the kind is what lets a client
drive the others without ever trying to sign in against them.

### Fixed — a client could not add a header without every call failing (`1.9.3`)

`Access-Control-Allow-Headers` was a fixed `Authorization, Content-Type`. A browser states exactly
which headers it intends to send and refuses the request when the answer omits one — in the browser,
before anything reaches this daemon, so the caller sees a failed fetch with no status code and nothing
here logs it. A panel that attached one extra header had every account call, every identity call and
the whole devices surface die at the preflight while sign-in kept working, because sign-in went
through a client that sent neither.

The requested headers are reflected now, falling back to the ordinary two when a preflight names
none — reflecting nothing would answer with an empty allowance, which is a refusal spelled as a
permission. `Vary` covers `Access-Control-Request-Headers` as well as `Origin`, so a cache cannot
serve one client's allowance to another that asked for more.

Safe to reflect because the origin is already one this cluster configured: a page allowed to call at
all is allowed to say what it is sending, and the request is still authorized on its own merits.

### Fixed — a sign-out did not name the account it ended (`1.9.2`)

`auth.signed_out` carried a null `UserId` whenever the caller signed out with a refresh token, which
is what a browser does. The token holds the identity and not the account row, and nothing looked the
row up — so anyone filtering auth events by account got every sign-in and silently no sign-outs,
which reads as a person who never signed out rather than as a query that cannot answer.

The account is now looked up by the handle the token carries. It is a real query with a real answer
rather than a value derived from the handle, and the id is the durable key a trail joins on where the
username is renameable.

`Tier` stays null on a sign-out, deliberately. A tier belongs to the session as it was minted, and the
sign-in row this pairs with by `Sid` already carries it; on both rows the same field would mean two
different things — granted-at-mint and happened-to-hold-at-exit — which no reader can tell apart.

### Added — ending one of somebody else's sessions (`1.9.1`)

`POST /auth/cluster/users/{userId}/sessions/{sid}/revoke`, admin only.

Deliberately not the same fact as ending all of them. "This one session looks wrong" and "sign this
person out everywhere" are different decisions with different costs: the first ends a device without
disturbing somebody mid-task, and an admin left only the second reaches for it because it is what
exists.

The session is addressed **under the account it belongs to**, so the check is whether this sid is that
person's rather than whether it exists. An admin ending a session without knowing whose it was could
not be recorded honestly, and the row has to name the subject. A sid belonging to a different account
answers `404` — an admin acting on the wrong account is told they have the wrong account rather than
shown a stranger's session.

### Added — creating an account, and the devices somebody is signed in on (`1.9.0`)

`POST /auth/cluster/users` creates an account as an administrator — the counterpart to registration,
and the door for somebody who will never register themselves or who arrives through a provider and
should already hold a tier when they do. A password is optional; one that is set answers to the same
floor as every other, or the door with the least scrutiny becomes the one that admits the weakest
password on the cluster. A new account is `active` or `pending` and never `disabled`: an admin wanting
that creates it and disables it, and the trail then says both things happened.

`GET /auth/sessions`, `POST /auth/session/revoke` and
`POST /auth/cluster/users/{userId}/sessions/revoke-all` are the sessions surface, and it is **here
because the sessions are**. A member verifies a cluster session offline against a published key and
stores nothing, so a member asked what devices an account holds answers honestly with none — an empty
card rather than a wrong question.

**Sessions are found under every handle an account can be proved by.** A session is keyed by the
handle somebody *arrived* with, so one account signed in with a password and with Discord has two
keys; asking under one finds half the devices and reports the other half as nothing.

A named session must be the caller's own. A sid is opaque and unguessable, but one that leaks must not
become a way to sign somebody else out — and "not yours" answers the same as "not real", because
telling those apart says whether an id exists. Ending sessions is never gated on holding the
capability: revoking takes authority away, and a member that has stood down still holds the rows for
what it minted.

Sessions carry `lastSeen`, which is the last time that session **rotated its tokens**. It is the only
contact the anchor has with a live session — every other request goes to a member and is verified
offline — so it is named for the nearest true thing rather than for a request count nothing counts,
and it is absent for a session that has not rotated.

### Fixed — a browser could not attach an identity at all (`1.9.0`)

The cross-origin allowance never sent `Access-Control-Allow-Credentials`, so a browser discarded both
the one-time ticket cookie and the whole response to `POST /auth/identities/{provider}/start`. The
callback could then only ever report that the link did not verify. Safe to send because the allowance
is a configured origin and never the wildcard — the two together are what the specification refuses to
combine.

### Fixed — a failed attach reported itself as a failed sign-in (`1.9.0`)

The link callback redirected with `#error=`, which is what a *sign-in* failure carries. A panel reads
the fragment once at boot and cannot tell two failures apart by their value, so a failed attach landed
on the sign-in card — telling somebody who is signed in that their sign-in failed. It carries
`#link_error=` now, which is what the same callback on a host holding its own accounts already sends.

### Fixed — a browser could not reach the doors that detach (`1.8.1`)

The cross-origin allowance named `GET, POST, PATCH, OPTIONS`, so a panel on another origin was
refused at the preflight for every `DELETE` — detaching an identity and deleting an account. A
preflight refusal happens in the browser: this daemon never sees the request and no log here records
it, so the door reads as unreachable rather than as a policy that does not permit it.

The allowed methods are pinned by a test against the doors that exist, so a door added with a new
method cannot ship without the allowance following it.

### Added — the anchor records what happens to the cluster's accounts (`1.8.0`)

The anchor writes its own event journal, at `/var/lib/kgsm-auth-anchor/events`. A Control Panel on
the same machine finds it by scanning for journals and serves it merged with every other producer's,
so no configuration connects the two.

**It is the only witness there is.** The anchor is where a person signs in, where an account is
created, and where authority is granted and taken away — for the whole cluster. Nothing else sees any
of it, so a line the anchor does not write is a fact that exists nowhere.

Eleven types are recorded: a session beginning and ending, a session withdrawn when the account
behind it is switched off, an account provisioned, approved, disabled, deleted, its tier moved or its
password set, an identity attached or detached, and a run of wrong passwords that locked an account.

**One line per fact, never one per request.** A patch that moves both a tier and a status writes two
lines, because an access review reads for one or the other and a combined line makes both queries a
text search. A patch that moves neither writes none.

**A sign-in is recorded where a session is minted, which is one place.** Every door — a password, a
registration, a provider redirect — mints through the same call, so the record cannot be forgotten in
one of them. Forgetting is silent: the person is signed in and nothing says so.

**`auth.locked_out` is emitted when a lock begins and never on the attempts it then refuses.** An
account under attack is retried immediately, so a line per refused attempt is the flood that buries
the line reporting the run. A wrong username never reaches it — there is nothing to lock — so the
event names an account that exists, which is what separates it from a failed attempt.

**A sign-out is recorded only when this call is what ended the session.** A client retrying, or one
holding a token revoked from elsewhere, presents a session that is already over. It still gets its
204, because somebody wanting to be signed out is signed out and reporting "there was no such
session" would tell a stranger holding a stolen token whether it was still live.

### Added — changing an account, not just opening one (`1.8.0`)

A person can change their own password, list the ways into their account, and detach one. An
administrator can set somebody's password and delete an account.

**They are the anchor's because the accounts are.** A member writing any of them lands in that
member's replica, unversioned by the anchor, and is overwritten by the next thing published about the
account — appearing to work and then quietly not having happened.

`POST /auth/password` requires the password currently held. A bearer left open on a shared machine is
otherwise enough to lock its owner out of their own account for good, and it is the one door where
being signed in is not the whole of the proof. It is verified through the sign-in path, so the door
that checks a password and the door that changes one cannot reach different conclusions about the
same one.

`POST /auth/cluster/users/{userId}/password` knows no current password, because the case it exists
for is a person who has lost theirs. It clears the lockout with it: an admin resetting a password for
somebody locked out has plainly resolved what the lockout existed for.

`DELETE /auth/cluster/users/{userId}` travels as a versioned tombstone rather than as an absence, so
a member that was down learns of the removal when it returns instead of handing the account back at
its next snapshot. Nothing announces the sessions: a member resolves authority against its replica on
every request, and an account that is not there answers "no account".

`GET /auth/identities` carries the credential id a detach names — a door addressed by an id a caller
cannot learn is unreachable. It never lists the password, because there is nothing about one to
detach; that it exists is said separately, since it decides whether removing the last identity would
leave a way in.

### Added — changing what proves an account (`1.8.0`)

`POST /auth/reauth`, `POST /auth/identities/{provider}/start` and
`GET /auth/identities/{provider}/callback` attach an account at a provider; `GET /auth/identities`
now carries what this cluster can attach and whether the caller may change it right now.

**Attaching and detaching exist together, and shipping one without the other would strand people.**
Signing in again with a provider you have just detached does not give the account back — nothing
claims that handle any more, so it provisions a second account and you are a stranger on it.

**These doors ask for a credential again, and the rest of the anchor does not.** Holding a session is
not the same as having proved you own it, and the two come apart exactly where it matters: an
unlocked laptop, a browser left signed in, a token lifted from storage. Most of what a session does is
bounded by that session's own life. Attaching an identity is not — afterwards whoever holds that
provider account can sign in as this one for as long as the account exists. Detaching carries the same
gate, because it is the half that locks somebody out.

**Signing in counts as proving it**, stamped at the one place a session is minted, so a new arrival is
never asked for anything and somebody returning to a week-old tab is asked once. Freshness is checked
when a link is *started*, never on the way back: the bounce takes as long as it takes, and the ticket
is already one-use, short-lived and unforgeable. A proof dies with its session, so a session id
reissued or replayed never arrives already trusted.

**The link callback is a different address from the sign-in one**, and both must be registered against
the provider's application. The two arrivals mean different things: one mints a session for whoever
comes back, the other attaches whoever comes back to an account already signed in. One address for
both would let a link return through the sign-in door and mint a session instead.

The browser carries an opaque ticket and never its own account id — a browser holding that would be
the authority on whose account is being changed. The provider screen is `consent`, not the silent
`none` a sign-in uses: somebody attaching an account is choosing *which* account, and a silent bounce
attaches whichever one that browser happens to be signed into without ever showing them which.

`Anchor__ReauthWindowMinutes` sets how long a proof lasts.

### Added — the link flow belongs to the flow, not to a surface (`TheKrystalShip.KGSM.Auth` 3.3.0)

`ReauthGate` and `LinkTicketStore` are part of the authorization-code flow rather than of any one
provider or any one component that runs it — the same reason `OAuthHandshake` is here. Two components
run that flow now, and a second copy of a security-relevant store is a second set of rules free to
drift from the first.

### Added — the shape of an account event (`TheKrystalShip.KGSM.Auth.Journal` 1.0.0)

The type names and payload writers for signing in, signing out, revocation, account lifecycle,
identity links and lockouts.

**One implementation, because two fail silently.** Two components write these — a host's own API when
it holds its accounts, the anchor when a cluster's are held by one — and one reads them back by
deserializing into a fixed shape. A field spelled differently by one writer does not throw: it lands
as a null, and the row renders with a name missing and nothing reported.

The package has **no dependencies at all**, which is the point. It is a wire shape both writers must
agree on, and one of them is a Native AOT daemon holding a cluster's account store.

### Added — telling the attempt that locks an account from the ones it refuses (`TheKrystalShip.KGSM.Auth.Users` 1.4.0-dev.4)

`LocalSignInResult` carries the account's standing with the lockout policy and whether this attempt is
what *caused* the lock. The two are the same answer to whoever is guessing and a different fact to
whoever reads the record, and only the caller can tell them apart.

### Fixed — a refused sign-in says so (`1.7.2`)

A wrong password, a forged callback and a refused registration were all silent. A browser was the only
witness to a failed sign-in and it cannot be asked afterwards, so the first person unable to get in
was a person nobody could help.

Every refusal at every door is now audible at warning level with enough to act on: which account was
attempted, whether it was locked out or switched off, and which provider refusal it was. A successful
password sign-in says so too, so an operator can see the door working rather than infer it from
silence.

The attempted username is recorded and the answer to the caller is unchanged — one outcome at one
cost, whether or not the name exists. This journal is not reachable by whoever is guessing, and
telling one person mistyping from somebody working through a list is exactly what it is for.

### Added — a sign-in page can tell what this cluster offers (`1.7.1`)

`GET /auth/providers` reports `registration` beside `redirects`. Whether somebody may make an account
here is a fact a sign-up card has to know before it draws itself, and the only other way to find out
is to attempt one — an attempt is not a probe. A panel that assumes draws a door that cannot open on
a cluster with registration switched off.

### Added — a person with no account can make one (`1.7.0`)

`POST /auth/register` creates an account from a username, a password and optionally a name to be
shown by, and hands back a real session. Off unless `Anchor__AllowSelfRegistration` says otherwise,
because it is an unauthenticated write and a cluster that never considered the question should not be
taking strangers because a default did.

**It adds a door to a room rather than a room.** Completing a sign-in at a configured provider
already provisions exactly this: an account at `none`, `pending`, `TierSource.Derived`, bounded by
the same `PendingPolicy` — one queue, not two counts that can disagree about how full it is. Nothing
on the wire can ask for a tier or a status; both are decided here and the tier is always none.

**The session it returns is real and reaches nothing**, deliberately. A bare refusal tells somebody
who has just made an account nothing about what happens next; a session lets a surface say they are
waiting on an administrator, and lets that administrator see them.

Only the member holding the accounts writes one. A member standing by would create an account the
holder has never heard of and will overwrite at the next snapshot — an account somebody was told they
had, that quietly stops existing. Every account created is announced at a version like any other
change, so a person who registers is not a stranger on every member they visit.

### Added — signing in with an account you already have (`1.6.0`)

The anchor authenticated by KGSM password and by nothing else, so on a cluster where most people are
known by an external identity it was a door almost nobody could use. It now takes them too:
`GET /auth/providers`, `GET /auth/{provider}/start`, `GET /auth/{provider}/callback`.

**A provider is a route value resolved against a catalog**, and the catalog is the only place this
daemon names one — wiring up another is an entry there and nothing else. The application is the
**host's**, read from the shared `KgsmAuth` configuration every KGSM surface on the machine binds, so
a person signing in here and signing in beside it goes through one application rather than two. It is
read by explicit key rather than bound, because a reflective binder is what an ahead-of-time compiled
daemon cannot do.

**The provider answers who, and contributes nothing else.** No group, no guild, no role is consulted;
what somebody may do is on their KGSM account. So an identity that already belongs to an account
resolves to that account with the tier it already has, and one that belongs to none provisions an
unapproved account holding nothing — never matched on a username or an email, which is the documented
route to handing one person another's access.

What this door mints is what the password door mints: a session audienced to the **cluster**, signed
with the private key, that every member verifies offline and none can produce. The two differ in what
proves a person and in nothing after that.

`state` and PKCE ride one short-lived `HttpOnly` cookie and neither is optional — the verifier never
travels in a URL, and the CSRF gate runs before any exchange is attempted. `SameSite=Lax` rather than
`Strict`, because Strict suppresses the cookie on the top-level redirect back from the provider and
would break every sign-in. A browser is handed its session in the URL **fragment**, which is never
sent to a server, so it stays out of access logs and out of the Referer header.

The `prompt` a caller asks for is the one the provider is sent. A door that takes an explicit request
for a screen and silently sends the opposite is wrong however the provider happens to treat it.

A member standing by starts no sign-in it could not finish. A provider nobody wired up and a provider
nobody has heard of are one answer, so the set a build knows about cannot be probed.

### Fixed — a member can say who a session it verified belongs to (`users-1.4.0-dev.3`)

A session names its holder by the handle of whatever proved them: `discord:123` for an external
identity, `local:<user id>` for a KGSM password. Only the first travelled, so a member that took the
cluster's accounts could verify a password-holder's session, hold their account, and still resolve
them as a stranger — signature good, tier `none`, every gate refusing. It failed as a correct-looking
answer about somebody else.

**Every handle travels now; no secret ever did or does.** A handle is the name of a fact and a hash is
evidence for it, and only the second lets somebody in. A replica holds a password's handle as an
identity with no secret, which is the shape sign-in already treats as an account with no password —
the decoy hash is verified and the attempt refused, at the same cost as any other. So a replica says
what somebody may do and still cannot let them in, which is what it was always meant to be.

The two tests that had to change were asserting the wrong thing: both stood a handle count in for
"the password did not travel", when the property is about the hash. They assert the hash now, and are
stronger for it.

### Fixed — a fact this anchor states now reaches every member (`1.5.1`)

A member's incarnation rose only to refute a report that it was suspect or dead, so an anchor that
restarted and stayed reachable gossiped an incarnation its peers already held and everything it
stated was ignored — silently, every round. The audience, the issuer and the browser address this
anchor publishes could not reach anybody, and neither could a rotated signing key.

Measured after the fix: the three facts arrived at a separate member within one gossip round of a
redeploy, and this anchor's incarnation settled rather than climbing once per round.

### Added — one session, verified where it cannot be minted (`1.5.0`, `sessions-2.2.0-dev.2`)

`ClusterSessionValidation.Accepting` widens a surface's own validation rules so it accepts two kinds
of session at one door: the ones it minted for itself, and the ones its cluster's auth anchor minted
for everybody. That is what makes signing in once real — a member with the published key can check a
session it had no part in issuing, and cannot produce one.

The two kinds are told apart by the **algorithm**, which is the only part of a presented token
decided by who signed it rather than by who presents it, and each is pinned to its own audience and
its own issuer: a symmetric signature is the surface's own and carries the surface's values, an ECDSA
one is the anchor's and carries the cluster's. No cross-pairing is accepted, so a combination nothing
currently mints cannot become useful later. The published key offered as an HMAC secret is refused,
which is the attack the pin exists for: that key is one every member holds.

Knowing nothing fails closed. A surface with no cluster, one that has not heard who holds the
accounts, or one whose holder states no audience or issuer accepts no cluster session at all and goes
on serving its own — guessing either would accept a token minted for a different cluster.

### Added — what an anchor states about itself (`1.5.0`)

Beside the verification keys, an anchor publishes the **audience** and the **issuer** its sessions
carry, and the **address a browser signs in at**. A member with keys and neither of the first two
cannot decide what to accept — and every surface stamps an issuer of its own, so a member assuming
they matched would refuse every session with nothing saying why. A browser holding nothing needs
somewhere to be sent. The address is stated rather than inferred from
the address members reach the anchor at — an anchor on a LAN address behind a public vhost has two,
and only one of them is a browser's.

### Added — signing out reaches the whole cluster (`1.5.0`)

A cluster session is accepted on every member and has a row on exactly one of them, so ending it at
the anchor ended it nowhere else. Sign-out, and the revoke a withdrawn account's refusal performs,
now announce `session.revoke` on the durable bus. A member that is down when somebody signs out
learns of it when it returns.

### Added — a member's snapshot of the accounts, and the fan-out that keeps it current (`1.4.0`)

`GET /auth/cluster/snapshot` hands another member every account with the version it is at — what a
member takes before it follows the stream, so one added on Tuesday is not missing what happened on
Monday. Authenticated by a member service token through the cluster package's own check, never by a
person's session: an admin is a person, and this door answers to members.

Every change is then announced on the durable bus as `account.changed`, and a removal as
`account.removed`. Withdrawal has to travel as reliably as granting, which is why it rides the outbox
rather than a best-effort notification — a member that is down when somebody is disabled gets the
change when it returns, not never.

The announcement is not in the same transaction as the change it announces, so a crash in the gap
leaves the change applied here and never told. The change is never lost, only the telling of it, and
a member repairs it by taking a snapshot — which is the path that already exists for joining rather
than a second mechanism for a narrow window.

### Added — the single write path for what a person may do (`1.3.0`)

`PATCH /auth/cluster/users/{userId}` changes an account's tier, its status, or both. An absent field
is left alone, so changing a status does not require restating a tier and cannot silently revert one
somebody else just set.

**Every change takes a version, and the version is returned.** It is what every other member orders
by, so a demotion and a re-promotion delivered out of order still settle on whichever was issued
last — and a caller holding the version knows its change is the newest statement about that account.

**A tier the caller misspells is refused, not read as `none`.** Everywhere else in the ecosystem an
unrecognised tier grants nothing, which is the safe reading of a value somebody else wrote. Here it
is what the caller asked for, and reading `opreator` as "no authority" would demote the person the
admin meant to promote. `none` itself stays askable, or withdrawing authority would be impossible.

**The last administrator cannot remove their own authority.** One account store serves the whole
cluster, so this is not "no admin on this machine" — it is nobody, anywhere, able to undo it through
any surface, with the only way back being an edit by hand on the machine holding the accounts.


### Added — the replica: a member's own copy of the cluster's accounts (`Auth.Users` 1.4.0-dev.2)

`AccountReplica` applies what the member holding the accounts publishes, and `IAccountVersions` is
the counter that orders it. A member can then answer *who is this and what may they do* without
leaving the machine — which is what lets serving, streaming and session refresh carry on while that
member is unreachable.

**No password travels.** A replicated account carries its external identities, because resolving a
session naming `discord:123` needs the handle that maps it to an account, and a handle is the name of
a fact rather than evidence for it. Password hashes stay where signing in happens. A replica therefore
says what somebody may do and cannot let them in — the difference between a compromised member
reading what its tier allows and signing in as anyone in the cluster.

**A whole record travels, never a field of one.** Per-field messages leave a replica holding a tier
from one point in time beside a status from another, an account that never existed in that
combination anywhere. One record at one version means a replica always holds a state the writer
actually published.

**The counter is its own table and `UserSchema.Version` does not move.** The store is opened by every
surface on a host, each pinned to its own build, and the schema guard refuses a file declaring a
version newer than the build reading it — deliberately, because half-understood accounts is the
failure that grants access quietly. Raising it would refuse the Control Panel, the bot and the
assistant at once until all three were redeployed. A table an older build has never heard of is
invisible to it instead.

A version row outlives the account it belongs to, and that is the tombstone: a change issued before a
removal carries a lower version and is refused rather than re-creating somebody who was deliberately
removed. A username another local account already holds is reported, never merged — merging on a
shared name is the documented route to handing somebody another person's access — and the version is
not advanced, so it stays resolvable rather than silently skipped.


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
