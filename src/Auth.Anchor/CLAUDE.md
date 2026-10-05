# `Auth.Anchor` (`tks-auth`) — locked decisions

The OpenID Connect provider that holds the accounts and signs people in — on its own, or as the member
of a KGSM cluster that signs people in to the whole cluster at once. Built from this repo's libraries
by project reference. Its own design authority is `../cluster-auth-plan.md`, its OpenID Connect half
`../hosted-sign-in-plan.md` (both at the workspace root), and its place as the organization's provider
`kgsm-docs/plans/tks-auth.md`. Minting is `Minting/CLAUDE.md`.

## The core and the KGSM module

- **`Program.cs` composes the core, and the KGSM module only when a cluster is configured.**
  `TksAuthCore` (`AddTksAuthCore`, `MapTksAuthCore`) is accounts, sessions, the OpenID Connect doors,
  the applications and their clients, the account page, the admin and authority routes and the journal. `KgsmModule`
  (`AddKgsmModule`, `MapKgsmModule`) is membership and the bus, the DNS member,
  `ClusterMembershipWorker` (standing, the founding claim, the `auth.*` facts, announced clients), the
  catalog's handlers and `AuthorityReporter`, `MemberDepartureWorker`, `AuthorityBroadcast` and its
  worker, `SessionBroadcast`, the member snapshot, the roster, `/auth/cluster/public-key` and the
  component surface.
- **One switch: the cluster secret.** `KgsmModule.ClusterFrom` reads it; `ClusterOptions.Enabled`
  decides whether the module is composed and is what `AnchorRole` is built from, so the standing and
  the composition cannot disagree. There is no second setting.
- **Every KGSM path is the module's.** `/etc/kgsm/cluster-founded`, `/var/lib/kgsm/anchors` (the
  descriptor and the manifest beside it) and the cluster store are reached only from module code. A
  standalone install reads and writes nothing under `/etc/kgsm` or `/var/lib/kgsm`;
  `StandaloneAnchorTests` asserts that and that no module service is registered.
- **The core tells other members things only through `ISessionAnnouncer` and
  `IAuthorityAnnouncer`.** The module binds them to `SessionBroadcast` and `AuthorityBroadcast`; a
  standalone anchor binds both to `StandaloneAnnouncements`, which ends nothing elsewhere and clears
  the authority outbox, because nobody else holds its sessions or its accounts. A core class that
  resolves a module service directly breaks every standalone start.
- **A standalone anchor's own actions enter its catalog from the binary, never from disk.**
  `StandaloneCatalog` reports `AuthActions.Declared` as this anchor's manifest on every start. In a
  cluster the reporter reads the installed manifest instead, and the two never both run: a report
  replaces the member's last one wholesale, so two reporters under one member id would overwrite each
  other. The standalone report carries no `auth:config.*` or `auth:journal.read`, since the surface
  those gate is the module's.

## The daemon

- **A KGSM session's audience is the CLUSTER, not a machine.** That single value is what makes one
  sign-in valid on every member, and changing `Anchor__ClusterId` on a running cluster invalidates
  every token at once. It reaches the minter as `SessionTokenOptions.Audience`. Every other
  application's tokens carry that application's audience (see "Applications").
- **Signing is asymmetric and the verification key is published.** A member must be able to check a
  session it cannot mint — one that could mint what it verifies could mint itself an Owner's session.
  `ValidAlgorithms` is pinned for the same reason: a public key offered as an HMAC secret would make
  the key everybody holds the key everybody can sign with.
- **The private key is generated exactly once, on a machine that has none.** Every member in the
  cluster verifies against its public half, so a key that changed would invalidate every session and
  leave every member checking against something nothing signs with. A file that exists and cannot be
  read stops the daemon; it is never a reason to generate. It is created with mode `0600` rather than
  chmod'd after — the gap between write and chmod is exactly what the mode exists to close.
- **The anchor runs on the account store at schema version 2.** `SqliteAuthorityStore` is both the
  authority and the `IUserStore` every door reads.
- **The anchor's store is its own file**, `/var/lib/tks-auth/accounts.db` in its state
  directory, and never the node's replica on the same machine (`/var/lib/kgsm/auth/users.db`). A node
  applying the anchor's snapshot to the file the anchor writes would be the authority rewritten by its
  own echo.
- **A KGSM session proves who, never what.** It carries no claim about access. Every route here decides
  its caller by an action — `Endpoints.RequireCaller(ctx, action)`, evaluated against the authority and,
  for `auth:*`, held to a recent sign-in — and the account's standing is re-read on refresh, where a
  withdrawn account has its session revoked rather than left to run out its bearer's lifetime. Two
  kinds of bearer are accepted at this daemon's own doors, and no other (`SessionReader`): a KGSM
  session, audienced to the cluster, and a session of tks-auth's own application — the admin pages' —
  audienced to `tks-auth`. Both are sessions under a browser's sign-in here and are decided by the same
  action and the same recent-sign-in rule; any other application's token is that application's alone.
- **A gated route declares its action on itself, and that declaration is both enforced and
  published.** `AuthAction` metadata on the route is what the handler reads (`AuthAction.Of`), the
  own-surface group is marked for `OwnSurfaceFilter`, and authority edits take their action from
  `EditKind` — the table `AuthorityRules.Check` enforces. `GET /auth/cluster/operations` is built from
  exactly those (`AnchorOperations`), so a client gates a control on the request it is about to make
  and names no action itself. A handler that checks an action it does not read from its route is an
  operation this document does not describe.
- **Disabling or deleting an account goes through the administration rules.** Those are what keep the
  last active Owner and let only an Owner act on another; approving and re-enabling are gated by their
  own actions. The first account an empty store gets is granted Owner.
- **A store that cannot be read is `503`, never `403`.** "We could not find out what this person may
  do" is a different fact from "they may do nothing", and reporting the first as the second locks out
  the Owner mid-incident. It is the same rule `Auth.Users` states for the store itself.
- **Every endpoint is a plain `RequestDelegate` and every wire shape has source-generated metadata.**
  The routing overloads that bind an arbitrary delegate reflect over its parameters, which no
  Native-AOT service can do, and the failure appears at publish time rather than at build time. The
  same goes for a shape missing from `AnchorJsonContext`: it throws at runtime, not at build.
- **The CORS allowance is a registered client's origin, never a wildcard and never with
  credentials.** It is answered only on what a client reads across origins — discovery, the key set,
  `/token`, `/userinfo`, `/auth/identity`, `/auth/cluster/*` and this anchor's own surface — and never
  on anything that reads the provider's cookie. This is a surface that mints credentials; a wildcard
  invites any page to drive somebody's sign-in from their own browser.
- **The package is preset-disabled.** A cluster has one anchor and which machine holds it is a
  decision made under `api:members.manage`. A second machine with the package installed and the unit stopped is a
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
- **Only the anchor on the machine that founded the cluster claims the accounts into an empty
  assignment** — `ClusterFounding.IsFoundedHere`, the founding record naming the secret it holds.
  Anywhere else an empty assignment means gossip has not arrived, and a claim made then competes with
  the real holder under a tie-break that can hand this anchor the cluster's accounts. A founding
  machine that takes another cluster's secret stops being the founder by that comparison alone.

## Its journal

- **The anchor writes its own event journal, and it is the only witness there is.** Signing in,
  creating an account and moving somebody's authority happen here for the whole cluster, so a line the
  anchor does not write is a fact that exists nowhere. The producer id has to be the name in the
  unit's `StateDirectory=`, because a reader establishes the producer from the path it read a line out
  of — a journal written anywhere else is not reported as misplaced, it is simply never found, and
  looks exactly like a daemon that recorded nothing. A test run relocates it with
  `KGSM_JOURNAL_STATE_ROOT`; left at its default, a suite that signs people in appends invented
  sign-ins to a live audit page.
- **A sign-in is recorded where a session is minted, which is one place.** `MintSessionFor`, reached
  only from the code exchange at `/token`, and every session it mints lives under a provider session. A
  second mint site is a second place to forget the line, and forgetting is silent: the person is signed
  in and nothing says so. The token exchange mints no session; it records `auth.token.exchanged` where it
  mints, its one place.
- **One line per fact that changed, never one per request**, and only when the action actually
  happened. A patch that changes an account's status writes its line; one that changes nothing writes none;
  a sign-out for a session that had already ended writes none. An access review reads for one fact at
  a time, and a line per request fills it with rows saying nothing.

## Sessions and credentials

- **Every session lives under a browser's sign-in here.** A row that is neither a provider session nor
  minted under one is deleted as the registry opens: nothing would end it on a sign-out or list it with
  the sign-in it came from.
- **Changing what proves an account asks for the credential again; nothing else here does.** Being
  signed in on a browser is not the same as having proved you own the account, and attaching an
  identity outlives the session that attached it — afterwards whoever holds that provider account signs
  in as this one. Detaching and setting a password carry the same gate. The proof is the provider
  session's `credential_at`, stamped whenever a credential is typed on that browser, and it dies with
  that provider session.
- **Attaching and detaching ship together or not at all.** Signing in again with a provider you just
  detached does not give the account back: nothing claims that handle, so it provisions a second
  account and the person is a stranger on it.
- **The link callback is a different address from the sign-in one.** One completes a request in flight
  for whoever comes back; the other attaches whoever comes back to an account already signed in, and
  always returns to the account page. One address for both lets a link return through the sign-in
  callback instead. Both have to be registered against the provider's application, or the bounce is
  refused where no log here sees it.
- **Freshness is checked when a link STARTS, never on the way back.** The bounce takes as long as it
  takes, and re-checking fails a link somebody legitimately began while adding nothing — the ticket is
  already one-use, short-lived and unforgeable.
- **Sessions are listed and ended HERE, because they exist only here.** A member verifies a cluster
  session offline against a published key and stores nothing, so a member asked what devices an
  account holds answers honestly with none — an empty card rather than a wrong question. They are
  looked up under **every credential handle the account holds**: a session is keyed by the handle
  somebody arrived with, so one account signed in with a password and with Discord has two keys.
  A person reads and ends their own on the account page; somebody holding `auth:accounts.disable`
  reads and ends anybody's under `/auth/cluster/users/{id}/sessions`. Ending one is never gated on holding the capability, for
  the same reason sign-out is not.
- **Ending one session and ending all of them are separate doors, and both exist.** They are different
  decisions with different costs, and somebody left only the wide one reaches for it because it is
  what exists. A session ended on somebody else's behalf is addressed under the account it belongs to,
  so the check is whether the sid is that person's — ending a session without knowing whose it was
  could not be recorded honestly.
- **The session registry is the anchor's own, on its own file.** Sessions are not accounts: a member
  replicating the cluster's accounts replicates none of the sign-ins.

## Administering itself

- **In a KGSM cluster the anchor administers itself, because on the ordinary topology nothing else is
  there to.** A leaf is configured and read through the node that runs it; an anchor is a peer of
  every node rather than something one of them hosts, and the machine it sits on need run no Control
  Panel at all. So the module serves `/auth/config` and `/auth/logs` from the daemon being configured and the daemon being read,
  on the anchor's own `auth:config.*` and `auth:journal.read` — a daemon's log is the account store
  described from the side.
- **The unit both surfaces name is the descriptor's, never a second setting.** One name in one place
  cannot disagree with itself, and a log surface reading the wrong unit reports somebody else's
  silence as this one's. The unit carries `SupplementaryGroups=systemd-journal`, without which
  `journalctl` exits 0 having printed nothing — a success indistinguishable from a daemon that has
  logged nothing.
- **One `journalctl -f` for however many people are watching.** The first subscriber starts the
  follow, the last one to leave stops it, and an unwatched page costs nothing. A subscriber that
  falls behind drops its own oldest lines rather than stalling the follow for everybody else — the
  journal on disk is the durable record, and a reconnect re-reads it. The stream carries no backlog:
  the caller hydrated its scrollback from the read, and sending history here shows every line twice
  on every attach.
- **An idle journal and a dropped connection look identical on screen.** The stream opens with a
  comment line, which is what makes a proxy release a response that has carried no bytes, and
  heartbeats after it — so a viewer can show a tail that has stopped as stopped rather than as quiet.
- **A test relocates every absolute path this daemon reads, not only the ones it writes.**
  `ConfigDescriptorPath` and `ConfigOverridePath` join the stores and the journal root: left at their
  defaults, a run resolves the descriptor the deployed daemon carries, names the live unit and
  follows its journal — and passes only on a host where the thing under test is already installed,
  which is measuring the host.
- **The catalog is kept here, from every member's report.** `AuthorityIntake` is the one place a
  report or an uninstall lands — over the bus from another member, directly from this anchor's own
  reporter, or, standalone, from `StandaloneCatalog` — and the one place what it changed is journaled, attributed to the member it came from as
  `system:<member>`. A node speaks only for its own instances: an uninstall is matched on the sender's
  member id and the nonce, never on a node the message names.
- **A member's report is forgotten only when the roster marks it left.** That is what removing a member
  does. A member that crashed is marked dead and reaped within minutes, and treating that as removal
  would strip a node down for maintenance of every grant it carries. `MemberDepartureWorker` reads the
  roster; nothing else forgets a report.
- **Every write reaches the cluster from the store's outbox, never from the write path.**
  `AuthorityBroadcast` drains `authority_outbox` after each write and on a timer, sending each owed
  record as it now stands, and clears a row only after the bus holds it. A write path that tries to
  send its own change is a second copy of the outbox that a crash can separate from the write.
- **The heartbeat goes only to members the roster shows alive.** `authority.current` carries the moment
  it was sent, so one held in the outbox for a member that is down would confirm nothing on arrival; a
  member that was down goes stale and takes a snapshot. The staleness bound is held to at least two
  heartbeats, so one late heartbeat never leaves a member read-only.
- **An authority edit is decided by `AuthorityRules`, never by the endpoint.** `AuthorityEndpoints`
  maps a request to an `AuthorityEdit`, pre-checks it against the snapshot to answer with the rule's
  code, and the store checks it again in the transaction that applies it. A check written in the
  endpoint is a second implementation of the rules. `POST /auth/cluster/authority/checks` asks the same
  rules about several edits at once and writes nothing, which is how a page says why a control is
  closed before anybody reaches for it without the page holding a copy of them.
- **The anchor's actions are declared twice and held together by a test.** `[Action]` on this assembly
  writes the manifest; `AuthActions` in `Auth.Access` names them for every evaluator.
  `AnchorManifestTests` fails when the two disagree.
- **Every `auth:*` action needs a recent sign-in, and only after the evaluator allows it.**
  `AnchorAccess` reads when the session's provider sign-in last proved a credential; nobody is sent to
  type a password for something they would be refused anyway.
- **`tks-auth owner grant <username>` is the Owner recovery path, and it is a mode of this
  binary rather than a tool beside it.** It reads the daemon's own settings, so it opens the store and
  writes the journal the daemon does, and is run as the anchor's service account. It bypasses the
  administration rules — whoever can run it already holds the file — and journals
  `auth.assignment.granted` with `local:<user>` as the actor. It opens the store the way the daemon
  does, refusing a file at any other schema version.

## Applications (`ApplicationRegistry`, `ApplicationCatalog`, `ClientAuthentication`)

- **Every client belongs to an application, and the application decides what is minted.** KGSM is the
  built-in application (`ApplicationRegistry.Kgsm`): its audience is the cluster id, its access lifetime
  `Anchor__AccessLifetimeMinutes`, and its clients are the announced ones, the declared panels and those
  registered under `/auth/cluster/clients` (a client row with no `application_id`). It is never stored and
  cannot be changed or removed here, because its audience is a cluster setting. Every application
  registered here is a row in the session store's `applications`, beside its clients.
- **tks-auth's own admin routes are a built-in application too** (`ApplicationRegistry.Provider`): id
  `auth`, the namespace of the actions those routes require, audience `tks-auth`, an application's
  lifetime, and its tokens list the `auth:*` actions the account holds. Its one client is the admin
  pages', `tks-auth` — public, PKCE, its redirect and post-sign-out address `<issuer origin>/admin/` —
  declared from the issuer by `ClientRegistry` like a configured panel, never stored, and nothing
  registers over it or removes it. The admin pages are therefore a client of the provider that serves
  them, administering with a session that no KGSM member and no other application accepts, whether or
  not a cluster is configured.
- **One code path, two doors.** `ApplicationRegistry` holds every rule and every journal line for
  registering, changing and removing an application, adding and removing a client and rotating a secret.
  `/auth/cluster/applications` (on `auth:applications.manage`) and `tks-auth app …` both call it, the
  command composing it over the daemon's own files with `DeferredAnnouncements`, so the daemon drains
  what it owed the cluster. A rule written in a door is a second implementation.
- **The registry is read from memory and reloaded by generation.** Every write to the clients or the
  applications advances `registry_meta.generation` in its own transaction, and `ClientRegistry` re-reads
  the store when a read finds the generation moved, checking at most once a second. That is how a
  change the host command makes reaches the running daemon.
- **An application's audience is its own.** Never the cluster id, never the issuer (an application's
  refresh tokens are audienced to the issuer), never `tks-auth`, and never another application's. Its
  id is its action namespace, and is never `kgsm`, `auth` or any namespace a KGSM member declares.
- **An application's access token lists its actions; KGSM's lists none.** `MintPairAsync` mints, for an
  application outside KGSM, an `at+jwt` audienced to it, naming the account in `sub` as the `id_token`
  does, carrying `client_id`, living the application's lifetime, and listing in `tks_actions` (an array,
  even empty) every catalog action in its namespace that `AccessEvaluator` allows the account at cluster
  scope. It is evaluated at every mint, the code exchange and every refresh alike, so the lifetime bounds
  how long a removed role keeps working there. Its refresh token is audienced to the issuer, so no
  resource server takes it as a bearer.
- **A confidential client proves its secret before any grant is read.** `ClientAuthentication` reads
  `client_secret_basic` or `client_secret_post` — both at once is `invalid_request` — and a client that
  fails is `invalid_client` with `401`, with a `Basic` challenge when Basic was tried. A code is therefore
  never spent by a request that could not have used it. A secret presented for a public client is
  refused, never ignored. PKCE is required of every client.
- **A session is continued only for the client it was minted for.** `sessions.client_id` records it at
  mint; the refresh of a confidential client's session needs that client authenticated, and naming any
  other client is `invalid_grant`. A session with no client recorded is KGSM's.
- **A client secret is made here, shown once and stored as its SHA-256 hash.** It is 256 random bits,
  so a slow hash buys nothing, and nobody can choose a weak one. It is never journaled, logged or listed,
  and rotating it ends the old one at once.
- **Removing an application or one of its clients ends every session minted through it**, in the
  transaction that removes the rows, and the application's actions leave the catalog with it.
- **An application's manifest is pulled, and refused whole when it speaks for anyone else.**
  `ApplicationCatalog` reads it from the registered address on registration, on a change of address and
  every `Anchor__ManifestRefreshMinutes` (`ApplicationManifestWorker`, only while this anchor holds the
  accounts), and hands it to `AuthorityIntake` as the report of `application:<id>`. A manifest in another
  namespace, in a KGSM component's or declaring requirements is refused; one that cannot be read changes
  nothing, so an application whose server is briefly down keeps every grant. Reports from the bus are
  members', never an application's.

## The token exchange (`TokenExchange`, `DiscordAuthorizations`)

- **`/token` takes `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) from an authenticated
  confidential client of an application outside KGSM, and from nothing else.** A public client is
  `unauthorized_client`; one that does not prove its secret, or names none, is `invalid_client`. KGSM's
  clients are refused: a KGSM session lives under a browser's sign-in, and an exchange has none.
- **Two subject token types, defined here.** `urn:tks:params:oauth:token-type:discord-access-token` is a
  Discord access token: Discord's `oauth2/@me` says whose it is and which Discord application holds it,
  and one from an application not in the client's application's `DiscordApplications` is
  `invalid_grant`. `urn:tks:params:oauth:token-type:discord-user-id` is a snowflake from a client whose
  application `ActForDiscord`; the token it gets carries `act: {"sub": "<client id>"}`. An application
  registered for neither kind is `unauthorized_client`. Never add a third type that takes a Discord
  identity on a client's word without either a token Discord vouches for or the act-for flag.
- **The token is the code flow's for that application, minus the session.** `at+jwt`, its audience, its
  lifetime, `tks_actions` evaluated at this mint, the account as `sub` — no `sid`, no refresh token, no
  `id_token`. The holder exchanges again; an Activity already holds the Discord token it exchanges.
- **The account decides the answer.** Only an active account gets a token. Pending, disabled and unknown
  are `invalid_grant` with the extension parameter `account_status` (`pending`, `disabled`, `unknown`),
  which the caller words for the person — never a token, never a bare error it has to guess at.
- **A Discord token nobody holds provisions a pending account; a Discord id does not.** The first runs
  `IdentityLinkService.ResolveOrProvisionAsync` under `Anchor__Pending*`, the rule and cap a Discord
  sign-in here uses, and journals the same `user.provisioned` and `identity.linked`. A bare id cannot be
  provisioned: learning who an id is needs a bot token, which this provider never holds.
- **Every exchange an authenticated client asks for is a line** — `auth.token.exchanged` or
  `auth.token.exchange_refused` with its reason — naming the client, the application, the Discord
  identity, the account and the acting client, origin `discord`. An outage at Discord or the store
  decides nothing and writes nothing.
- **What Discord says about a token is held for the token's life, capped at
  `Anchor__DiscordTokenCacheMinutes`.** Keyed by the token's SHA-256, never the token; bounded by entry
  count; a refusal and an outage are never held. The cap is how long a token revoked at Discord is still
  exchanged here, so it is a setting and not a constant.

## The Discord round trip (`DiscordDirectory`, `OAuthHandshake`)

- **It answers who, and only who.** `DiscordDirectory` is an `IIdentityProvider` and stays the only
  chokepoint to `discord.com`. It takes **one** `KgsmOAuthApplication`, not every provider's, so a
  composition cannot hand it another provider's by accident. It holds no guild, reads no role and
  takes no bot token: what a person may do is the account store's answer, and a login here proves one
  fact — that the caller holds this subject at Discord. `DiscordAuthException` derives from
  `KgsmAuthProviderException` so a caller handles any provider's outage identically.
- **The exchange asks it too, with no application of this provider's.**
  `DiscordDirectory.ReadAuthorizationAsync` presents a token another Discord application was issued to
  `oauth2/@me` on the same typed client and reads the answer through source-generated metadata. A
  `401`/`403`, or a token without `identify`, is `null`; a `429`, a `5xx`, an unreachable host or an
  unreadable body throws.
- **The caller's token buys one thing and is dropped.** It is presented to `users/@me` or `oauth2/@me`
  and never stored, so a completed login or exchange leaves the host holding no credential at Discord.
- **Register it transient, and resolve it once per composition.** It is a typed `HttpClient`; holding
  one in a singleton pins a handler for the process lifetime and silently stops the factory rotating
  it, so DNS changes never land. The composition resolves the client once and hands the same instance
  to both halves, so one sign-in uses one client.
- **A bad code is `null`; an outage throws.** A 4xx from the token endpoint is an expired or replayed
  code — the caller's problem, a `401`, start again. A 5xx or an unreachable host is
  `DiscordAuthException`, which is a `502`. Collapsing them reports one as the other and sends a
  browser round a retry loop that cannot succeed.
- **`OAuthHandshake` is its own type, not Discord's.** The state+PKCE pair is a property of the
  authorization-code flow, not of Discord, and every provider's round trip uses it unchanged.
- **`state` and PKCE ride one cookie and neither is optional.** `state` stops login CSRF and only
  works because the cookie binds it to the browser that started the login; a server-side set of issued
  states admits the attacker's own state. PKCE stops code interception. Do not "simplify" either away.
- **`SameSite=Lax`, never `Strict`.** Strict suppresses the cookie on the top-level redirect back from
  Discord, which breaks every login.

## The OpenID Connect provider

- **The issuer is configuration and the OIDC doors require it to be a URL.** Never inferred from a
  request: a Host header is the caller's to set. An anchor whose issuer is not an absolute URL answers
  `no_issuer` at every OIDC door rather than guessing one.
- **Until the client and its redirect are known to be registered, a refusal is rendered on the anchor's
  own origin.** Redirecting to an unregistered address with an error is the open redirect
  `/authorize` exists to refuse. Redirects are matched exactly — no prefix, no pattern.
- **The request in flight lives here, behind `kgsm_authz`.** The page, its form and its provider links
  carry no request field. One request per browser: beginning another deletes the last.
- **A credential post is refused before the credential is read** unless it carries the request cookie
  and a same-origin `Sec-Fetch-Site`, or an `Origin` equal to the issuer's where no fetch metadata is
  sent. That is the login-CSRF gate, and moving the check after the password check turns it into a
  lockout anybody can trigger.
- **A code is taken out of the store before anything about the exchange is checked**, by one
  delete-returning statement, once the client has authenticated. A code presented wrongly is spent;
  two exchanges racing get one row.
- **Every session minted through the provider records its provider session, in one column set at
  mint.** It is what makes sign-out, a second account on one browser, and ending the provider session
  from the sessions list each end exactly the right set. A mint site that skips it strands a surface
  signed in after its browser signed out.
- **The account is re-read on every pass**, cookie or no cookie: disabled or deleted ends the provider
  session and is refused, pending gets the wait and no code, only active gets a code.
- **An external provider's round trip completes the request in flight only when its returning `state`
  is the one the request recorded.** The callback is the one address registered with the provider's
  application and it also serves the provider door's own sign-in; matching on the cookie alone would let
  an abandoned request capture that sign-in.
- **A member's client is paths joined to its roster address, never URLs it names.** A member announcing
  full URLs could make any origin a place codes are sent. A registered client of the same id wins.
- **A surface's client id is its origin's host** (`ClusterClientAnnouncement.ClientIdFor`), for an
  announced surface and a declared panel alike, so a surface derives its own from where it was loaded
  and is told nothing — which is what lets a panel on a static host sign in through a member that
  never served it.
- **Where KGSM's clients live is published, as `auth.origins`, while this anchor holds the accounts.**
  Every member reads it through the holder to admit those origins, so a registered client and a
  declared panel — which exist only here — are admitted everywhere without anybody configuring a
  member. An application outside KGSM is nothing a member serves, and its origins are admitted here
  alone.
- **A panel on a static host is declared, not stored.** `Anchor__PanelOrigins` is what the deploy said
  this process serves, so it is rebuilt on every start and wins over a stored client of the same id; the
  registry refuses to remove one or to register over it. Its paths are
  `ClusterClientAnnouncement.ControlPanel`, the same statement a node announces its panel with.
- **`id_token`'s subject is the account, its audience the client.** It is never accepted as a bearer,
  and a bearer is never accepted as a sign-out hint.
- **The pages are this repo's `web/`, served as built from `UiPath`** (`ui/` beside the binary). The
  anchor writes the provider links at the marker and nothing else, reads the files per request, and
  serves `/ui/` only from under `UiPath` — a resolved path outside it is a 404, because this daemon can
  open its signing key. Every document goes out under the same content security policy, the admin
  pages' (`/admin/`) included. A failed plain form post is answered on the built-in page with the
  reason: the static document has nowhere to put one. With no pages installed the built-in floor still
  signs people in, and the account and admin pages answer that they are not installed.
- **The account page is the only place a credential changes, and a change needs a recent proof** —
  the provider session's `credential_at` inside the re-authentication window. Its sign-in is a request
  in flight for the `kgsm-account` pseudo-client, which is never registered and never issued a code.
- **A provider round trip begun to re-prove the person accepts only an identity already attached to
  that account**, resolved and never provisioned. It is recognised by the `state` it began with and
  returns to `/account`; it never mints anything.
