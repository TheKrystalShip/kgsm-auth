# `Auth.Anchor` (`kgsm-auth-anchor`) — locked decisions

The cluster member that holds the accounts and signs people in to the whole cluster at once. Built from
this repo's libraries by project reference. Its own design authority is `../cluster-auth-plan.md`,
and its OpenID Connect half `../hosted-sign-in-plan.md` (both at the workspace root). Minting is
`Minting/CLAUDE.md`.

## The daemon

- **A session's audience is the CLUSTER, not a machine.** That single value is what makes one
  sign-in valid on every member, and changing `Anchor__ClusterId` on a running cluster invalidates
  every token at once. It reaches the minter as `SessionTokenOptions.Audience`.
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
- **The CORS allowance is a registered client's origin, never a wildcard and never with
  credentials.** It is answered only on what a client reads across origins — discovery, the key set,
  `/token`, `/userinfo`, `/auth/identity`, `/auth/cluster/*` and this anchor's own surface — and never
  on anything that reads the provider's cookie. This is a surface that mints credentials; a wildcard
  invites any page to drive somebody's sign-in from their own browser.
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
  in and nothing says so.
- **One line per fact that changed, never one per request**, and only when the action actually
  happened. A patch moving both a tier and a status writes two lines; one moving neither writes none;
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
  A person reads and ends their own on the account page; an administrator reads and ends somebody's
  under `/auth/cluster/users/{id}/sessions`. Ending one is never gated on holding the capability, for
  the same reason sign-out is not.
- **Ending one session and ending all of them are separate doors, and both exist.** They are different
  decisions with different costs, and an admin left only the wide one reaches for it because it is
  what exists. A session an admin acts on is addressed under the account it belongs to, so the check
  is whether the sid is that person's — an admin ending a session without knowing whose it was could
  not be recorded honestly.
- **The session registry is the anchor's own, on its own file.** Sessions are not accounts: a member
  replicating the cluster's accounts replicates none of the sign-ins.

## Administering itself

- **The anchor administers itself, because on the ordinary topology nothing else is there to.** A
  leaf is configured and read through the node that runs it; an anchor is a peer of every node rather
  than something one of them hosts, and the machine it sits on need run no Control Panel at all. So
  `/auth/config` and `/auth/logs` are served by the daemon being configured and the daemon being read,
  and both are admin-only — a daemon's log is the account store described from the side.
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

## The Discord round trip (`DiscordDirectory`, `OAuthHandshake`)

- **It answers who, and only who.** `DiscordDirectory` is an `IIdentityProvider` and stays the only
  chokepoint to `discord.com`. It takes **one** `KgsmOAuthApplication`, not every provider's, so a
  composition cannot hand it another provider's by accident. It holds no guild, reads no role and
  takes no bot token: what a person may do is the account store's answer, and a login here proves one
  fact — that the caller holds this subject at Discord. `DiscordAuthException` derives from
  `KgsmAuthProviderException` so a caller handles any provider's outage identically.
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
  delete-returning statement. A code presented wrongly is spent; two exchanges racing get one row.
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
  full URLs could make any origin a place codes are sent. An administrator's client of the same id
  wins.
- **A surface's client id is its origin's host** (`ClusterClientAnnouncement.ClientIdFor`), for an
  announced surface and a declared panel alike, so a surface derives its own from where it was loaded
  and is told nothing — which is what lets a panel on a static host sign in through a member that
  never served it.
- **Where the clients live is published, as `auth.origins`, while this anchor holds the accounts.**
  Every member reads it through the holder to admit those origins, so an administrator's client and a
  declared panel — which exist only here — are admitted everywhere without anybody configuring a
  member.
- **A panel on a static host is declared, not stored.** `Anchor__PanelOrigins` is what the deploy said
  this process serves, so it is rebuilt on every start and wins over a stored client of the same id; the
  registry refuses to remove one or to register over it. Its paths are
  `ClusterClientAnnouncement.ControlPanel`, the same statement a node announces its panel with.
- **`id_token`'s subject is the account, its audience the client.** It is never accepted as a bearer,
  and a bearer is never accepted as a sign-out hint.
- **The pages are `kgsm-web-auth`'s documents, served as built.** The anchor writes the provider links
  at the marker and nothing else, reads the files per request, and serves `/ui/` only from under
  `UiPath` — a resolved path outside it is a 404, because this daemon can open its signing key. A
  failed plain form post is answered on the built-in page with the reason: the static document has
  nowhere to put one.
- **The account page is the only place a credential changes, and a change needs a recent proof** —
  the provider session's `credential_at` inside the re-authentication window. Its sign-in is a request
  in flight for the `kgsm-account` pseudo-client, which is never registered and never issued a code.
- **A provider round trip begun to re-prove the person accepts only an identity already attached to
  that account**, resolved and never provisioned. It is recognised by the `state` it began with and
  returns to `/account`; it never mints anything.
