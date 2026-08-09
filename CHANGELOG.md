# Changelog

All notable changes to `kgsm-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
