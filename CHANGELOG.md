# Changelog

All notable changes to `kgsm-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
