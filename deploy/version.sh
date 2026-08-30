#!/usr/bin/env bash
#
# version.sh — print this project's packaging version.
#
#   ./deploy/version.sh            # the version as declared
#   ./deploy/version.sh --pkgver   # the same, in a form pacman accepts
#
# The version is declared in exactly ONE place and read from there, so the package, the binary and
# the changelog can never disagree about what this is.
#
# This repo publishes four NuGet packages beside the daemon, each versioning on its own schedule.
# The package ships the DAEMON, so this points at the daemon's csproj and the two can never be
# confused for one another.

# A pacman pkgver may not contain a hyphen, so --pkgver strips it. That keeps prerelease ordering
# correct under vercmp: 3.16.0rc3 < 3.16.0rc4 < 3.16.0.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_FILE="${HERE}/../src/Auth.Anchor/Anchor.csproj"

read_version() {
    grep -oP '<Version>\K[0-9][^<]*(?=</Version>)' "$SOURCE_FILE" | head -1
}

raw="$(read_version || true)"
[[ -n "$raw" ]] || { printf 'version.sh: no version found in %s\n' "$SOURCE_FILE" >&2; exit 1; }

case "${1:-}" in
    "")       printf '%s\n' "$raw" ;;
    --pkgver) printf '%s\n' "${raw//-/}" ;;
    *)        printf 'usage: version.sh [--pkgver]\n' >&2; exit 1 ;;
esac
