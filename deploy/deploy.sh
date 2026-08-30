#!/usr/bin/env bash
#
# deploy.sh — build and deploy the kgsm-auth-anchor daemon. Fully headless: no sudo, no prompts.
#
#   ./deploy/deploy.sh
#
# Assumes deploy/setup.sh has provisioned this host (prefix owned by you, the unit symlinked out of
# a directory you own, polkit grant in place). If it has not, this script says so and stops before
# building. Publishes the Native-AOT binary as YOU — a single self-contained native binary, so the
# host needs no .NET runtime.
#
#   * the binary, its dlopen'd native libs and its settings file go to /opt/kgsm-auth-anchor,
#   * the systemd unit is refreshed only if it changed (a write to a file you own + daemon-reload),
#   * the config descriptor is installed before the swap, so it never lags the binary,
#   * deploy is verified by an actual 200 from GET /health.
#
# The private signing key is NOT touched. It lives in the unit's state directory, is generated once
# on a machine that has none, and every session in the cluster is verified against its public half —
# so a deploy that replaced it would invalidate every session at once.
#
# Knobs: RID, ANCHOR_PORT, HEALTH_TRIES.
#
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/deploy-common.sh"

PROJECT_CSPROJ="$REPO_DIR/src/Auth.Anchor/Anchor.csproj"
RID="${RID:-linux-x64}"

STOPPED=0
on_err() {
    err "deploy failed (line $1)."
    if [[ "$STOPPED" -eq 1 ]]; then
        err "the service was stopped for the swap and may be down — bringing it back up ..."
        if systemctl start "$SERVICE"; then
            err "restarted ${SERVICE} (running the PREVIOUS build)."
        else
            err "could NOT restart ${SERVICE}. Check: systemctl status ${SERVICE}"
        fi
    fi
    exit 1
}
trap 'on_err "$LINENO"' ERR

# ── Preflight ─────────────────────────────────────────────────────────────────
refuse_root
require_setup
[[ -f "$PROJECT_CSPROJ" ]] || { err "project not found: $PROJECT_CSPROJ"; exit 1; }
command -v clang > /dev/null 2>&1 || warn "'clang' not found — Native-AOT publish needs a C toolchain (clang + zlib). Install it if publish fails."

# ── 1. Build (Native-AOT, as the invoking user) ───────────────────────────────
log "publishing Native-AOT (${RID}) → ${PUBLISH_DIR} (ILC compile — this takes a minute)"
rm -rf "$PUBLISH_DIR"
dotnet publish "$PROJECT_CSPROJ" -c Release -r "$RID" -o "$PUBLISH_DIR"

# ── 2. Refresh the unit if it changed (we own the file; systemd reads it via the symlink) ──
install_units_unprivileged

# ── 2b. Publish the config descriptor ─────────────────────────────────────────
# Before the swap, so the surface kgsm-api reads never lags the binary that implements it. The
# publish above regenerated it from the source being deployed, not from whatever was last committed.
install_leaf_descriptor

# ── 3. The swap ───────────────────────────────────────────────────────────────
log "stopping ${SERVICE}"
sysctl_do stop "$SERVICE" || true
STOPPED=1

# --delete prunes what a previous build emitted and this one does not — a stale native lib beside
# the binary is one the daemon would still dlopen. The prefix holds nothing but the publish tree,
# so there is nothing else here to lose: the signing key, the session store and the operator's env
# file all live elsewhere.
log "syncing publish tree → ${PREFIX}"
rsync -a --delete --exclude='*.pdb' --exclude='*.dbg' --exclude='*.xml' "$PUBLISH_DIR/" "$PREFIX/"

if [[ "$UNIT_CHANGED" -eq 1 ]]; then
    log "reloading systemd"
    sysctl_do daemon-reload
fi

log "starting ${SERVICE}"
sysctl_do start "$SERVICE"
STOPPED=0

# ── 4. Verify (an actual 200 from /health) ────────────────────────────────────
log "waiting for ${SERVICE} to report healthy on 127.0.0.1:${ANCHOR_PORT} ..."
if wait_health; then
    log "kgsm-auth-anchor is up and healthy ✓"
    systemctl --no-pager --lines=0 status "$SERVICE" 2>/dev/null | head -n 4 || true
else
    err "service started but GET /health on 127.0.0.1:${ANCHOR_PORT} did not return 200 within ${HEALTH_TRIES}s. Recent logs:"
    journalctl -u "$SERVICE" -n 30 --no-pager || true
    exit 1
fi
