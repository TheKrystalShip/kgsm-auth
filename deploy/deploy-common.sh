#!/usr/bin/env bash
#
# deploy-common.sh — the shared parameter block + helpers for this project's deploy scripts.
#
# Sourced by BOTH deploy/setup.sh (the one-shot privileged host provisioning) and
# deploy/deploy.sh (the headless code delivery). Every path, unit name and user lives here
# exactly once, so the two entry points can never disagree about what this project installs.
#
# This file is vendored per repo — each kgsm-* repo carries its own copy so a standalone clone
# deploys with no umbrella checkout present. The canonical source is
# tks/scripts/deploy-template/; edit the PROJECT BLOCK below and leave the rest alone.
#
# Not executable on its own.

# This file only DEFINES things; every variable below is consumed by the two scripts that
# source it, which shellcheck cannot see from here.
# shellcheck disable=SC2034

set -euo pipefail

# ── Identity (needed by the project block below) ──────────────────────────────
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The user that owns the install and runs the service. Everything is provisioned FOR this
# user so that day-to-day deploys need no privilege at all.
DEPLOY_USER="${KGSM_DEPLOY_USER:-$(id -un)}"
DEPLOY_GROUP="${KGSM_DEPLOY_GROUP:-$(id -gn)}"

# ── PROJECT BLOCK — the only part that changes per repo ───────────────────────
# The repo is kgsm-auth and the unit is kgsm-auth-anchor: this repo's other output is a set of
# libraries every surface compiles against, and the daemon is one thing built from them.
PROJECT="kgsm-auth-anchor"

UNITS=("${PROJECT}.service")
ENABLE_UNITS=("${PROJECT}.service")

PREFIX="/opt/${PROJECT}"

# Operator config. The unit's Environment= lines carry working defaults and this file only
# overrides them, so it is seeded entirely commented out. setup.sh writes it once and never again;
# the unit reads it with EnvironmentFile=-, so deleting it is also a supported way to say "no
# overrides".
ENV_DIR="/etc/${PROJECT}"
ENV_FILE="${ENV_DIR}/${PROJECT}.env"
ENV_EXAMPLE="${REPO_DIR}/deploy/${PROJECT}.env.example"

HEALTH_TRIES="${HEALTH_TRIES:-30}"

# The config descriptor kgsm-api reads to render this anchor's configuration page. setup.sh creates
# the discovery directory; deploy.sh installs the file there unprivileged on every deploy, so the
# descriptor can never be older than the binary it describes.
LEAF_DESCRIPTOR="${REPO_DIR}/deploy/${PROJECT}.leaf.json"

# The id kgsm-api knows this project by — the descriptor's "id", its filename stem in the discovery
# directory, and the {leaf} segment of the API's config route.
LEAF_ID="auth-anchor"

render_unit() {   # $1 = unit filename
    sed "s/^User=.*/User=${DEPLOY_USER}/; s/^Group=.*/Group=${DEPLOY_GROUP}/" \
        "${REPO_DIR}/deploy/$1"
}

# Health is HTTP on the port the unit's Anchor__ListenAddress binds. Probed on the loopback
# whatever the unit binds to, because what is being proven is that this daemon serves — not that a
# firewall lets somebody else reach it.
ANCHOR_PORT="${ANCHOR_PORT:-8098}"
health_probe() {
    curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:${ANCHOR_PORT}/health" 2>/dev/null
}

# What several members of a cluster on one machine share, and the directory this anchor publishes its
# verification key into. A package host gets it from kgsm-base's tmpfiles fragment, which is where it
# belongs — it is written by several packages and owned by none of them. A host provisioned from a
# checkout has no kgsm-base, so it is created here on the same terms: created if absent, never
# re-owned if it is already there, because a machine that has the package has a directory whose
# ownership is that package's answer and not this one's.
CLUSTER_SHARED_DIR="${KGSM_CLUSTER_SHARED_DIR:-/var/lib/kgsm/cluster}"

# This anchor's own nginx server block, if the host runs nginx as its public multiplexer. A person
# signs in here directly, so unlike a leaf it needs a name a browser can reach. The :80 ACME block and
# the certificate lifecycle stay host-level: a component that claimed those would make every other one
# on the box depend on it. Skipped cleanly where nginx is not installed.
NGINX_FRAGMENT="${REPO_DIR}/deploy/nginx/${PROJECT}.conf"

setup_project_extras() {
    if [[ -n "${NGINX_FRAGMENT:-}" && -f "$NGINX_FRAGMENT" && -d /etc/nginx/conf.d ]]; then
        log "installing the nginx vhost → /etc/nginx/conf.d/$(basename "$NGINX_FRAGMENT")"
        $SUDO install -m 0644 -o root -g root "$NGINX_FRAGMENT" "/etc/nginx/conf.d/$(basename "$NGINX_FRAGMENT")"
        # Validated before reloading: a bad fragment must fail here, loudly, rather than at the next
        # reload for an unrelated reason — by which point nobody would connect the two.
        if $SUDO nginx -t > /dev/null 2>&1; then
            $SUDO systemctl reload nginx 2>/dev/null || true
        else
            warn "nginx -t failed after installing the fragment — NOT reloading; run 'sudo nginx -t' to see why"
        fi
    elif [[ -n "${NGINX_FRAGMENT:-}" && -f "$NGINX_FRAGMENT" ]]; then
        log "nginx is not installed on this host — skipping the vhost fragment"
    fi

    if [[ -d "$CLUSTER_SHARED_DIR" ]]; then
        log "shared cluster directory ${CLUSTER_SHARED_DIR} already exists — leaving its ownership alone"
        return 0
    fi
    log "creating ${CLUSTER_SHARED_DIR} (owned by ${DEPLOY_USER}) — what members on this machine share"
    $SUDO install -d -m 0755 -o "$DEPLOY_USER" -g "$DEPLOY_GROUP" "$CLUSTER_SHARED_DIR"
}
# ── END PROJECT BLOCK ─────────────────────────────────────────────────────────

# ── Derived paths (do not edit) ───────────────────────────────────────────────
# Where the REAL unit files live: a user-owned directory beside the project's config. systemd
# reaches them through a symlink at /etc/systemd/system/<unit> that setup.sh plants once. This
# is what lets deploy.sh update a unit with no sudo — it writes a file it owns, then asks
# systemd (via the polkit grant) to re-read it.
UNIT_DIR="${ENV_DIR}/systemd"
SYSTEMD_DIR="/etc/systemd/system"

# The polkit grant setup.sh installs: lets DEPLOY_USER drive systemctl for THIS project's units
# with no password and no interactive auth agent.
POLKIT_DST="/etc/polkit-1/rules.d/48-${PROJECT}-deploy.rules"

# The polkit rule's CONTENT is a committed file, not a heredoc, so what the host grants can be
# read and reviewed without running anything. Only the deploying user and the unit list cannot be
# known until install time, and those are the template's two placeholders.
POLKIT_TEMPLATE="${REPO_DIR}/deploy/polkit/48-${PROJECT}-deploy.rules.in"

render_polkit_rule() {
    [[ -f "$POLKIT_TEMPLATE" ]] || { err "missing polkit template: ${POLKIT_TEMPLATE}"; return 1; }

    local units_js="" u
    for u in "${UNITS[@]}"; do
        units_js+="        \"${u}\": true,"$'\n'
    done
    units_js="${units_js%$'\n'}"

    local rendered
    rendered="$(< "$POLKIT_TEMPLATE")"
    rendered="${rendered//@PROJECT@/${PROJECT}}"
    rendered="${rendered//@DEPLOY_USER@/${DEPLOY_USER}}"
    rendered="${rendered//@UNITS@/${units_js}}"
    printf '%s\n' "$rendered"
}

SERVICE="${UNITS[0]}"           # the primary unit, e.g. kgsm-api.service
PUBLISH_DIR="${REPO_DIR}/artifacts/publish"

# Where every leaf drops its config descriptor. Shared across projects and scanned by kgsm-api —
# the API holds no list of leaves, so a new leaf becomes configurable by landing a file here.
LEAF_DESCRIPTOR_DIR="${KGSM_LEAF_DESCRIPTOR_DIR:-/var/lib/kgsm/leaves}"

# Privileged-call indirection, used by setup.sh ONLY. deploy.sh never calls this. An automated
# run can set SUDO='sudo -A' + SUDO_ASKPASS=… to provision without an interactive prompt; no
# password is ever stored in the repo.
SUDO="${SUDO:-sudo}"

# ── Output helpers ────────────────────────────────────────────────────────────
log()  { printf '\033[1;34m>> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m** %s\033[0m\n' "$*" >&2; }
err()  { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; }

# ── Shared preflight ──────────────────────────────────────────────────────────

# Refuse to run as root. Both entry points build/publish as the invoking user so the source
# tree never gains root-owned obj/bin, and setup.sh templates the grants with a real user.
refuse_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        err "do NOT run this as root — run it as the service-owning user."
        err "setup.sh sudo's the few steps that need it; deploy.sh needs no privilege at all."
        exit 1
    fi
}

# The contract deploy.sh enforces before it touches anything: this host has been provisioned.
# A missing piece means setup.sh has not run (or has been undone) — say so and stop, rather
# than half-deploying or blocking on a password prompt that will never be answered.
require_setup() {
    local u problem=0

    [[ -d "$PREFIX" && -w "$PREFIX" ]] || {
        err "install prefix ${PREFIX} is missing or not writable by $(id -un)."; problem=1; }
    [[ -d "$UNIT_DIR" && -w "$UNIT_DIR" ]] || {
        err "unit directory ${UNIT_DIR} is missing or not writable by $(id -un)."; problem=1; }

    for u in "${UNITS[@]}"; do
        if [[ ! -L "${SYSTEMD_DIR}/${u}" ]]; then
            err "${SYSTEMD_DIR}/${u} is not a symlink into ${UNIT_DIR}."; problem=1
        elif [[ "$(readlink -f "${SYSTEMD_DIR}/${u}")" != "${UNIT_DIR}/${u}" ]]; then
            err "${SYSTEMD_DIR}/${u} points at $(readlink "${SYSTEMD_DIR}/${u}"), not ${UNIT_DIR}/${u}."
            problem=1
        fi
    done

    if [[ "$problem" -ne 0 ]]; then
        err ""
        err "this host is not provisioned for headless deploys of ${PROJECT}."
        err "run ONCE (it will ask for your sudo password):   ${REPO_DIR}/deploy/setup.sh"
        exit 1
    fi
}

# systemctl, unprivileged, via the polkit grant setup.sh installed. A denial here means the
# grant is missing — surface that as the actionable thing it is instead of a raw polkit error.
sysctl_do() {   # $@ = systemctl arguments
    # --no-ask-password: this path must fail fast rather than block on a prompt nobody will answer.
    if ! systemctl --no-ask-password "$@"; then
        err "systemctl $* was refused."
        err "the polkit grant for ${DEPLOY_USER} is missing or does not cover this unit."
        err "re-run: ${REPO_DIR}/deploy/setup.sh"
        return 1
    fi
}

# Poll health_probe until it passes. Used inside an `if`, so a failing probe never trips ERR.
wait_health() {
    local i
    for ((i = 1; i <= HEALTH_TRIES; i++)); do
        health_probe && return 0
        sleep 1
    done
    return 1
}

# Write the rendered units into UNIT_DIR (which we own — no privilege). Sets UNIT_CHANGED=1
# when any unit's content actually changed, so the caller can daemon-reload only when needed.
UNIT_CHANGED=0
install_units_unprivileged() {
    local u tmp
    UNIT_CHANGED=0
    for u in "${UNITS[@]}"; do
        tmp="$(mktemp)"
        render_unit "$u" > "$tmp"
        if ! cmp -s "$tmp" "${UNIT_DIR}/${u}"; then
            log "unit changed → ${UNIT_DIR}/${u}"
            install -m 0644 "$tmp" "${UNIT_DIR}/${u}"
            UNIT_CHANGED=1
        fi
        rm -f "$tmp"
    done
}

# Install this project's leaf config descriptor into the shared discovery directory. Unprivileged:
# the directory is owned by DEPLOY_USER (setup.sh created it), so this is a plain file write.
#
# A project with no descriptor file is simply not a leaf — nothing is installed and nothing fails.
# When the file IS present the descriptor is validated before it lands, because kgsm-api skips a
# malformed one silently: catching it here is the difference between "the panel has no page for
# this leaf" and knowing why.
install_leaf_descriptor() {
    [[ -n "${LEAF_DESCRIPTOR:-}" && -f "$LEAF_DESCRIPTOR" ]] || return 0

    local dst="${LEAF_DESCRIPTOR_DIR}/${LEAF_ID}.json"

    # Validate what we can before it lands: it must parse, and its "id" must be the id this
    # project deploys under — a mismatch would install the file under a name kgsm-api then reads
    # back as a different leaf.
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 - "$LEAF_DESCRIPTOR" "$LEAF_ID" <<'PY'
import json, sys
path, want = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(path))
except Exception as e:
    sys.exit(f"{path} is not valid JSON: {e}")
if d.get("id") != want:
    sys.exit(f"{path} declares id={d.get('id')!r}, but this project deploys leaf id {want!r}.")
PY
        then
            err "refusing to install the leaf descriptor — kgsm-api would skip it and the"
            err "Control Panel would show no configuration for ${PROJECT}."
            return 1
        fi
    fi

    if [[ ! -d "$LEAF_DESCRIPTOR_DIR" ]]; then
        err "leaf descriptor directory ${LEAF_DESCRIPTOR_DIR} is missing."
        err "run ONCE (it will ask for your sudo password):   ${REPO_DIR}/deploy/setup.sh"
        return 1
    fi

    if ! cmp -s "$LEAF_DESCRIPTOR" "$dst"; then
        log "leaf descriptor changed → ${dst}"
        install -m 0644 "$LEAF_DESCRIPTOR" "$dst"
    fi
}
