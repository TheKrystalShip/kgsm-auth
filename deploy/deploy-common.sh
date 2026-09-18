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

# What this anchor can be configured with, generated from AnchorSettings on every build. The
# `.anchor.json` suffix is what routes it: setup.sh creates the anchors directory and deploy.sh
# installs the file there unprivileged, so the descriptor can never be older than the binary it
# describes — and it never lands where a node's leaves are scanned for.
LEAF_DESCRIPTOR="${REPO_DIR}/deploy/${PROJECT}.anchor.json"

# The id this anchor is known by — the descriptor's "id" and its filename stem in the anchors
# directory.
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

# Serving the names the cluster's DNS anchor gives this anchor: its keys, the site it generates, its proxy
# rules, the include that loads the site, and the grant to reload the web server after writing it. A
# person signs in here directly, so the accounts capability's name is what a browser reaches.
TLS_DIR="/var/lib/kgsm/tls/${PROJECT}"
SITES_DIR="/var/lib/kgsm/nginx"
LOCATIONS_SRC="${REPO_DIR}/deploy/nginx/${PROJECT}.locations"
SITES_INCLUDE_SRC="${REPO_DIR}/deploy/nginx/${PROJECT}.sites.conf"
NGINX_RELOAD_TEMPLATE="${REPO_DIR}/deploy/polkit/47-${PROJECT}-nginx-reload.rules.in"
NGINX_RELOAD_DST="/etc/polkit-1/rules.d/47-${PROJECT}-nginx-reload.rules"

setup_serving() {
    if [[ ! -d /etc/nginx ]]; then
        log "nginx is not installed on this host — this anchor's names are published, and served by nothing here"
        return 0
    fi

    # Keys live here, readable by this component alone; the web server reads them as root.
    if [[ ! -d /var/lib/kgsm/tls ]]; then
        $SUDO install -d -m 0755 -o "$DEPLOY_USER" -g "$DEPLOY_GROUP" /var/lib/kgsm/tls
    fi
    $SUDO install -d -m 0700 -o "$DEPLOY_USER" -g "$DEPLOY_GROUP" "$TLS_DIR"

    # Shared by every component on the machine, each writing and including only its own file. Setgid so
    # a file keeps the directory's group whichever component writes it.
    if [[ ! -d "$SITES_DIR" ]]; then
        log "creating ${SITES_DIR} — the sites KGSM components generate"
        $SUDO install -d -m 2775 -o "$DEPLOY_USER" -g "$DEPLOY_GROUP" "$SITES_DIR"
    fi

    $SUDO install -D -m 0644 -o root -g root "$LOCATIONS_SRC" "/etc/nginx/kgsm/${PROJECT}.locations"
    # This component's own include, one per component, so two components on one machine never claim
    # the same file.
    $SUDO install -m 0644 -o root -g root "$SITES_INCLUDE_SRC" "/etc/nginx/conf.d/00-${PROJECT}-sites.conf"

    local rendered
    rendered="$(mktemp)"
    sed -e "s|@PROJECT@|${PROJECT}|g" -e "s|@SVC_USER@|${DEPLOY_USER}|g" "$NGINX_RELOAD_TEMPLATE" > "$rendered"
    if ! $SUDO cmp -s "$rendered" "$NGINX_RELOAD_DST" 2>/dev/null; then
        log "installing the web-server reload grant → ${NGINX_RELOAD_DST}"
        $SUDO install -D -m 0644 "$rendered" "$NGINX_RELOAD_DST"
    fi
    rm -f "$rendered"
}

setup_project_extras() {
    setup_serving

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

# ── The anchor's own configuration surface ────────────────────────────────────
# This daemon serves the page its configuration is changed on, because nothing else can: a leaf is
# configured through the node that runs it, and an anchor is a peer of every node rather than
# something one of them hosts. Two things have to be in place for a change to take effect, and both
# are installed once by setup.sh:
#
#   the drop-in   feeds the override file back to the unit, ordered after everything else it loads
#   the grant     lets the account the daemon runs as bounce its own unit, and nothing else
#
# The override FILE is not installed by anything — the daemon writes it, unprivileged, in its own
# state directory, and its absence is the normal state of an anchor nobody has changed.
CONFIG_OVERRIDE_FILE="${KGSM_ANCHOR_CONFIG_OVERRIDE:-/var/lib/${PROJECT}/config-override.env}"
CONFIG_DROPIN_TEMPLATE="${REPO_DIR}/deploy/config/50-${PROJECT}-config.conf"
CONFIG_DROPIN_DST="${SYSTEMD_DIR}/${UNITS[0]}.d/50-${PROJECT}-config.conf"
CONFIG_POLKIT_TEMPLATE="${REPO_DIR}/deploy/config/49-${PROJECT}-self-restart.rules.in"
CONFIG_POLKIT_DST="/etc/polkit-1/rules.d/49-${PROJECT}-self-restart.rules"

render_config_dropin() {
    [[ -f "$CONFIG_DROPIN_TEMPLATE" ]] || { err "missing drop-in template: ${CONFIG_DROPIN_TEMPLATE}"; return 1; }
    local rendered
    rendered="$(< "$CONFIG_DROPIN_TEMPLATE")"
    printf '%s\n' "${rendered//@OVERRIDE_FILE@/${CONFIG_OVERRIDE_FILE}}"
}

# The service account, which is what the grant names. render_unit rewrites the unit's User= to the
# deploying user, so under deploy.sh these are one account and this grant restates what the deploy
# grant already allows. It is installed anyway: the two say different things, they are read by
# different templates, and a host where the service account is its own is exactly the host where
# nobody would think to check.
render_config_polkit() {
    [[ -f "$CONFIG_POLKIT_TEMPLATE" ]] || { err "missing polkit template: ${CONFIG_POLKIT_TEMPLATE}"; return 1; }
    local rendered
    rendered="$(< "$CONFIG_POLKIT_TEMPLATE")"
    rendered="${rendered//@SVC_USER@/${DEPLOY_USER}}"
    rendered="${rendered//@UNIT@/${UNITS[0]}}"
    printf '%s\n' "$rendered"
}

SERVICE="${UNITS[0]}"           # the primary unit, e.g. kgsm-api.service
PUBLISH_DIR="${REPO_DIR}/artifacts/publish"

# Where a component's config descriptor lands, and the two are separate directories because leaves and
# anchors are separate things. A LEAF is run by this node: kgsm-api scans the leaves directory, holds
# no list of its own, and a new leaf becomes configurable by landing a file there. An ANCHOR serves one
# capability to the whole cluster and is a peer of every node in it — sharing a machine with one is a
# deployment coincidence — so its descriptor records what runs here and is read by nothing that
# administers this node's services.
#
# Which directory a project uses is decided by the SUFFIX of the descriptor its build produced, and the
# generator refuses a suffix that disagrees with the identity the component declares. So a component
# cannot reach the wrong directory without failing its own build.
LEAF_DESCRIPTOR_DIR="${KGSM_LEAF_DESCRIPTOR_DIR:-/var/lib/kgsm/leaves}"
ANCHOR_DESCRIPTOR_DIR="${KGSM_ANCHOR_DESCRIPTOR_DIR:-/var/lib/kgsm/anchors}"

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

# Where this project's descriptor belongs, from the suffix its build produced. An unrecognised suffix
# is refused rather than guessed at: guessing puts an anchor on some node's service board, which has
# no symptom until somebody reads that board and believes it.
descriptor_dir_for() {
    case "$1" in
        *.anchor.json) printf '%s' "$ANCHOR_DESCRIPTOR_DIR" ;;
        *.leaf.json)   printf '%s' "$LEAF_DESCRIPTOR_DIR" ;;
        *)             return 1 ;;
    esac
}

# Install this project's config descriptor into the discovery directory its kind belongs to.
# Unprivileged: the directory is owned by DEPLOY_USER (setup.sh created it), so this is a plain file
# write.
#
# A project with no descriptor file describes nothing — nothing is installed and nothing fails. When
# the file IS present it is validated before it lands, because a reader skips a malformed one
# silently: catching it here is the difference between "the panel has no page for this" and knowing
# why.
install_leaf_descriptor() {
    [[ -n "${LEAF_DESCRIPTOR:-}" && -f "$LEAF_DESCRIPTOR" ]] || return 0

    local dir
    if ! dir="$(descriptor_dir_for "$LEAF_DESCRIPTOR")"; then
        err "${LEAF_DESCRIPTOR} ends in neither .leaf.json nor .anchor.json, so there is no"
        err "directory it belongs in. The suffix is what says whether this component is one of"
        err "this node's leaves or an anchor serving the whole cluster."
        return 1
    fi

    local dst="${dir}/${LEAF_ID}.json"

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

    if [[ ! -d "$dir" ]]; then
        err "descriptor directory ${dir} is missing."
        err "run ONCE (it will ask for your sudo password):   ${REPO_DIR}/deploy/setup.sh"
        return 1
    fi

    if ! cmp -s "$LEAF_DESCRIPTOR" "$dst"; then
        log "config descriptor changed → ${dst}"
        install -m 0644 "$LEAF_DESCRIPTOR" "$dst"
    fi

    # A component that has changed kind leaves its old file behind, and a stale descriptor in the
    # leaves directory is read as a leaf however the component now describes itself.
    local other
    [[ "$dir" == "$ANCHOR_DESCRIPTOR_DIR" ]] && other="${LEAF_DESCRIPTOR_DIR}/${LEAF_ID}.json" \
                                             || other="${ANCHOR_DESCRIPTOR_DIR}/${LEAF_ID}.json"
    if [[ -f "$other" ]]; then
        log "removing ${other} — this component is described in ${dir}"
        rm -f "$other"
    fi
}
