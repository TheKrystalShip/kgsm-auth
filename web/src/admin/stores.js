// stores.js — what the admin pages hold: what the caller may do here, and the authority they
// administer.
//
// **These pages name no action.** A control is gated on the request it would make — the method, the
// path and the body — and the provider says which action that is (`GET /auth/cluster/operations`,
// read by `../lib/operations.js`) and whether this person holds it (`GET /me/access`, read by
// `../lib/access.js`). Nothing here decides access, and nothing here can drift from what the daemon
// enforces.
//
// The authority is one slot shared by every page, read when a page opens and again after every change
// made from here; the version it was read at is what every change names. A change made against an
// older version is refused `409 stale_authority` with the authority as it stands, which is adopted so
// the page redraws on what is now true. Every other refusal is the rules' own — `code`, the provider's
// sentence, and for a subset refusal the actions not held — handed back to the page that asked.

import { createStore } from "@thekrystalship/krystal-ui/lib/store";
import { reportAllows, targetOf } from "../lib/access.js";
import { requirementOf } from "../lib/operations.js";
import { ACCOUNTS, EDITS, api } from "./client.js";

// ── What the caller may do ────────────────────────────────────────────────────

// `state`: loading | ok | refused | unavailable | unreachable. Only `ok` carries a report.
const accessStore = createStore({ state: "loading", report: null, operations: null });

function refreshAccess() {
  return Promise.all([api.me(), api.operations()]).then(
    ([report, operations]) => accessStore.setState({ state: "ok", report, operations }),
    (e) => accessStore.setState({
      state: e.status === 503 ? "unavailable" : e.status === 401 || e.status === 403 ? "refused" : "unreachable",
      report: null, operations: accessStore.getState().operations,
    }));
}

// Where one published entry is checked: the scope it names, made concrete. A request whose scope is
// the request's own — an assignment at a node — is asked at `opts.target`.
function entryTarget(entry, opts) {
  if (opts && opts.anywhere) return null;
  if (entry.scope === "request") return (opts && opts.target) || { cluster: true };
  return { cluster: true };
}

// Why this request may not be made, or null when it may. A provider that has not answered, or a request
// it does not publish, closes the control.
function callRefusal(method, path, opts) {
  const { state, report, operations } = accessStore.getState();
  if (state !== "ok" || !report) return "Not available";
  const req = requirementOf(operations, method, path, opts && opts.body);
  if (!req.published) return "Not offered here";
  for (const e of req.entries) {
    if (!reportAllows(report, e.action, targetOf(entryTarget(e, opts)))) return "Needs " + e.action;
  }
  return null;
}

// Why the caller cannot make an authority edit of `kind` (asked at `target` for an assignment).
const editRefusal = (kind, target) => callRefusal("POST", EDITS, { body: { kind }, target });

// The same question for a request on the accounts: `sub` under the accounts route (`/_` for any one)
// and the body it would carry.
const userRefusal = (method, sub, body) => callRefusal(method, ACCOUNTS + (sub || ""), { body });

// Whether the provider says this person holds every action, declared or not.
const isOwner = () => !!(accessStore.getState().report && accessStore.getState().report.owner);

// Whether this person may change anything here at all — any write the provider publishes, anywhere.
function administers() {
  const { state, report, operations } = accessStore.getState();
  if (state !== "ok" || !report || !operations) return false;
  if (report.owner) return true;
  return (operations.operations || [])
    .some((op) => op.method !== "GET" && reportAllows(report, op.action, targetOf(null)));
}

// ── The authority ─────────────────────────────────────────────────────────────

const authorityStore = createStore({ status: "idle", view: null, error: null });

function refreshAuthority() {
  authorityStore.setState((s) => ({ ...s, status: s.view ? s.status : "loading", error: null }));
  return api.authority.read().then(
    (view) => { authorityStore.setState({ status: "ready", view, error: null }); return view; },
    (error) => { authorityStore.setState((s) => ({ ...s, status: "error", error })); throw error; },
  );
}

// A refusal, in the shape every page shows it.
function refusalOf(e) {
  return {
    code: (e && e.envCode) || null,
    message: (e && e.userMessage) || "The change was refused.",
    actions: (e && e.body && Array.isArray(e.body.actions)) ? e.body.actions : null,
  };
}

// Make one change against the version on screen: `{ ok: true, createdId }` or `{ ok: false, refusal }`,
// never a throw. What the caller may do can move with it — assigning themselves a role, editing a role
// they hold — so their own access is read again too.
function edit(change) {
  const view = authorityStore.getState().view;
  if (!view) return Promise.resolve({ ok: false, refusal: { code: null, message: "Access has not loaded yet.", actions: null } });
  return api.authority.edit(view.version, change).then(
    (result) => {
      refreshAuthority().catch(() => {});
      refreshAccess();
      return { ok: true, createdId: (result && result.createdId) || null };
    },
    (e) => {
      if (e && e.status === 409 && e.body && e.body.authority) {
        authorityStore.setState({ status: "ready", view: e.body.authority, error: null });
      }
      return { ok: false, refusal: refusalOf(e) };
    },
  );
}

// The rules' verdict on edits nobody has made, in order. A failed ask answers nothing rather than
// "allowed", so a page keeps its controls as they were.
function check(edits) {
  if (!edits || !edits.length) return Promise.resolve([]);
  return api.authority.check(edits).catch(() => edits.map(() => null));
}

authorityStore.refresh = refreshAuthority;
authorityStore.edit = edit;
authorityStore.check = check;

// ── The cluster's members ─────────────────────────────────────────────────────

// The members a KGSM cluster names, for a scope's words; empty where this provider holds no cluster.
const membersStore = createStore({ list: [] });

function refreshMembers() {
  return api.members().then((list) => membersStore.setState({ list }), () => membersStore.setState({ list: [] }));
}

export {
  accessStore, administers, authorityStore, callRefusal, editRefusal, isOwner, membersStore,
  refreshAccess, refreshMembers, refusalOf, userRefusal,
};
