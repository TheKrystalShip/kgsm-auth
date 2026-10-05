// access.js — looking an action up in the answers members gave to `GET /me/access`.
//
// Every browser-facing member answers for what it holds: a node for itself and its instances, over
// the actions its own components perform; the auth anchor for `auth:*`, at every scope the caller holds
// a role in; another anchor for its own namespace (`dns:*`, `assistant:*`). Each answer is already evaluated — the caller's effective actions, per target — so this
// module looks things up and decides nothing. It holds no copy of the rules and so cannot disagree with
// them.
//
// A report is `{ version, current, owner, cluster: [...], nodes: {id: [...]}, instances: {key: [...]} }`
// with an instance keyed `<node>/<id>#<nonce>`. `owner` is the one answer a list cannot give: an Owner
// performs actions no manifest declares, which no report can name.
//
// Imports nothing, so a script can load it outside a browser.

// The answer for one member, keyed so the node and anchor answers never collide. An anchor's answer
// is keyed by the action namespace it answers for: `anchor:auth` for the auth anchor, `anchor:dns` and
// `anchor:assistant` for the holders of those capabilities.
const nodeSource = (hostId) => "node:" + hostId;
const anchorSource = (namespace) => "anchor:" + namespace;
const ANCHOR_SOURCE = anchorSource("auth");

// The key a report names an instance by, or null when the server has not said its install nonce: a
// grant on a server is a grant on that install, and without the nonce it cannot be told from a
// reinstall under the same id.
function instanceKey(hostId, serverId, nonce) {
  return hostId && serverId && nonce ? hostId + "/" + serverId + "#" + nonce : null;
}

// A target, from what a caller has in hand. Absent is "anywhere" — the question a nav entry asks.
//   { cluster: true }             cluster-wide only
//   { hostId }                    a node
//   { server }                    a server row (hostId, id, installNonce)
function targetOf(t) {
  if (!t) return { kind: "anywhere" };
  if (t.cluster) return { kind: "cluster" };
  if (t.server) {
    const s = t.server;
    return { kind: "instance", hostId: s.hostId || null, key: instanceKey(s.hostId, s.id, s.installNonce) };
  }
  if (t.hostId) return { kind: "node", hostId: t.hostId };
  return { kind: "anywhere" };
}

const has = (list, action) => Array.isArray(list) && list.indexOf(action) !== -1;

// Whether one report allows `action` at a resolved target.
function reportAllows(r, action, tg) {
  if (!r) return false;
  if (r.owner) return true;
  if (has(r.cluster, action)) return true;
  const nodes = r.nodes || {};
  const instances = r.instances || {};
  switch (tg.kind) {
    case "cluster":
      return false;
    case "node":
      return has(nodes[tg.hostId], action);
    case "instance":
      return (tg.hostId != null && has(nodes[tg.hostId], action)) || (tg.key != null && has(instances[tg.key], action));
    default:
      return Object.keys(nodes).some((k) => has(nodes[k], action))
        || Object.keys(instances).some((k) => has(instances[k], action));
  }
}

// Which members answer for `action` at a target. `auth:*` is the auth anchor's alone. An action whose
// namespace an anchor answers for (`dns:*`, `assistant:*`) is that anchor's, beside the nodes: a
// component standing as a leaf is answered for by its node instead, and both read one authority, so
// either one saying yes is the same yes. Everything else is the node the target is on, or every node
// for a question about anywhere or the cluster.
function answerersOf(sources, action, tg) {
  const namespace = String(action).split(":")[0];
  if (namespace === "auth") return [sources[ANCHOR_SOURCE]];
  const anchor = namespace ? sources[anchorSource(namespace)] : undefined;
  const nodes = tg.hostId
    ? [sources[nodeSource(tg.hostId)]]
    : Object.keys(sources).filter((k) => k.startsWith("node:")).map((k) => sources[k]);
  return anchor ? [anchor, ...nodes] : nodes;
}

// Whether the caller may perform `action` at `target`, by the answers held in `sources`
// (`{ [sourceKey]: { report } }`). A member that has not answered answers nothing.
function allows(sources, action, target) {
  if (!sources || !action) return false;
  const tg = targetOf(target);
  return answerersOf(sources, action, tg).some((s) => !!(s && reportAllows(s.report, action, tg)));
}

// Whether any member says the caller holds everything.
function isOwner(sources) {
  return Object.keys(sources || {}).some((k) => !!(sources[k] && sources[k].report && sources[k].report.owner));
}

// Every action a report set names anywhere, for a surface listing what somebody holds.
function actionsHeld(sources) {
  const out = new Set();
  for (const k of Object.keys(sources || {})) {
    const r = sources[k] && sources[k].report;
    if (!r) continue;
    (r.cluster || []).forEach((a) => out.add(a));
    Object.values(r.nodes || {}).forEach((l) => (l || []).forEach((a) => out.add(a)));
    Object.values(r.instances || {}).forEach((l) => (l || []).forEach((a) => out.add(a)));
  }
  return [...out].sort();
}

export { ANCHOR_SOURCE, actionsHeld, allows, anchorSource, instanceKey, isOwner, nodeSource, reportAllows, targetOf };
