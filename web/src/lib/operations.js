// operations.js — which action a request needs, as the member serving it publishes.
//
// A client names no action. Every member publishes its operations — each gated route, the action it
// requires and the scope it is checked at — built from the metadata it enforces with (kgsm-api's
// `GET /api/v1/operations`, the auth anchor's `GET /auth/cluster/operations`, the DNS anchor's and the
// assistant's `GET /operations`). A control asks about the request it is about to make; this module
// finds the entries that request matches. Whether the caller holds them is `access.js`'s, from the same
// member's `/me/access`.
//
// The document: `{ schemaVersion, base, operations: [{ method, route, action, scope, target?, field?,
// value? }] }`. A route is a template (`/servers/{id}/backups`); a literal segment is more specific than
// a parameter, so `/hosts/{id}/services/kgsm/config` answers for the engine where `{leaf}` answers for
// every other leaf. An entry with a `field` applies when the body carries that field — with that `value`
// when it names one — and every entry a request matches must be held. An `action` may name a route
// parameter (`{leaf}:config.write`), filled from the path.
//
// Imports nothing, so the standalone assistant gates with it too.

const SCHEMA = 1;

function segmentsOf(path) {
  return String(path || "").split("?")[0].split("/").filter(Boolean);
}

// The params a template binds against a path, or null when it does not match.
function bind(template, path) {
  const t = segmentsOf(template);
  const p = segmentsOf(path);
  if (t.length !== p.length) return null;
  const params = {};
  for (let i = 0; i < t.length; i++) {
    const m = /^\{([^}:]+)(:[^}]*)?\}$/.exec(t[i]);
    if (m) params[m[1]] = decodeURIComponent(p[i]);
    else if (t[i].toLowerCase() !== p[i].toLowerCase()) return null;
  }
  return params;
}

const literalCount = (template) => segmentsOf(template).filter((s) => !s.startsWith("{")).length;

function fill(text, params) {
  return String(text).replace(/\{([^}]+)\}/g, (all, name) => (name in params ? params[name] : all));
}

// What a request needs from `manifest`: `{ published, route, params, entries }`, where `entries` are the
// actions (filled) every one of which must be held. `published` is false when the member lists no
// operation at that method and path — a gate the member does not describe, which closes the control.
function requirementOf(manifest, method, path, body) {
  if (!manifest || manifest.schemaVersion !== SCHEMA || !Array.isArray(manifest.operations)) {
    return { published: false, route: null, params: {}, entries: [] };
  }
  const base = manifest.base || "";
  let rel = String(path || "").split("?")[0];
  if (base && rel.toLowerCase().startsWith(base.toLowerCase() + "/")) rel = rel.slice(base.length);
  const verb = String(method || "GET").toUpperCase();

  let best = null;
  for (const op of manifest.operations) {
    if (op.method !== verb) continue;
    const params = bind(op.route, rel);
    if (!params) continue;
    const rank = literalCount(op.route);
    if (!best || rank > best.rank) best = { route: op.route, rank, params };
  }
  if (!best) return { published: false, route: null, params: {}, entries: [] };

  const b = body || {};
  const entries = manifest.operations
    .filter((op) => op.method === verb && op.route === best.route)
    .filter((op) => !op.field
      || (op.value == null ? b[op.field] !== undefined : String(b[op.field]) === op.value))
    .map((op) => ({ action: fill(op.action, best.params), scope: op.scope, target: op.target || null }));

  return { published: entries.length > 0, route: best.route, params: best.params, entries };
}

// Every action a member's document names — for a surface asking whether somebody can do anything at
// all there, never for naming one.
function actionsOf(manifest) {
  if (!manifest || !Array.isArray(manifest.operations)) return [];
  return [...new Set(manifest.operations.map((o) => o.action))];
}

export { actionsOf, bind, requirementOf };
