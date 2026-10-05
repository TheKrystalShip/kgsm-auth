// kit.jsx — what the admin pages share: reading the authority, asking the rules about edits nobody has
// made, showing a refusal, and naming a scope.
//
// Every page gates its controls on the request they would make (`stores.js`) and shows a control the
// rules would refuse with the rules' own reason beside it, rather than hiding it. The reason is the
// provider's: `authorityStore.check` runs the same rules an edit meets and writes nothing.

import React from "react";

import { Icon, useStore } from "@thekrystalship/krystal-ui";
import { authorityStore, membersStore } from "./stores.js";

// The authority, read when the first page wanting it mounts and kept for the rest.
function useAuthority() {
  const state = useStore(authorityStore);
  React.useEffect(() => { authorityStore.refresh().catch(() => {}); }, []);
  return state;
}

// The rules' verdicts on `edits`, re-asked whenever `key` or the authority's version moves. Null
// until answered, and a null entry for an edit the provider could not be asked about.
function useChecks(edits, key) {
  const version = useStore(authorityStore, (s) => (s.view ? s.view.version : null));
  const [results, setResults] = React.useState(null);
  const ref = React.useRef(edits);
  ref.current = edits;
  React.useEffect(() => {
    let cancelled = false;
    if (version == null) return undefined;
    authorityStore.check(ref.current).then((r) => { if (!cancelled) setResults(r); });
    return () => { cancelled = true; };
  }, [key, version]);
  return results;
}

// A refusal beside the control it is about. `reauth_required` is the one a person can clear here: the
// account page, opened at `#confirm`, asks for their credential, and the change can be made again.
function RefusalNote({ refusal, compact }) {
  if (!refusal) return null;
  const reauth = refusal.code === "reauth_required";
  return (
    <div className={"access-refusal" + (compact ? " access-refusal--compact" : "")} role="alert">
      <Icon name={reauth ? "key-round" : "lock"} size={13} />
      <span>
        {refusal.message}
        {refusal.actions && refusal.actions.length > 0 && (
          <> <span className="access-refusal__actions">{refusal.actions.join(", ")}</span></>
        )}
      </span>
      {reauth && (
        <a className="access-refusal__link" href="/account#confirm" target="_blank" rel="noreferrer">Prove it’s you</a>
      )}
    </div>
  );
}

// A lock and its reason, for a row the rules close.
function Locked({ result }) {
  if (!result || result.allowed) return null;
  return (
    <span className="access-lock" title={result.message || ""}>
      <Icon name="lock" size={12} />
      <span className="access-lock__text">{result.message}</span>
    </span>
  );
}

// `instance:<node>/<id>#<nonce>` → its parts, or null.
function parseInstance(scope) {
  const m = /^instance:([^/]+)\/([^#]+)#(.+)$/.exec(scope || "");
  return m ? { hostId: m[1], serverId: m[2], nonce: m[3] } : null;
}

// What a link into these pages said a scope is called — a server's name, which this provider holds no
// record of — kept for as long as the tab is open.
const scopeLabels = new Map();
function nameScope(scope, label) {
  if (scope && label) scopeLabels.set(scope, label);
}

// A node by the name the cluster gives it, or its id.
function nodeName(hostId, members) {
  const m = (members || []).find((x) => x.memberId === hostId);
  return (m && m.nickname) || hostId;
}

// A scope in words: everywhere, a node by its name, a server by its name and node.
function useScopeText() {
  const members = useStore(membersStore, (s) => s.list);
  return React.useCallback((scope) => {
    if (!scope || scope === "cluster") return "Everywhere";
    if (scope.startsWith("node:")) return nodeName(scope.slice(5), members);
    const inst = parseInstance(scope);
    if (!inst) return scope;
    return (scopeLabels.get(scope) || inst.serverId) + " on " + nodeName(inst.hostId, members);
  }, [members]);
}

// Every scope an assignment can be made at: everywhere, each node the cluster names or a grant
// mentions, and each server a grant or a link has named — a grant names the install, and one without
// its nonce cannot be made.
function useScopeOptions(view, extra) {
  const members = useStore(membersStore, (s) => s.list);
  const text = useScopeText();
  return React.useMemo(() => {
    const scopes = new Set();
    (members || []).filter((m) => m.kind === "node").forEach((m) => scopes.add("node:" + m.memberId));
    if (view) {
      view.assignments.forEach((a) => scopes.add(a.scope));
      view.accounts.forEach((a) => (a.requirements || []).forEach((q) => { if (q.grant) scopes.add(q.grant); }));
    }
    if (extra) scopes.add(extra);
    scopes.delete("cluster");
    const label = (s) => (s.startsWith("node:") ? "Node · " : "Server · ") + text(s);
    return [
      { value: "cluster", label: "Everywhere" },
      ...[...scopes].filter((s) => s.startsWith("node:") || parseInstance(s))
        .sort((a, b) => label(a).localeCompare(label(b)))
        .map((s) => ({ value: s, label: label(s) })),
    ];
  }, [members, view, extra, text]);
}

// The component an action belongs to: the part before the colon.
const componentOf = (action) => String(action || "").split(":")[0];

// A role's name as a person reads it.
function roleName(view, id) {
  const r = view && view.roles.find((x) => x.id === id);
  return r ? r.name : id;
}

// The pages' shared empty states.
function Brief({ title, sub }) {
  return (
    <div className="chat-brief">
      <div className="chat-brief__empty chat-brief__empty--neutral">
        <div className="chat-brief__empty-title">{title}</div>
        {sub && <div className="chat-brief__empty-sub">{sub}</div>}
      </div>
    </div>
  );
}

// What a page renders while the authority is not in hand, or null once it is.
function authorityGate(state) {
  if (state.view) return null;
  if (state.status === "error") {
    const e = state.error;
    if (e && e.status === 403) return <Brief title="You don’t have access to this" sub={e.userMessage} />;
    return <Brief title="Couldn’t read access" sub={(e && e.userMessage) || null} />;
  }
  return <Brief title="Loading…" />;
}

export {
  Brief, Locked, RefusalNote, authorityGate, componentOf, nameScope, parseInstance, roleName,
  useAuthority, useChecks, useScopeOptions, useScopeText,
};
