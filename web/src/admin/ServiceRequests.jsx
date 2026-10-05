// ServiceRequests — what each service account has asked to do as itself, and what was decided.
//
// A component declares the actions it performs on its own behalf; the provider approves each one
// automatically unless it is an `auth:*` action, which waits for a person. A person may approve a
// waiting one, narrow an approved one to a smaller scope, or revoke one — and a revoked requirement
// stays revoked for the account's life. A requirement the component's manifest stops listing is kept
// and grants nothing until it is listed again.

import React from "react";

import { Icon, Select, SettingsSection } from "@thekrystalship/krystal-ui";
import { RefusalNote, authorityGate, useAuthority, useScopeOptions, useScopeText } from "./kit.jsx";
import { authorityStore, editRefusal } from "./stores.js";

const STATE_LABEL = { approved: "Approved", waiting: "Waiting", revoked: "Revoked" };

function ServiceRequests() {
  const state = useAuthority();
  const view = state.view;
  const canManage = !editRefusal("requirement.approve");
  const scopeText = useScopeText();
  const scopes = useScopeOptions(view);
  const [refusal, setRefusal] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  const run = async (change) => {
    setBusy(true);
    setRefusal(null);
    const r = await authorityStore.edit(change);
    setBusy(false);
    if (!r.ok) setRefusal(r.refusal);
  };

  const gate = authorityGate(state);
  if (gate) return gate;

  const services = view.accounts.filter((a) => a.kind === "service")
    .sort((a, b) => a.username.localeCompare(b.username));
  const waiting = services.reduce((n, s) => n + s.requirements.filter((q) => q.state === "waiting").length, 0);

  return (
    <SettingsSection icon="bot" title="Service requests"
      meta={services.length + (services.length === 1 ? " service" : " services") + (waiting ? " · " + waiting + " waiting" : "")}>
      <RefusalNote refusal={refusal} />
      {services.length === 0 && <div className="access-sub access-sub--empty">No service accounts.</div>}
      {services.map((svc) => (
        <div key={svc.id} className="access-group" data-service={svc.username}>
          <div className="access-group__title">
            <Icon name="bot" size={13} /> {svc.username}
            {svc.status !== "active" && <span className="access-pill access-pill--warn">{svc.status}</span>}
          </div>
          {svc.requirements.length === 0 && <div className="access-sub access-sub--empty">Declares nothing.</div>}
          {svc.requirements.map((q) => (
            <Requirement key={q.action} svc={svc} q={q} canManage={canManage} busy={busy}
              scopeText={scopeText} scopes={scopes} run={run} />
          ))}
        </div>
      ))}
    </SettingsSection>
  );
}

function Requirement({ svc, q, canManage, busy, scopeText, scopes, run }) {
  const [scope, setScope] = React.useState(q.grant || "cluster");
  const decided = q.state === "approved" ? (q.decidedBy ? "by " + q.decidedBy : "automatically") : null;
  return (
    <div className="access-action" data-requirement={q.action}>
      <div className="access-action__main">
        <code className="access-check__id">{q.action}</code>
        {q.why && <span className="access-action__why">{q.why}</span>}
      </div>
      <span className={"access-pill access-pill--" + q.state}>{STATE_LABEL[q.state] || q.state}</span>
      <span className="access-action__by">
        {q.state === "approved" ? scopeText(q.grant) + " · " + decided : q.scopeKind}
        {!q.declared && " · no longer declared"}
      </span>
      {canManage && q.state !== "revoked" && (
        <span className="access-row__tools">
          <Select className="access-action__file" value={scope} aria-label={"Scope for " + q.action}
            disabled={busy} onChange={(e) => setScope(e.target.value)}>
            {scopes.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </Select>
          {q.state === "waiting"
            ? <button type="button" className="fb-editor__btn" disabled={busy}
                onClick={() => run({ kind: "requirement.approve", accountId: svc.id, action: q.action, scope })}>Approve</button>
            : <button type="button" className="host-btn host-btn--ghost" disabled={busy || scope === q.grant}
                onClick={() => run({ kind: "requirement.narrow", accountId: svc.id, action: q.action, scope })}>Narrow</button>}
          <button type="button" className="host-btn host-btn--danger" disabled={busy}
            onClick={() => run({ kind: "requirement.revoke", accountId: svc.id, action: q.action })}>Revoke</button>
        </span>
      )}
    </div>
  );
}

export { ServiceRequests };
