// PermissionsAdmin — the permissions: create them, file catalog actions into them, and see which roles
// hold each.
//
// Editing a permission changes every role holding it, so the rules close one held by a role ranked at
// or above the caller's — each permission is asked about once per version and a closed one says so.

import React from "react";

import { Icon, SettingsSection } from "@thekrystalship/krystal-ui";
import { Locked, RefusalNote, authorityGate, componentOf, roleName, useAuthority, useChecks } from "./kit.jsx";
import { DeleteButton } from "./RolesAdmin.jsx";
import { authorityStore, editRefusal } from "./stores.js";

function PermissionsAdmin() {
  const state = useAuthority();
  const view = state.view;
  const canEdit = !editRefusal("permission.create");

  const permissions = React.useMemo(
    () => (view ? [...view.permissions].sort((a, b) => a.name.localeCompare(b.name)) : []), [view]);
  const probes = React.useMemo(
    () => permissions.map((p) => ({ kind: "permission.actions", permissionId: p.id, actions: p.actions })),
    [permissions]);
  const verdicts = useChecks(probes, probes.map((p) => p.permissionId + ":" + p.actions.join(",")).join("|"));

  const [refusal, setRefusal] = React.useState(null);
  const [name, setName] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [open, setOpen] = React.useState(null);

  const run = async (change) => {
    setBusy(true);
    setRefusal(null);
    const r = await authorityStore.edit(change);
    setBusy(false);
    if (!r.ok) setRefusal(r.refusal);
    return r;
  };

  const gate = authorityGate(state);
  if (gate) return gate;

  return (
    <SettingsSection icon="key-round" title="Permissions" meta={permissions.length + " defined"}>
      <RefusalNote refusal={refusal} />

      {permissions.length === 0 && <div className="access-sub access-sub--empty">No permissions yet.</div>}
      <div className="access-list">
        {permissions.map((p, i) => {
          const verdict = verdicts ? verdicts[i] : null;
          const closed = !canEdit || (verdict && !verdict.allowed);
          return (
            <div key={p.id} className="access-row" data-permission={p.name}>
              <div className="access-row__head">
                <span className="access-row__grip" aria-hidden="true"><Icon name="key-round" size={14} /></span>
                <span className="access-row__name">{p.name}</span>
                <span className="access-row__meta">
                  {p.actions.length} {p.actions.length === 1 ? "action" : "actions"}
                  {p.heldBy.length > 0 && <> · held by {p.heldBy.map((id) => roleName(view, id)).join(", ")}</>}
                </span>
                <Locked result={canEdit ? verdict : null} />
                <span className="access-row__tools">
                  {!closed && (
                    <DeleteButton label={p.name} busy={busy}
                      onDelete={() => run({ kind: "permission.delete", permissionId: p.id })} />
                  )}
                  <button type="button" className="access-link-btn" onClick={() => setOpen(open === p.id ? null : p.id)}>
                    {open === p.id ? "Close" : "Actions"}
                  </button>
                </span>
              </div>
              {open === p.id && (
                <PermissionActions view={view} permission={p} editable={!closed} busy={busy}
                  onRename={(n) => run({ kind: "permission.rename", permissionId: p.id, name: n })}
                  onSave={(actions) => run({ kind: "permission.actions", permissionId: p.id, actions })} />
              )}
            </div>
          );
        })}
      </div>

      {canEdit && (
        <form className="access-create" onSubmit={async (e) => {
          e.preventDefault();
          const n = name.trim();
          if (!n) return;
          const r = await run({ kind: "permission.create", name: n });
          if (r.ok) setName("");
        }}>
          <input className="login-form__input" placeholder="New permission" value={name} aria-label="New permission name"
            disabled={busy} onChange={(e) => setName(e.target.value)} />
          <button type="submit" className="fb-editor__btn" disabled={busy || !name.trim()}>Create permission</button>
        </form>
      )}
    </SettingsSection>
  );
}

// Which actions a permission holds, from every fileable action in the catalog, grouped by component.
// A self action is every active person's already and is not filed anywhere.
function PermissionActions({ view, permission, editable, busy, onRename, onSave }) {
  const [chosen, setChosen] = React.useState(() => new Set(permission.actions));
  const [label, setLabel] = React.useState(permission.name);
  React.useEffect(() => { setChosen(new Set(permission.actions)); }, [permission.actions]);
  React.useEffect(() => { setLabel(permission.name); }, [permission.name]);

  const groups = React.useMemo(() => {
    const by = {};
    view.catalog.filter((a) => !a.self).forEach((a) => { (by[componentOf(a.action)] = by[componentOf(a.action)] || []).push(a); });
    // An action filed here that no member declares any more is still shown, so it can be taken out.
    permission.actions.forEach((id) => {
      if (!view.catalog.some((a) => a.action === id)) {
        (by[componentOf(id)] = by[componentOf(id)] || []).push({ action: id, title: "no longer declared", effect: "", scope: "" });
      }
    });
    return Object.keys(by).sort().map((c) => ({ component: c, actions: by[c].sort((a, b) => a.action.localeCompare(b.action)) }));
  }, [view.catalog, permission.actions]);

  const dirty = chosen.size !== permission.actions.length || permission.actions.some((a) => !chosen.has(a));
  const toggle = (id) => setChosen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <div className="access-sub">
      {editable && (
        <form className="access-create access-create--inline" onSubmit={(e) => {
          e.preventDefault();
          const n = label.trim();
          if (n && n !== permission.name) onRename(n);
        }}>
          <input className="login-form__input" value={label} aria-label="Permission name" disabled={busy}
            onChange={(e) => setLabel(e.target.value)} />
          <button type="submit" className="host-btn host-btn--ghost" disabled={busy || !label.trim() || label.trim() === permission.name}>Rename</button>
        </form>
      )}
      {groups.map((g) => (
        <div key={g.component} className="access-group">
          <div className="access-group__title">{g.component}</div>
          {g.actions.map((a) => (
            <label key={a.action} className="access-check">
              <input type="checkbox" checked={chosen.has(a.action)} disabled={!editable || busy} onChange={() => toggle(a.action)} />
              <span className="access-check__name">{a.title}</span>
              <code className="access-check__id">{a.action}</code>
              {a.scope && <span className="access-check__meta">{a.effect} · {a.scope}</span>}
            </label>
          ))}
        </div>
      ))}
      {editable && (
        <div className="access-sub__foot">
          <button type="button" className="fb-editor__btn" disabled={busy || !dirty} onClick={() => onSave([...chosen])}>
            Save actions
          </button>
        </div>
      )}
    </div>
  );
}

export { PermissionsAdmin };
