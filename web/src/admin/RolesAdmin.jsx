// RolesAdmin — the roles in rank order: create, rename, rank by dragging, delete, and the permissions
// each one holds.
//
// Owner is first and locked: it holds every action and is edited by nobody. `everyone` is last among
// the people's roles and holds what every active person holds; its permissions are edited like any
// role's. A role a service account is given is a service's own and is not listed here.
//
// Each custom role is asked about once per version — "may I set this role's permissions to what they
// are?" — and a role the rules close is shown with the provider's reason rather than left clickable.

import React from "react";

import { Icon, SettingsSection } from "@thekrystalship/krystal-ui";
import { Locked, RefusalNote, authorityGate, useAuthority, useChecks } from "./kit.jsx";
import { authorityStore, editRefusal } from "./stores.js";

const PEOPLES = new Set(["owner", "custom", "everyone"]);

function RolesAdmin() {
  const state = useAuthority();
  const view = state.view;
  const canEdit = !editRefusal("role.create");

  const roles = React.useMemo(
    () => (view ? view.roles.filter((r) => PEOPLES.has(r.kind)).sort((a, b) => a.rank - b.rank) : []),
    [view]);
  const custom = roles.filter((r) => r.kind === "custom");

  // One probe per editable role, so each row can say why it is closed.
  const probes = React.useMemo(
    () => roles.filter((r) => r.kind !== "owner")
      .map((r) => ({ kind: "role.permissions", roleId: r.id, permissionIds: r.permissions })),
    [roles]);
  const verdicts = useChecks(probes, probes.map((p) => p.roleId + ":" + p.permissionIds.join(",")).join("|"));
  const verdictOf = (id) => {
    const i = probes.findIndex((p) => p.roleId === id);
    return verdicts && i >= 0 ? verdicts[i] : null;
  };

  const [refusal, setRefusal] = React.useState(null);
  const [name, setName] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [open, setOpen] = React.useState(null);
  const [dragging, setDragging] = React.useState(null);

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

  const create = async () => {
    const n = name.trim();
    if (!n) return;
    const r = await run({ kind: "role.create", name: n });
    if (r.ok) setName("");
  };

  // Ranks are positions among the custom roles, the first being 1.
  const moveTo = (roleId, index) => run({ kind: "role.rank", roleId, rank: index + 1 });

  return (
    <SettingsSection icon="shield" title="Roles" meta={custom.length + " made here"}>
      <RefusalNote refusal={refusal} />

      <div className="access-list">
        {roles.map((role) => {
          const verdict = role.kind === "owner" ? null : verdictOf(role.id);
          const closed = role.kind === "owner" || !canEdit || (verdict && !verdict.allowed);
          const index = custom.findIndex((c) => c.id === role.id);
          const draggable = role.kind === "custom" && !closed && !busy;
          return (
            <div key={role.id}
              className={"access-row" + (dragging === role.id ? " access-row--dragging" : "")}
              data-role={role.name}
              draggable={draggable}
              onDragStart={() => setDragging(role.id)}
              onDragEnd={() => setDragging(null)}
              onDragOver={(e) => { if (dragging && role.kind === "custom") e.preventDefault(); }}
              onDrop={(e) => {
                e.preventDefault();
                if (dragging && dragging !== role.id && index >= 0) moveTo(dragging, index);
                setDragging(null);
              }}>
              <div className="access-row__head">
                <span className="access-row__grip" aria-hidden="true">
                  {draggable ? <Icon name="grip-vertical" size={14} /> : <Icon name={role.kind === "owner" ? "crown" : "shield"} size={14} />}
                </span>
                <RoleName role={role} editable={role.kind === "custom" && !closed} busy={busy}
                  onRename={(n) => run({ kind: "role.rename", roleId: role.id, name: n })} />
                <span className="access-row__meta">
                  {role.kind === "owner" ? "every action"
                    : role.permissions.length + (role.permissions.length === 1 ? " permission" : " permissions")}
                </span>
                {role.kind !== "owner" && <Locked result={canEdit ? verdict : null} />}
                <span className="access-row__tools">
                  {role.kind === "custom" && !closed && (
                    <>
                      <button type="button" className="access-icon-btn" aria-label={"Move " + role.name + " up"}
                        disabled={busy || index <= 0} onClick={() => moveTo(role.id, index - 1)}>
                        <Icon name="chevron-up" size={14} />
                      </button>
                      <button type="button" className="access-icon-btn" aria-label={"Move " + role.name + " down"}
                        disabled={busy || index >= custom.length - 1} onClick={() => moveTo(role.id, index + 1)}>
                        <Icon name="chevron-down" size={14} />
                      </button>
                      <DeleteButton label={role.name} busy={busy}
                        onDelete={() => run({ kind: "role.delete", roleId: role.id })} />
                    </>
                  )}
                  {role.kind !== "owner" && (
                    <button type="button" className="access-link-btn" onClick={() => setOpen(open === role.id ? null : role.id)}>
                      {open === role.id ? "Close" : "Permissions"}
                    </button>
                  )}
                </span>
              </div>
              {open === role.id && (
                <RolePermissions view={view} role={role} editable={!closed} busy={busy}
                  onSave={(ids) => run({ kind: "role.permissions", roleId: role.id, permissionIds: ids })} />
              )}
            </div>
          );
        })}
      </div>

      {canEdit && (
        <form className="access-create" onSubmit={(e) => { e.preventDefault(); create(); }}>
          <input className="login-form__input" placeholder="New role" value={name} aria-label="New role name"
            disabled={busy} onChange={(e) => setName(e.target.value)} />
          <button type="submit" className="fb-editor__btn" disabled={busy || !name.trim()}>Create role</button>
        </form>
      )}
    </SettingsSection>
  );
}

// A role's name, renamed in place.
function RoleName({ role, editable, busy, onRename }) {
  const [editing, setEditing] = React.useState(false);
  const [value, setValue] = React.useState(role.name);
  React.useEffect(() => { setValue(role.name); }, [role.name]);
  if (!editing) {
    return (
      <span className="access-row__name">
        {role.name}
        {editable && (
          <button type="button" className="access-icon-btn" aria-label={"Rename " + role.name} onClick={() => setEditing(true)}>
            <Icon name="pencil" size={12} />
          </button>
        )}
      </span>
    );
  }
  const save = async () => {
    const n = value.trim();
    if (!n || n === role.name) { setEditing(false); return; }
    const r = await onRename(n);
    if (r.ok) setEditing(false);
  };
  return (
    <form className="access-row__name access-row__name--editing" onSubmit={(e) => { e.preventDefault(); save(); }}>
      <input className="login-form__input" value={value} autoFocus disabled={busy} aria-label="Role name"
        onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => { if (e.key === "Escape") setEditing(false); }} />
      <button type="submit" className="access-icon-btn" aria-label="Save name" disabled={busy}><Icon name="check" size={13} /></button>
    </form>
  );
}

// Delete, asked twice.
function DeleteButton({ label, busy, onDelete }) {
  const [armed, setArmed] = React.useState(false);
  if (!armed) {
    return (
      <button type="button" className="access-icon-btn access-icon-btn--danger" aria-label={"Delete " + label}
        disabled={busy} onClick={() => setArmed(true)}>
        <Icon name="trash-2" size={13} />
      </button>
    );
  }
  return (
    <span className="access-confirm">
      <button type="button" className="host-btn host-btn--danger" disabled={busy}
        onClick={() => { setArmed(false); onDelete(); }}>Delete {label}</button>
      <button type="button" className="host-btn host-btn--ghost" onClick={() => setArmed(false)}>Keep</button>
    </span>
  );
}

// The permissions a role holds, as a checklist of every permission there is.
function RolePermissions({ view, role, editable, busy, onSave }) {
  const [chosen, setChosen] = React.useState(() => new Set(role.permissions));
  React.useEffect(() => { setChosen(new Set(role.permissions)); }, [role.permissions]);
  const dirty = chosen.size !== role.permissions.length || role.permissions.some((p) => !chosen.has(p));
  const toggle = (id) => setChosen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  if (!view.permissions.length) return <div className="access-sub access-sub--empty">No permissions exist yet.</div>;
  return (
    <div className="access-sub">
      {view.permissions.map((p) => (
        <label key={p.id} className="access-check">
          <input type="checkbox" checked={chosen.has(p.id)} disabled={!editable || busy} onChange={() => toggle(p.id)} />
          <span className="access-check__name">{p.name}</span>
          <span className="access-check__meta">{p.actions.length} {p.actions.length === 1 ? "action" : "actions"}</span>
        </label>
      ))}
      {editable && (
        <div className="access-sub__foot">
          <button type="button" className="fb-editor__btn" disabled={busy || !dirty} onClick={() => onSave([...chosen])}>
            Save permissions
          </button>
        </div>
      )}
    </div>
  );
}

export { DeleteButton, RolesAdmin };
