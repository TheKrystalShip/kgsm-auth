// AccountsAdmin — the accounts somebody may sign in with, where each stands, and the roles each holds
// at which scope.
//
// An account is the primary identity object: it exists on its own, and an external provider (Discord
// today, others later) is a credential attached to it rather than the source of it. What an account
// may do is the roles assigned to it — each everywhere, at a node or on one server — plus what
// `everyone` holds; approving somebody makes them active holding only that, and assigning a role is
// the next, separate act.
//
// Read straight from the provider rather than through a store: accounts change only when somebody
// changes them here, and a cached list is a list that can be stale about who may sign in. Each write
// re-reads. The roles come from the authority (`authorityStore`), which only somebody administering
// some of it may read; without it the rows show no roles rather than claiming there are none.
//
// Every control is gated on the request it would make and every refusal is the provider's sentence.

import React from "react";

import { Icon, Modal, Select, SettingsSection, useStore } from "@thekrystalship/krystal-ui";
import { when } from "../lib/formatting.js";
import { Assignments } from "./Assignments.jsx";
import { ConfirmRevokeDialog } from "./ConfirmRevokeDialog.jsx";
import { api } from "./client.js";
import { Brief, RefusalNote, roleName } from "./kit.jsx";
import { accessStore, administers, authorityStore, refusalOf, userRefusal } from "./stores.js";

const STATUS_LABEL = { active: "Active", pending: "Awaiting approval", disabled: "Disabled" };

// The providers an account signs in with, from the credential handles it holds (`provider:subject`).
const providersOf = (u) => (u.identities || []).map((i) => (typeof i === "string" ? i.split(":")[0] : i.provider));

function AccountsAdmin() {
  // Re-rendered when the caller's own access moves, which is what every gate below reads.
  useStore(accessStore, (s) => s.report);
  // Checked before asking, because a table that 403s tells the reader less than a sentence naming what
  // they would need.
  const allowed = administers();

  const [rows, setRows] = React.useState(null);          // null = not loaded yet
  const [refusal, setRefusal] = React.useState(null);
  const [editing, setEditing] = React.useState(null);    // a user row, or "new"
  const view = useStore(authorityStore, (s) => s.view);

  const reload = React.useCallback(() => {
    if (!allowed) return Promise.resolve();
    setRefusal(null);
    authorityStore.refresh().catch(() => {});
    return api.users.list().then(
      (list) => setRows(list),
      (e) => { setRows([]); setRefusal(refusalOf(e)); });
  }, [allowed]);

  React.useEffect(() => { reload(); }, [reload]);

  // Approve in place: the account becomes active holding what `everyone` holds, and nothing more.
  const [approving, setApproving] = React.useState(null);
  const approve = (u) => {
    setApproving(u.id);
    setRefusal(null);
    api.users.update(u.id, { status: "active" }).then(
      () => reload().then(() => setApproving(null)),
      (e) => { setRefusal(refusalOf(e)); setApproving(null); });
  };

  if (!allowed) return <Brief title="You don’t have access to this" />;

  const canApprove = !userRefusal("PATCH", "/_", { status: "active" });
  const canCreate = !userRefusal("POST", "");
  const waiting = (rows || []).filter((u) => u.status === "pending").length;
  // People waiting first. They are the only rows on this screen that need something done, and a list
  // of twenty accounts would otherwise bury them.
  const ordered = [...(rows || [])].sort(
    (a, b) => (a.status === "pending" ? 0 : 1) - (b.status === "pending" ? 0 : 1));
  const rolesOf = (id) => (view ? view.assignments.filter((a) => a.accountId === id) : null);
  const services = view ? view.accounts.filter((a) => a.kind === "service") : [];

  return (
    <>
      <SettingsSection icon="users" title="Accounts"
        meta={rows ? rows.length + (rows.length === 1 ? " account" : " accounts") : null}>
        <RefusalNote refusal={refusal} />

        {waiting > 0 && (
          <div className="settings-users__waiting">
            <Icon name="hourglass" size={14} />
            {waiting === 1 ? "1 person is waiting for approval." : `${waiting} people are waiting for approval.`}
          </div>
        )}

        {rows === null ? (
          <div className="settings-users__empty">Loading…</div>
        ) : rows.length === 0 && !refusal ? (
          <div className="settings-users__empty">No accounts yet.</div>
        ) : (
          <div className="settings-users">
            {ordered.map((u) => {
              const held = rolesOf(u.id);
              return (
                <div key={u.id} className="settings-users__row" data-account={u.username}>
                  <button type="button" className="settings-users__open" onClick={() => setEditing(u)}>
                    <span className="settings-users__avatar">{(u.displayName || u.username || "?")[0].toUpperCase()}</span>
                    <span className="settings-users__who">
                      <span className="settings-users__name">{u.displayName || u.username}</span>
                      <span className="settings-users__handle">
                        {u.username}
                        {providersOf(u).length > 0 && <> · {providersOf(u).join(", ")}</>}
                        {!u.hasPassword && providersOf(u).length === 0 && <> · no way to sign in</>}
                      </span>
                    </span>
                    {held && (
                      <span className="settings-users__roles">
                        {held.length === 0
                          ? <span className="settings-users__role">everyone</span>
                          : held.slice(0, 3).map((a) => (
                            <span key={a.id} className="settings-users__role">{roleName(view, a.roleId)}</span>
                          ))}
                        {held.length > 3 && <span className="settings-users__role">+{held.length - 3}</span>}
                      </span>
                    )}
                    <span className={"settings-users__status settings-users__status--" + u.status}>{STATUS_LABEL[u.status] || u.status}</span>
                    <Icon name="chevron-right" size={14} />
                  </button>
                  {u.status === "pending" && canApprove && (
                    <button type="button" className="settings-users__approve"
                      disabled={approving === u.id}
                      onClick={() => approve(u)}>
                      {approving === u.id ? "Approving…" : "Approve"}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {canCreate && (
          <div className="settings-foot">
            <button className="fb-editor__btn" onClick={() => setEditing("new")}>
              Add an account
            </button>
          </div>
        )}
      </SettingsSection>

      {services.length > 0 && (
        <SettingsSection icon="bot" title="Service accounts" meta={String(services.length)}>
          <div className="settings-users">
            {services.map((s) => (
              <div key={s.id} className="settings-users__row">
                <span className="settings-users__open">
                  <span className="settings-users__avatar"><Icon name="bot" size={14} /></span>
                  <span className="settings-users__who">
                    <span className="settings-users__name">{s.username}</span>
                    <span className="settings-users__handle">
                      {s.requirements.length} {s.requirements.length === 1 ? "requirement" : "requirements"}
                    </span>
                  </span>
                  <span className={"settings-users__status settings-users__status--" + s.status}>{STATUS_LABEL[s.status] || s.status}</span>
                </span>
              </div>
            ))}
          </div>
        </SettingsSection>
      )}

      {editing && (
        <UserModal
          view={view}
          user={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); reload(); }} />
      )}
    </>
  );
}

// Create or edit one account. Creating names it, optionally with a first password; editing changes
// where it stands, sets a new password, assigns its roles, and ends its sessions or the account.
function UserModal({ view, user, onClose, onSaved }) {
  const creating = !user;
  const [form, setForm] = React.useState(() => ({
    username: "",
    displayName: "",
    status: user ? user.status : "active",
    password: "",
  }));
  const [busy, setBusy] = React.useState(false);
  const [refusal, setRefusal] = React.useState(null);
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const canCreate = !userRefusal("POST", "");
  const canApprove = !userRefusal("PATCH", "/_", { status: "active" });
  const canDisable = !userRefusal("PATCH", "/_", { status: "disabled" });
  const canDelete = !userRefusal("DELETE", "/_");
  // Which statuses this person may move the account to: approving and returning to the queue are one
  // action, switching off and on another.
  const statusAllowed = (to) => {
    if (!user || to === user.status) return true;
    if (to === "disabled" || user.status === "disabled") return canDisable;
    return canApprove;
  };

  const save = async () => {
    setBusy(true);
    setRefusal(null);
    try {
      if (creating) {
        await api.users.create({
          username: form.username.trim(),
          displayName: form.displayName.trim() || form.username.trim(),
          status: form.status,
          password: form.password || undefined,
        });
      } else {
        if (form.status !== user.status) await api.users.update(user.id, { status: form.status });
        if (form.password) await api.users.setPassword(user.id, form.password);
      }
      onSaved();
    } catch (e) {
      setBusy(false);
      setRefusal(refusalOf(e));
    }
  };

  const remove = async () => {
    setBusy(true);
    setRefusal(null);
    try {
      await api.users.remove(user.id);
      onSaved();
    } catch (e) {
      setBusy(false);
      setRefusal(refusalOf(e));
    }
  };

  const dirty = creating || form.status !== user.status || !!form.password;

  return (
    <Modal onClose={busy ? undefined : onClose} canClose={!busy}>
      <div className="modal settings-users__form">
        <h2 className="host-remove__title">{creating ? "Add an account" : (user.displayName || user.username)}</h2>
        {!creating && <div className="settings-users__linked">{user.username}</div>}
        <RefusalNote refusal={refusal} />

        {creating && (
          <>
            <label className="login-form__label" htmlFor="user-username">Username</label>
            <input id="user-username" className="login-form__input" value={form.username}
              autoCapitalize="off" spellCheck="false" disabled={busy} onChange={set("username")} />

            <label className="login-form__label" htmlFor="user-display">Display name</label>
            <input id="user-display" className="login-form__input" value={form.displayName}
              disabled={busy} onChange={set("displayName")} />
          </>
        )}

        <label className="login-form__label" htmlFor="user-status">Status</label>
        <Select id="user-status" value={form.status} disabled={busy} onChange={set("status")}>
          <option value="active" disabled={!statusAllowed("active")}>Active</option>
          <option value="pending" disabled={!statusAllowed("pending")}>Awaiting approval</option>
          {!creating && <option value="disabled" disabled={!statusAllowed("disabled")}>Disabled</option>}
        </Select>

        {canCreate && (
          <>
            <label className="login-form__label" htmlFor="user-password">
              {creating ? "Password (optional)" : "Set a new password"}
            </label>
            <input id="user-password" className="login-form__input" type="password" value={form.password}
              autoComplete="new-password" disabled={busy} onChange={set("password")} />
          </>
        )}
        {!creating && user.identities && user.identities.length > 0 && (
          <div className="settings-users__linked">
            Also signs in with: {user.identities.map((i) => (typeof i === "string" ? i : i.handle)).join(", ")}
          </div>
        )}

        {!creating && view && (
          <div className="settings-users__sessions">
            <div className="settings-users__sessions-head"><span>Roles</span></div>
            <Assignments view={view} accountId={user.id} />
          </div>
        )}

        {!creating && canDisable && <UserSessions user={user} disabled={busy} />}

        <div className="settings-users__actions">
          {!creating && canDelete && (
            <button className="host-btn host-btn--danger" onClick={remove} disabled={busy}>Delete</button>
          )}
          <span className="admin-spacer" />
          <button className="host-btn host-btn--ghost" onClick={onClose} disabled={busy}>Close</button>
          {(creating || canApprove || canDisable || canCreate) && (
            <button className="host-btn host-btn--primary" onClick={save}
              disabled={busy || !dirty || (creating && !form.username.trim())}>
              {busy ? "Saving…" : creating ? "Create" : "Save"}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

// Where this account is signed in, and ending any of it — inside the dialog for the person it belongs
// to, so whoever acts on somebody has already named them rather than an opaque id.
//
// Signing somebody out is deliberately NOT the same act as disabling them: the sessions end and the
// account is untouched, so they can sign straight back in. The confirmation says so, because
// somebody reaching for this during an incident is usually reaching for the other one.
//
// A session's recency is its last token rotation, not the person's last request: the provider sees
// a session only when it is refreshed.
function UserSessions({ user, disabled }) {
  const [rows, setRows] = React.useState(null);   // null = not loaded
  const [error, setError] = React.useState(null);
  const [busy, setBusy] = React.useState(null);   // a sid, "all", or null
  const [confirm, setConfirm] = React.useState(null);
  const name = user.displayName || user.username;

  const reload = React.useCallback(() => {
    setError(null);
    return api.sessions.list(user.id).then(
      (s) => setRows(s),
      (e) => { setRows([]); setError(messageOf(e, "Couldn’t load their sessions.")); });
  }, [user.id]);

  React.useEffect(() => { reload(); }, [reload]);

  const run = () => {
    if (!confirm) return;
    const all = confirm.mode === "other-all";
    setBusy(all ? "all" : confirm.sid);
    const call = all ? api.sessions.revokeAll(user.id) : api.sessions.revokeOne(user.id, confirm.sid);
    call.then(
      () => { setConfirm(null); setBusy(null); reload(); },
      (e) => { setBusy(null); setError(messageOf(e, "Couldn’t end that session.")); });
  };

  return (
    <div className="settings-users__sessions">
      <div className="settings-users__sessions-head">
        <span>Signed in on</span>
        {rows && rows.length > 0 && (
          <button type="button" className="settings-users__sessions-all"
            disabled={disabled || busy != null}
            onClick={() => setConfirm({ mode: "other-all" })}>
            {busy === "all" ? "Signing out…" : "Sign out everywhere"}
          </button>
        )}
      </div>

      {error && (
        <div className="login-card__error" role="alert"><Icon name="alert-triangle" size={14} />{error}</div>
      )}

      {rows === null && !error && <div className="settings-users__empty">Loading…</div>}
      {rows !== null && rows.length === 0 && !error && (
        <div className="settings-users__empty">No active sessions.</div>
      )}

      {(rows || []).map((s) => (
        <div key={s.sid} className="settings-users__session">
          <span className="settings-users__session-device">
            {s.userAgent && String(s.userAgent).trim() ? s.userAgent : "Unknown device"}
          </span>
          <span className="settings-users__session-when">last refreshed {when(s.lastSeen)}</span>
          <button type="button" className="settings-link__btn"
            disabled={disabled || busy != null}
            onClick={() => setConfirm({ mode: "other-one", sid: s.sid })}>
            {busy === s.sid ? "Ending…" : "End"}
          </button>
        </div>
      ))}

      {confirm && (
        <ConfirmRevokeDialog
          mode={confirm.mode}
          targetName={name}
          busy={busy != null}
          onClose={() => setConfirm(null)}
          onConfirm={run} />
      )}
    </div>
  );
}

// The provider's own message when it wrote one, because it is more specific than anything guessable
// here. Falls back only when there is nothing to show.
function messageOf(e, fallback) {
  return (e && e.userMessage) || fallback;
}

export { AccountsAdmin };
