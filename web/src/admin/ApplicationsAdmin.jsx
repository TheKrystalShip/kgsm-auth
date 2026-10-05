// ApplicationsAdmin — the applications this provider signs people in to: registering one, changing
// it, its clients and their secrets, and removing it.
//
// An application is the API its clients' tokens are for: an id that is also the namespace of its
// actions, the audience its resource server checks, where it serves its action manifest, how long its
// access tokens live, the Discord applications whose tokens its clients may present and whether it may
// act for a linked Discord user. KGSM and tks-auth itself are built in, listed and never edited here.
//
// A client secret is made by the provider and shown in the answer that made it, and never again: the
// page holds it on screen until it is dismissed, and nothing stores it.

import React from "react";

import { Icon, SettingsSection, useStore } from "@thekrystalship/krystal-ui";
import { createStore } from "@thekrystalship/krystal-ui/lib/store";
import { APPLICATIONS, api } from "./client.js";
import { Brief, RefusalNote } from "./kit.jsx";
import { DeleteButton } from "./RolesAdmin.jsx";
import { accessStore, callRefusal, refusalOf } from "./stores.js";

const applicationsStore = createStore({ status: "idle", list: null, error: null });

function refreshApplications() {
  return api.applications.list().then(
    (list) => applicationsStore.setState({ status: "ready", list, error: null }),
    (error) => applicationsStore.setState((s) => ({ ...s, status: "error", error })));
}

// A list typed one per line or separated by commas or spaces.
const listOf = (text) => String(text || "").split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);

function ApplicationsAdmin() {
  useStore(accessStore, (s) => s.report);
  const { status, list, error } = useStore(applicationsStore);
  const [secrets, setSecrets] = React.useState([]);
  const [registering, setRegistering] = React.useState(false);
  const allowed = !callRefusal("GET", APPLICATIONS);

  React.useEffect(() => { if (allowed) refreshApplications(); }, [allowed]);

  if (!allowed) return <Brief title="You don’t have access to this" />;
  if (status === "error" && !list) return <Brief title="Couldn’t read the applications" sub={error && error.userMessage} />;
  if (!list) return <Brief title="Loading…" />;

  // Every answer that made a secret shows it here, once.
  const answered = (answer) => {
    if (answer && answer.secrets && answer.secrets.length) setSecrets(answer.secrets);
    refreshApplications();
  };

  return (
    <>
      {secrets.length > 0 && <IssuedSecrets secrets={secrets} onDone={() => setSecrets([])} />}

      <SettingsSection icon="app-window" title="Applications"
        meta={list.length + (list.length === 1 ? " application" : " applications")}
        action={!registering && !callRefusal("POST", APPLICATIONS)
          ? <button type="button" className="fb-editor__btn" onClick={() => setRegistering(true)}>Register an application</button>
          : null}>
        {registering && (
          <RegisterForm onCancel={() => setRegistering(false)}
            onDone={(answer) => { setRegistering(false); answered(answer); }} />
        )}
        <div className="access-list">
          {list.map((app) => <ApplicationRow key={app.id} app={app} onAnswer={answered} />)}
        </div>
      </SettingsSection>
    </>
  );
}

// The secrets a change just made, each with a way to copy it.
function IssuedSecrets({ secrets, onDone }) {
  const [copied, setCopied] = React.useState(null);
  const copy = (s) => {
    if (navigator.clipboard) navigator.clipboard.writeText(s.secret).then(() => setCopied(s.clientId), () => {});
  };
  return (
    <SettingsSection icon="key-round" title="Client secret">
      {secrets.map((s) => (
        <div key={s.clientId} className="app-secret" data-secret-for={s.clientId}>
          <span className="app-secret__client">{s.clientId}</span>
          <code className="app-secret__value">{s.secret}</code>
          <button type="button" className="host-btn host-btn--ghost" onClick={() => copy(s)}>
            <Icon name={copied === s.clientId ? "check" : "copy"} size={14} /> Copy
          </button>
        </div>
      ))}
      <div className="settings-foot">
        <button type="button" className="fb-editor__btn" onClick={onDone}>Done</button>
      </div>
    </SettingsSection>
  );
}

// One application: its fields, its manifest's last reading, its clients; editable unless built in.
function ApplicationRow({ app, onAnswer }) {
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [refusal, setRefusal] = React.useState(null);
  const builtin = app.source === "builtin";
  const path = APPLICATIONS + "/" + encodeURIComponent(app.id);
  const canChange = !builtin && !callRefusal("PATCH", path);
  const canRemove = !builtin && !callRefusal("DELETE", path);

  const run = async (call) => {
    setBusy(true);
    setRefusal(null);
    try {
      onAnswer(await call());
      return true;
    } catch (e) {
      setRefusal(refusalOf(e));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const manifest = app.manifest
    ? (app.manifest.taken ? app.manifest.actions + (app.manifest.actions === 1 ? " action" : " actions") : app.manifest.problem)
    : null;

  return (
    <div className="access-row" data-application={app.id}>
      <div className="access-row__head">
        <span className="access-row__grip" aria-hidden="true"><Icon name={builtin ? "lock" : "app-window"} size={14} /></span>
        <span className="access-row__name">{app.name}</span>
        <span className="access-row__meta">
          {app.id} · {app.audience}{manifest ? " · " + manifest : ""}
        </span>
        <span className="access-row__tools">
          {canRemove && (
            <DeleteButton label={app.name} busy={busy} onDelete={() => run(() => api.applications.remove(app.id))} />
          )}
          <button type="button" className="access-link-btn" onClick={() => setOpen(!open)}>
            {open ? "Close" : builtin ? "Clients" : "Edit"}
          </button>
        </span>
      </div>
      {open && (
        <div className="access-sub">
          <RefusalNote refusal={refusal} compact />
          {!builtin && (
            <ApplicationFields app={app} editable={canChange} busy={busy}
              onSave={(change) => run(() => api.applications.set(app.id, change))} />
          )}
          <Clients app={app} builtin={builtin} busy={busy} run={run} />
        </div>
      )}
    </div>
  );
}

// An application's own fields as a form; only what changed is sent.
function ApplicationFields({ app, editable, busy, onSave }) {
  const initial = React.useMemo(() => ({
    name: app.name,
    audience: app.audience,
    manifestUrl: app.manifestUrl || "",
    lifetime: String(app.accessLifetimeMinutes),
    discord: (app.discordApplications || []).join(", "),
    actForDiscord: !!app.actForDiscord,
  }), [app]);
  const [form, setForm] = React.useState(initial);
  React.useEffect(() => { setForm(initial); }, [initial]);
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }));

  const change = {};
  if (form.name.trim() !== initial.name) change.name = form.name.trim();
  if (form.audience.trim() !== initial.audience) change.audience = form.audience.trim();
  if (form.manifestUrl.trim() !== initial.manifestUrl) change.manifestUrl = form.manifestUrl.trim();
  if (form.lifetime !== initial.lifetime) change.accessLifetimeMinutes = Number(form.lifetime);
  if (listOf(form.discord).join(",") !== listOf(initial.discord).join(",")) change.discordApplications = listOf(form.discord);
  if (form.actForDiscord !== initial.actForDiscord) change.actForDiscord = form.actForDiscord;
  const dirty = Object.keys(change).length > 0;

  return (
    <form className="app-form" onSubmit={(e) => { e.preventDefault(); if (dirty) onSave(change); }}>
      <Field id={"name-" + app.id} label="Name" value={form.name} onChange={set("name")} disabled={!editable || busy} />
      <Field id={"audience-" + app.id} label="Audience" value={form.audience} onChange={set("audience")} disabled={!editable || busy} mono />
      <Field id={"manifest-" + app.id} label="Manifest" value={form.manifestUrl} onChange={set("manifestUrl")} disabled={!editable || busy} mono />
      <Field id={"lifetime-" + app.id} label="Access lifetime (minutes)" value={form.lifetime} onChange={set("lifetime")}
        disabled={!editable || busy} type="number" />
      <Field id={"discord-" + app.id} label="Discord applications" value={form.discord} onChange={set("discord")} disabled={!editable || busy} mono />
      <label className="access-check app-form__check">
        <input type="checkbox" checked={form.actForDiscord} disabled={!editable || busy} onChange={set("actForDiscord")} />
        <span className="access-check__name">Acts for linked Discord users</span>
      </label>
      {editable && (
        <div className="access-sub__foot">
          <button type="submit" className="fb-editor__btn" disabled={busy || !dirty}>Save</button>
        </div>
      )}
    </form>
  );
}

function Field({ id, label, mono, ...input }) {
  return (
    <>
      <label className="login-form__label" htmlFor={id}>{label}</label>
      <input id={id} className={"login-form__input" + (mono ? " app-form__mono" : "")} spellCheck="false"
        autoCapitalize="off" {...input} />
    </>
  );
}

// An application's clients: their addresses, whether they hold a secret, a new secret, removing one,
// and adding another.
function Clients({ app, builtin, busy, run }) {
  const base = APPLICATIONS + "/" + encodeURIComponent(app.id) + "/clients";
  const canAdd = !builtin && !callRefusal("POST", base);
  const [adding, setAdding] = React.useState(false);

  return (
    <div className="access-group">
      <div className="access-group__title">Clients</div>
      {app.clients.length === 0 && <div className="access-sub access-sub--empty">No clients.</div>}
      {app.clients.map((c) => {
        const one = base + "/" + encodeURIComponent(c.clientId);
        return (
          <div key={c.clientId} className="access-action" data-client={c.clientId}>
            <div className="access-action__main">
              <code className="access-check__id">{c.clientId}</code>
              <span className="access-action__why">{c.redirectUris.join(" · ") || "—"}</span>
            </div>
            <span className="access-pill">{c.confidential ? "confidential" : "public"}</span>
            <span className="access-action__by">{c.memberId || c.source}</span>
            {!builtin && (
              <span className="access-row__tools">
                {c.confidential && !callRefusal("POST", one + "/secret") && (
                  <button type="button" className="host-btn host-btn--ghost" disabled={busy}
                    onClick={() => run(() => api.applications.rotateSecret(app.id, c.clientId))}>New secret</button>
                )}
                {!callRefusal("DELETE", one) && (
                  <DeleteButton label={c.clientId} busy={busy}
                    onDelete={() => run(() => api.applications.removeClient(app.id, c.clientId))} />
                )}
              </span>
            )}
          </div>
        );
      })}
      {canAdd && (adding
        ? <ClientForm busy={busy} onCancel={() => setAdding(false)}
            onSubmit={async (client) => { if (await run(() => api.applications.addClient(app.id, client))) setAdding(false); }} />
        : (
          <div className="access-sub__foot">
            <button type="button" className="host-btn host-btn--ghost" onClick={() => setAdding(true)}>Add a client</button>
          </div>
        ))}
    </div>
  );
}

// One client's registration. An empty id is made by the provider.
function useClientFields() {
  const [client, setClient] = React.useState({ clientId: "", redirects: "", postLogout: "", confidential: false });
  const set = (k) => (e) => setClient((c) => ({ ...c, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }));
  const body = {
    clientId: client.clientId.trim() || null,
    redirectUris: listOf(client.redirects),
    postLogoutRedirectUris: listOf(client.postLogout),
    confidential: client.confidential,
  };
  return { client, set, body };
}

function ClientFields({ prefix, client, set, busy }) {
  return (
    <>
      <Field id={prefix + "-client"} label="Client id" value={client.clientId} onChange={set("clientId")} disabled={busy} mono />
      <label className="login-form__label" htmlFor={prefix + "-redirects"}>Redirect URIs</label>
      <textarea id={prefix + "-redirects"} className="login-form__input app-form__mono app-form__area" value={client.redirects}
        spellCheck="false" disabled={busy} onChange={set("redirects")} />
      <label className="login-form__label" htmlFor={prefix + "-post-logout"}>Post-sign-out URIs</label>
      <textarea id={prefix + "-post-logout"} className="login-form__input app-form__mono app-form__area" value={client.postLogout}
        spellCheck="false" disabled={busy} onChange={set("postLogout")} />
      <label className="access-check app-form__check">
        <input type="checkbox" checked={client.confidential} disabled={busy} onChange={set("confidential")} />
        <span className="access-check__name">Confidential</span>
      </label>
    </>
  );
}

function ClientForm({ busy, onCancel, onSubmit }) {
  const { client, set, body } = useClientFields();
  return (
    <form className="app-form" onSubmit={(e) => { e.preventDefault(); onSubmit(body); }}>
      <ClientFields prefix="new" client={client} set={set} busy={busy} />
      <div className="access-sub__foot">
        <button type="button" className="host-btn host-btn--ghost" onClick={onCancel} disabled={busy}>Cancel</button>
        <button type="submit" className="fb-editor__btn" disabled={busy}>Add client</button>
      </div>
    </form>
  );
}

// Registering an application with its first client.
function RegisterForm({ onCancel, onDone }) {
  const [app, setApp] = React.useState({ id: "", name: "", audience: "", manifestUrl: "", lifetime: "", discord: "", actForDiscord: false });
  const { client, set: setClient, body: clientBody } = useClientFields();
  const [busy, setBusy] = React.useState(false);
  const [refusal, setRefusal] = React.useState(null);
  const set = (k) => (e) => setApp((a) => ({ ...a, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setRefusal(null);
    const hasClient = clientBody.clientId || clientBody.redirectUris.length || clientBody.confidential;
    try {
      const answer = await api.applications.add({
        id: app.id.trim(),
        name: app.name.trim() || app.id.trim(),
        audience: app.audience.trim() || null,
        manifestUrl: app.manifestUrl.trim() || null,
        accessLifetimeMinutes: app.lifetime ? Number(app.lifetime) : null,
        discordApplications: listOf(app.discord),
        actForDiscord: app.actForDiscord,
        clients: hasClient ? [clientBody] : [],
      });
      onDone(answer);
    } catch (err) {
      setRefusal(refusalOf(err));
      setBusy(false);
    }
  };

  return (
    <form className="app-form app-form--register" onSubmit={submit}>
      <RefusalNote refusal={refusal} compact />
      <Field id="app-id" label="Id" value={app.id} onChange={set("id")} disabled={busy} mono />
      <Field id="app-name" label="Name" value={app.name} onChange={set("name")} disabled={busy} />
      <Field id="app-audience" label="Audience" value={app.audience} onChange={set("audience")} disabled={busy} mono placeholder={app.id.trim()} />
      <Field id="app-manifest" label="Manifest" value={app.manifestUrl} onChange={set("manifestUrl")} disabled={busy} mono />
      <Field id="app-lifetime" label="Access lifetime (minutes)" value={app.lifetime} onChange={set("lifetime")} disabled={busy} type="number" placeholder="5" />
      <Field id="app-discord" label="Discord applications" value={app.discord} onChange={set("discord")} disabled={busy} mono />
      <label className="access-check app-form__check">
        <input type="checkbox" checked={app.actForDiscord} disabled={busy} onChange={set("actForDiscord")} />
        <span className="access-check__name">Acts for linked Discord users</span>
      </label>
      <div className="access-group__title">Client</div>
      <ClientFields prefix="register" client={client} set={setClient} busy={busy} />
      <div className="access-sub__foot">
        <button type="button" className="host-btn host-btn--ghost" onClick={onCancel} disabled={busy}>Cancel</button>
        <button type="submit" className="fb-editor__btn" disabled={busy || !app.id.trim()}>Register</button>
      </div>
    </form>
  );
}

export { ApplicationsAdmin, applicationsStore, refreshApplications };
