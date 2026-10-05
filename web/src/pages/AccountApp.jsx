import React from "react";
import { Icon, Modal, SettingsRow, SettingsSection } from "@thekrystalship/krystal-ui";
import { OAuthIcon, providerLabel } from "../chrome/oauth-icons.jsx";
import { fmtRelative, parseTs } from "../lib/formatting.js";
import { passwordOk, passwordStrength } from "../lib/credentialRules.js";
import { AuthError, PasswordField, PasswordMeter } from "../chrome/AuthChrome.jsx";
import { deleteJson, getJson, postJson } from "./api.js";

// AccountApp — somebody's own account, on the provider that holds it.
//
// The one place a person changes how they sign in: their password, the provider accounts attached to
// them, and where they are signed in. Every application links here rather than carrying a copy, so
// nothing an application holds can change a credential.
//
// A change to how somebody signs in needs a RECENT proof. The daemon says until when the last one is
// good (`freshUntil`); inside that window a change goes straight through, outside it the page asks for
// the password first — or, for an account with none, a round trip to a provider it already has. That
// round trip leaves the page, so what was being done is remembered in this tab and resumed on return.
//
// The same proof gates `auth:*` actions on every surface. A surface refused with `reauth_required`
// opens this page at `#confirm`, which asks for the proof straight away and changes nothing else.

const RESUME_KEY = "kgsm:account:resume";

function remember(action) {
  try { sessionStorage.setItem(RESUME_KEY, JSON.stringify(action)); } catch { /* private mode */ }
}
function takeRemembered() {
  try {
    const raw = sessionStorage.getItem(RESUME_KEY);
    sessionStorage.removeItem(RESUME_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

// What a returning round trip reported, read once from the fragment and then cleared from the address.
function takeOutcome() {
  const hash = window.location.hash.replace(/^#/, "");
  if (!hash) return null;
  history.replaceState(null, "", window.location.pathname);
  const params = new URLSearchParams(hash);
  if (params.has("linked")) return { tone: "ok", text: providerLabel(params.get("linked")) + " connected." };
  if (params.has("proved")) return { tone: "proved" };
  if (params.has("confirm")) return { tone: "confirm" };
  const linkError = params.get("link_error");
  if (linkError === "identity_taken") return { tone: "bad", text: "That account is already connected to someone else." };
  if (linkError) return { tone: "bad", text: "Connecting didn’t complete." };
  const reauthError = params.get("reauth_error");
  if (reauthError === "other_account") return { tone: "bad", text: "That account isn’t connected to this one." };
  if (reauthError) return { tone: "bad", text: "Confirming didn’t complete." };
  return null;
}

function when(ts) {
  if (!ts) return "—";
  try { return fmtRelative(parseTs(ts)); } catch { return "—"; }
}

// A person reads a device, not a user-agent string. Browser and platform only, and the raw string as
// the tooltip, because the heuristic is a label and not a claim.
function deviceName(ua) {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : null;
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows"
    : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : null;
  if (browser && os) return browser + " on " + os;
  return browser || os || "Unknown device";
}

const capitalise = (word) => (word ? word[0].toUpperCase() + word.slice(1) : "—");

function isFresh(me) {
  return !!(me && me.freshUntil && parseTs(me.freshUntil) > Date.now());
}

function AccountApp() {
  const [me, setMe] = React.useState(null);
  const [loadError, setLoadError] = React.useState(null);
  const [outcome, setOutcome] = React.useState(() => takeOutcome());
  const [proving, setProving] = React.useState(null);   // the action waiting on a proof
  const [changingPassword, setChangingPassword] = React.useState(false);
  const [disconnecting, setDisconnecting] = React.useState(null);
  const [busy, setBusy] = React.useState(null);
  const [error, setError] = React.useState(null);

  const reload = React.useCallback(async () => {
    const r = await getJson("/account/me");
    if (r.status === 401) { window.location.assign("/account/sign-in"); return null; }
    if (!r.ok) { setLoadError(r.error); return null; }
    setMe(r.body);
    return r.body;
  }, []);

  // The actions a proof guards, by name, so one begun before a provider round trip can be resumed
  // after it.
  const run = React.useCallback(async (action) => {
    setError(null);
    if (action.kind === "confirm") { setOutcome({ tone: "ok", text: "Confirmed." }); return; }
    if (action.kind === "password") { setChangingPassword(true); return; }
    if (action.kind === "unlink") { setDisconnecting(action.identity); return; }
    if (action.kind === "link") {
      setBusy("link:" + action.provider);
      const r = await postJson("/account/identities/" + encodeURIComponent(action.provider) + "/start");
      if (r.ok && r.body && r.body.url) { window.location.assign(r.body.url); return; }
      setBusy(null);
      if (r.code === "reauth_required") { setProving(action); return; }
      setError(r.error);
    }
  }, []);

  const guarded = React.useCallback((action) => {
    if (isFresh(me)) run(action);
    else setProving(action);
  }, [me, run]);

  React.useEffect(() => {
    reload().then((loaded) => {
      if (!loaded) return;
      const resumed = takeRemembered();
      if (outcome && outcome.tone === "proved") {
        setOutcome(null);
        if (resumed) run(resumed);
      } else if (outcome && outcome.tone === "confirm") {
        setOutcome(null);
        const confirm = { kind: "confirm" };
        if (isFresh(loaded)) run(confirm);
        else setProving(confirm);
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once, on the load a round trip returns to
  }, []);

  const endSession = async (row) => {
    setBusy(row.sid);
    const r = await postJson("/account/sessions/revoke", { sid: row.sid });
    setBusy(null);
    if (!r.ok) { setError(r.error); return; }
    if (row.current) window.location.assign("/account/sign-in");
    else reload();
  };

  const endEverything = async () => {
    setBusy("all");
    const r = await postJson("/account/sessions/revoke", { all: true });
    if (!r.ok) { setBusy(null); setError(r.error); return; }
    window.location.assign("/account/sign-in");
  };

  const signOut = async () => {
    setBusy("sign-out");
    await postJson("/account/sign-out");
    window.location.assign("/account/sign-in");
  };

  if (loadError) {
    return (
      <div className="account-page">
        <AuthError>{loadError}</AuthError>
      </div>
    );
  }
  if (!me) return <div className="account-page" aria-busy="true" />;

  const linked = new Set(me.identities.map((i) => i.provider));
  const connectable = me.providers.filter((p) => !linked.has(p));

  return (
    <div className="account-page">
      <header className="account-page__head">
        <img className="account-page__mark" src={import.meta.env.BASE_URL + "assets/tks-mark.png"} alt="" />
        <div className="account-page__who">
          <h1>{me.displayName}</h1>
          <span>{me.username}</span>
        </div>
        <button className="host-btn host-btn--ghost" onClick={signOut} disabled={busy === "sign-out"}>
          <Icon name="log-out" size={15} /> Sign out
        </button>
      </header>

      {outcome && outcome.text ? (
        <div className={"account-page__notice account-page__notice--" + outcome.tone} role="status">
          <Icon name={outcome.tone === "ok" ? "check" : "alert-triangle"} size={15} /> {outcome.text}
        </div>
      ) : null}
      {error ? <AuthError>{error}</AuthError> : null}

      <SettingsSection icon="user" title="Account">
        <SettingsRow icon="at-sign" title="Username" sub={me.username} />
        <SettingsRow icon="shield" title="Status" sub={me.status === "pending" ? "Awaiting approval" : capitalise(me.status)} />
      </SettingsSection>

      <SettingsSection icon="key-round" title="Signing in">
        <SettingsRow icon="lock" title="Password" sub={me.hasPassword ? "Set" : "None"}>
          <button className="host-btn host-btn--ghost" onClick={() => guarded({ kind: "password" })}>
            {me.hasPassword ? "Change" : "Set a password"}
          </button>
        </SettingsRow>

        {me.identities.map((identity) => (
          <SettingsRow key={identity.id} icon="link" title={providerLabel(identity.provider)}
            sub={identity.label || identity.handle}>
            <button className="host-btn host-btn--ghost" disabled={busy === identity.id}
              onClick={() => guarded({ kind: "unlink", identity })}>
              Disconnect
            </button>
          </SettingsRow>
        ))}

        {connectable.map((provider) => (
          <SettingsRow key={provider} icon="plus" title={providerLabel(provider)} sub="Not connected">
            <button className="oauth-btn account-page__connect" disabled={busy === "link:" + provider}
              onClick={() => guarded({ kind: "link", provider })}>
              <OAuthIcon provider={provider} size={16} /> Connect
            </button>
          </SettingsRow>
        ))}
      </SettingsSection>

      <SettingsSection icon="monitor-smartphone" title="Signed in"
        action={me.sessions.length > 1 ? (
          <button className="btn-link" onClick={endEverything} disabled={busy === "all"}>Sign out everywhere</button>
        ) : null}>
        {me.sessions.map((row) => (
          <SettingsRow key={row.sid}
            icon={row.kind === "provider" ? "globe" : /mobile|android|iphone|ipad/i.test(row.userAgent || "") ? "smartphone" : "monitor"}
            title={row.current ? "This browser" : deviceName(row.userAgent)}
            sub={(row.kind === "provider" ? "Signed in here" : "An application") + " · " + when(row.created)}>
            <button className="host-btn host-btn--ghost" disabled={busy === row.sid}
              title={row.userAgent || undefined} onClick={() => endSession(row)}>
              {row.current ? "Sign out" : "End"}
            </button>
          </SettingsRow>
        ))}
      </SettingsSection>

      {proving ? (
        <ProveDialog
          me={me}
          onClose={() => setProving(null)}
          onProvider={(provider) => {
            remember(proving);
            window.location.assign("/account/reauth/" + encodeURIComponent(provider));
          }}
          onProved={async () => {
            const action = proving;
            setProving(null);
            await reload();
            run(action);
          }} />
      ) : null}

      {changingPassword ? (
        <PasswordDialog
          hasPassword={me.hasPassword}
          onClose={() => setChangingPassword(false)}
          onReauth={() => { setChangingPassword(false); setProving({ kind: "password" }); }}
          onDone={() => { setChangingPassword(false); setOutcome({ tone: "ok", text: "Password saved." }); reload(); }} />
      ) : null}

      {disconnecting ? (
        <DisconnectDialog
          identity={disconnecting}
          onClose={() => setDisconnecting(null)}
          onReauth={() => { const identity = disconnecting; setDisconnecting(null); setProving({ kind: "unlink", identity }); }}
          onDone={() => { setDisconnecting(null); reload(); }} />
      ) : null}
    </div>
  );
}

// Asking for a proof. The password where the account has one; otherwise a provider it already holds,
// which is a round trip rather than a field.
function ProveDialog({ me, onClose, onProved, onProvider }) {
  const [password, setPassword] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState(null);
  const providers = me.identities.map((i) => i.provider).filter((p) => me.providers.includes(p));

  const submit = async () => {
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    const r = await postJson("/account/reauth", { password });
    setBusy(false);
    if (r.ok) onProved();
    else setError(r.error);
  };

  return (
    <Modal onClose={busy ? undefined : onClose} canClose={!busy}>
      <div className="modal settings-users__form">
        <h2 className="host-remove__title">Confirm it’s you</h2>
        {error ? <div className="login-card__error" role="alert"><Icon name="alert-triangle" size={14} />{error}</div> : null}

        {me.hasPassword ? (
          <>
            <label className="login-form__label" htmlFor="prove-password">Password</label>
            <input id="prove-password" className="login-form__input" type="password" value={password}
              autoComplete="current-password" autoFocus disabled={busy}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") submit(); }} />
          </>
        ) : (
          <div className="oauth-stack">
            {providers.map((p) => (
              <button key={p} type="button" className={"oauth-btn oauth-btn--" + p} onClick={() => onProvider(p)}>
                <OAuthIcon provider={p} /> Continue with {providerLabel(p)}
              </button>
            ))}
          </div>
        )}

        <div className="settings-users__actions">
          <span className="account-page__spacer" />
          <button className="host-btn host-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          {me.hasPassword ? (
            <button className="host-btn host-btn--primary" onClick={submit} disabled={busy || !password}>
              {busy ? "Checking…" : "Confirm"}
            </button>
          ) : null}
        </div>
      </div>
    </Modal>
  );
}

function PasswordDialog({ hasPassword, onClose, onReauth, onDone }) {
  const [next, setNext] = React.useState("");
  const [again, setAgain] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState(null);
  const ready = passwordOk(next) && next === again;

  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    const r = await postJson("/account/password", { password: next });
    setBusy(false);
    if (r.ok) onDone();
    else if (r.code === "reauth_required") onReauth();
    else setError(r.error);
  };

  return (
    <Modal onClose={busy ? undefined : onClose} canClose={!busy}>
      <div className="modal settings-users__form">
        <h2 className="host-remove__title">{hasPassword ? "Change your password" : "Set a password"}</h2>
        {error ? <div className="login-card__error" role="alert"><Icon name="alert-triangle" size={14} />{error}</div> : null}

        <PasswordField id="pw-new" label="New password" value={next} autoComplete="new-password"
          disabled={busy} onChange={(e) => setNext(e.target.value)}>
          <PasswordMeter strength={passwordStrength(next)} />
        </PasswordField>
        <PasswordField id="pw-again" label="New password again" value={again} autoComplete="new-password"
          disabled={busy} onChange={(e) => setAgain(e.target.value)}>
          {again && again !== next
            ? <div className="field-note field-note--bad"><Icon name="x" size={13} /> <span>Passwords don’t match</span></div>
            : null}
        </PasswordField>

        <div className="settings-users__actions">
          <span className="account-page__spacer" />
          <button className="host-btn host-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="host-btn host-btn--primary" onClick={submit} disabled={busy || !ready}>
            {busy ? "Saving…" : "Save password"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function DisconnectDialog({ identity, onClose, onReauth, onDone }) {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    const r = await deleteJson("/account/identities/" + encodeURIComponent(identity.id));
    setBusy(false);
    if (r.ok) onDone();
    else if (r.code === "reauth_required") onReauth();
    else setError(r.error);
  };

  return (
    <Modal onClose={busy ? undefined : onClose} canClose={!busy}>
      <div className="modal host-remove">
        <h2 className="host-remove__title">Disconnect {providerLabel(identity.provider)}?</h2>
        <p className="host-remove__text">{identity.label || identity.handle}</p>
        {error ? <div className="login-card__error" role="alert"><Icon name="alert-triangle" size={14} />{error}</div> : null}
        <div className="settings-users__actions">
          <span className="account-page__spacer" />
          <button className="host-btn host-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="host-btn host-btn--danger" onClick={submit} disabled={busy}>
            {busy ? "Disconnecting…" : "Disconnect"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export { AccountApp };
