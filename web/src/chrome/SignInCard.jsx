import React from "react";
import { Icon } from "@thekrystalship/krystal-ui";
import { passwordOk, passwordStrength, usernameOk, usernameProblem } from "../lib/credentialRules.js";
import { AuthError, PasswordField, PasswordMeter, ProviderButtons } from "./AuthChrome.jsx";

// SignInCard — one card, two tabs.
//
// Where a credential goes is the caller's: this holds what is typed and what went wrong, and hands
// the rest to `onSubmit` and `onProvider`.
//
// The order down the card is the same on both tabs, so nothing moves when you toggle:
//
//   segment → providers → divider → form
//
// Errors sit with what they are about. A wrong password renders above the username, inside the
// form, where the eye already is on the way back to fixing it. A door that cannot be reached
// invalidates the tabs, the providers and the form alike, so that one sits at the top of the card.
//
// `onSubmit({ username, password, displayName })` resolves `{ ok, error, unreachable }`. On `ok` the
// card stays busy: the caller is navigating or adopting a session, and a card that re-enabled itself
// would offer a second submission of the same credential.

function SignInCard({
  tab, onTab, providers, registrationOpen, available = true,
  anchorError, onAnchorError, notice, onSubmit, onProvider, extra,
}) {
  const registering = tab === "register";

  const [username, setUsername] = React.useState("");
  const [displayName, setDisplayName] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [formError, setFormError] = React.useState(null);

  // Switching tabs keeps what was typed — somebody who tried to sign in and finds they
  // have no account should not retype their username to make one.
  React.useEffect(() => { setFormError(null); }, [tab]);

  const nameProblem = usernameProblem(username);
  const strength = passwordStrength(password);
  const confirmMismatch = registering && confirm.length > 0 && confirm !== password;

  const canSubmit = !busy && available && (registering
    ? usernameOk(username) && passwordOk(password) && confirm === password
    : !!username && !!password);

  const submit = async (e) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setFormError(null);
    if (onAnchorError) onAnchorError(null);

    const result = await onSubmit({
      username: registering ? username.trim() : username,
      password,
      displayName: displayName.trim(),
    });

    if (!result.ok) {
      setBusy(false);
      if (result.unreachable && onAnchorError) onAnchorError(result.error);
      else setFormError(result.error);
    }
  };

  const bounce = (provider) => {
    if (busy || !available) return;
    setBusy(provider);
    onProvider(provider);
  };

  const list = providers || [];
  const unreachable = !!anchorError;

  return (
    <div className="login-card">
      {/* Above the tabs: this is not about either of them. */}
      <AuthError>{anchorError}</AuthError>

      <div className="authseg" role="tablist">
        <button
          type="button" role="tab" aria-selected={!registering}
          className={!registering ? "is-on" : ""}
          onClick={() => onTab("login")}>Sign in</button>
        <button
          type="button" role="tab" aria-selected={registering}
          className={registering ? "is-on" : ""}
          onClick={() => onTab("register")}>Register</button>
      </div>

      {notice ? <AuthError>{notice}</AuthError> : null}

      <ProviderButtons
        providers={list}
        verb={registering ? "register" : "login"}
        busy={typeof busy === "string" ? busy : null}
        disabled={unreachable || busy === true}
        onPick={bounce} />

      {registering && !registrationOpen ? (
        <div className="login-note login-note--warn">
          <Icon name="ban" size={15} />
          <div>
            <b>This cluster isn’t taking new accounts.</b>
          </div>
        </div>
      ) : (
        <>
          {list.length ? (
            <div className="login-divider"><span>or with a KGSM account</span></div>
          ) : null}

          <form className="login-form" onSubmit={submit}>
            <AuthError field>{formError}</AuthError>

            <label className="login-form__label" htmlFor="auth-username">Username</label>
            <input
              id="auth-username"
              className={"login-form__input"
                + (registering && username && nameProblem ? " is-bad" : "")
                + (registering && usernameOk(username) ? " is-good" : "")}
              type="text"
              autoComplete="username"
              autoCapitalize="off"
              spellCheck="false"
              value={username}
              disabled={unreachable || !!busy}
              onChange={(e) => { setUsername(e.target.value); if (formError) setFormError(null); }} />
            {registering && username && nameProblem
              ? <div className="field-note field-note--bad"><Icon name="x" size={13} /> <span>{nameProblem}</span></div>
              : null}

            {registering ? (
              <>
                <label className="login-form__label" htmlFor="auth-display">
                  <span>Display name</span><em>optional</em>
                </label>
                <input
                  id="auth-display"
                  className="login-form__input"
                  type="text"
                  autoComplete="nickname"
                  placeholder={username.trim() || "Heisen"}
                  value={displayName}
                  disabled={unreachable || !!busy}
                  onChange={(e) => setDisplayName(e.target.value)} />
              </>
            ) : null}

            <PasswordField
              id="auth-password"
              label="Password"
              value={password}
              disabled={unreachable || !!busy}
              autoComplete={registering ? "new-password" : "current-password"}
              onChange={(e) => { setPassword(e.target.value); if (formError) setFormError(null); }}
              right={!registering ? (
                <button
                  type="button"
                  className="btn-link"
                  style={{ fontSize: 11, letterSpacing: 0, textTransform: "none" }}
                  onClick={() => setFormError("Ask whoever manages accounts on this cluster to reset it.")}>
                  Forgot?
                </button>
              ) : null}>
              {registering ? <PasswordMeter strength={strength} /> : null}
            </PasswordField>

            {registering ? (
              <PasswordField
                id="auth-confirm"
                label="Confirm password"
                value={confirm}
                disabled={unreachable || !!busy}
                autoComplete="new-password"
                onChange={(e) => setConfirm(e.target.value)}>
                {confirmMismatch
                  ? <div className="field-note field-note--bad"><Icon name="x" size={13} /> <span>Passwords don’t match</span></div>
                  : confirm && confirm === password
                    ? <div className="field-note field-note--ok"><Icon name="check" size={13} /> <span>Passwords match</span></div>
                    : null}
              </PasswordField>
            ) : null}

            <button type="submit" className="login-form__submit" disabled={!canSubmit}>
              {busy === true
                ? (<><span className="oauth-spinner" /> {registering ? "Creating your account…" : "Signing in…"}</>)
                : (registering ? "Create account" : "Sign in")}
            </button>
          </form>
        </>
      )}

      {unreachable ? extra : null}
    </div>
  );
}

export { SignInCard };
