import React from "react";
import { Icon } from "@thekrystalship/krystal-ui";
import { AuthShell } from "./AuthChrome.jsx";

// PendingPage — an account the provider knows, waiting to be let in.
//
// Proving who you are and being let in are two different things, and this is the gap between them:
// the provider knows exactly who this is, and a pending account holds nothing until somebody holding
// `auth:accounts.approve` approves it.
//
// ── Why this polls ──────────────────────────────────────────────────────────────────
// Approval happens on somebody else's screen, minutes or days from now, and this browser has to
// notice, with nothing it could subscribe to: a pending account holds no session yet. So `onCheck`
// asks again — the provider's wait answers whether the request in flight can go on.
//
// The cadence is cheap and polite: every POLL_MS while the tab is visible, paused while it is hidden
// (nobody is watching a background tab for a redirect), and resumed with an immediate read when it
// comes back — which is also the case that matters most, since somebody who was told "you're in"
// alt-tabs straight here.

const POLL_MS = 5000;

function PendingPage({ user, onCheck }) {
  const handle = (user && (user.display || user.name)) || null;
  const [checking, setChecking] = React.useState(false);

  const check = React.useCallback(async () => {
    setChecking(true);
    try { await onCheck(); } finally { setChecking(false); }
  }, [onCheck]);

  React.useEffect(() => {
    let timer = null;
    let stopped = false;

    const tick = () => { if (!stopped) onCheck(); };

    const start = () => {
      if (timer) return;
      timer = setInterval(tick, POLL_MS);
    };
    const stop = () => {
      if (!timer) return;
      clearInterval(timer);
      timer = null;
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") { tick(); start(); }
      else stop();
    };

    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopped = true;
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [onCheck]);

  return (
    <AuthShell tagline={null}>
      <div className="pending">
        <div className="pending__icon">
          <Icon name="hourglass" size={26} strokeWidth={1.7} />
        </div>
        <h1 className="pending__title">Waiting for approval</h1>
        <p className="pending__body">Your account has to be approved.</p>
        {handle ? <div className="pending__who">{handle}</div> : null}
        <div className="pending__actions">
          <button className="login-form__submit" onClick={check} disabled={checking}>
            <Icon name="rotate-cw" size={15} className={checking ? "is-spinning" : ""} />
            {checking ? "Checking…" : "Check again"}
          </button>
        </div>
      </div>
    </AuthShell>
  );
}

export { PendingPage };
