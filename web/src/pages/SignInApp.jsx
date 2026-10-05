import React from "react";
import { AuthError, AuthShell } from "../chrome/AuthChrome.jsx";
import { SignInCard } from "../chrome/SignInCard.jsx";
import { getJson, postJson } from "./api.js";

// SignInApp — the sign-in page, for the request in flight.
//
// What is particular to this request — whose sign-in it is, which providers are wired, whether
// registration is open — is read from /authorize/context, because the document is static and the
// request lives behind a cookie. A credential answers with where to go: the client, carrying its
// code, or the wait. Nothing here ever holds a session.

function SignInApp() {
  const [context, setContext] = React.useState(null);
  const [problem, setProblem] = React.useState(null);
  const [tab, setTab] = React.useState("login");
  const [anchorError, setAnchorError] = React.useState(null);
  const registering = tab === "register";

  React.useEffect(() => {
    let live = true;
    getJson("/authorize/context").then((r) => {
      if (!live) return;
      if (r.ok) setContext(r.body);
      else setProblem(r.error);
    });
    return () => { live = false; };
  }, []);

  const submit = async ({ username, password, displayName }) => {
    const r = registering
      ? await postJson("/authorize/register", { username, password, displayName: displayName || null })
      : await postJson("/authorize/credentials", { username, password });
    if (!r.ok) return r;

    window.location.assign((r.body && (r.body.redirect || r.body.wait)) || "/authorize/wait");
    return { ok: true };
  };

  if (problem) {
    return (
      <AuthShell tagline={null}>
        <div className="login-card"><AuthError>{problem}</AuthError></div>
      </AuthShell>
    );
  }

  const name = context ? context.client.name : null;

  return (
    <AuthShell tagline={registering ? "Create an account." : "Sign in."}>
      <SignInCard
        tab={tab}
        onTab={setTab}
        providers={context ? context.providers : []}
        registrationOpen={!!(context && context.registration)}
        available={!!context}
        anchorError={anchorError}
        onAnchorError={setAnchorError}
        onSubmit={submit}
        onProvider={(provider) => window.location.assign("/authorize/" + encodeURIComponent(provider))} />

      {name ? (
        <div className="doorway doorway--static">
          <span>{registering ? "Creating your account for" : "Signing in to"} <b>{name}</b></span>
        </div>
      ) : null}
    </AuthShell>
  );
}

export { SignInApp };
