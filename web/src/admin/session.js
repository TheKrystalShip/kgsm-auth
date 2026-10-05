// session.js — the admin pages' sign-in: an OpenID Connect client of the provider that served them.
//
// The admin pages are a public client of tks-auth itself, `tks-auth`, built into the daemon with its
// redirect on the issuer's own origin: authorization code with PKCE, a refresh token renewing the
// session without a page, and a bearer its admin routes accept. The protocol is `oidc-client-ts`'s;
// what is decided here is only what the library cannot know.
//
// The session lives in `localStorage` so a tab opened days later renews without a bounce; the verifier
// and `state` of a round trip in flight stay in `sessionStorage`, because they belong to the one tab
// that left. Renewal is the refresh grant alone — no iframe, no silent re-authorization.
//
// Where the person was going rides the round trip as its `state`, so a link into one page with a
// scope filled in lands on that page with that scope once they have signed in.

import { ErrorResponse, UserManager, WebStorageStateStore } from "oidc-client-ts";

const CLIENT_ID = "tks-auth";
const PATH = "/admin/";
const PROVIDER_TIMEOUT_S = 10;

const origin = window.location.origin;
const manager = new UserManager({
  authority: origin,
  client_id: CLIENT_ID,
  redirect_uri: origin + PATH,
  post_logout_redirect_uri: origin + PATH,
  response_type: "code",
  scope: "openid",
  userStore: new WebStorageStateStore({ prefix: "tks-auth.admin.", store: window.localStorage }),
  stateStore: new WebStorageStateStore({ prefix: "tks-auth.admin.", store: window.sessionStorage }),
  automaticSilentRenew: false,
  monitorSession: false,
  loadUserInfo: false,
  requestTimeoutInSeconds: PROVIDER_TIMEOUT_S,
});

let current = null;
let renewing = null;

// Leave for the provider's sign-in, carrying where this tab was.
function signIn() {
  return manager.signinRedirect({ state: { hash: window.location.hash } });
}

// Renew through the refresh grant: the new session, or null when the provider refused the refresh
// token or could not be asked. Concurrent callers share one renewal.
function renew() {
  if (renewing) return renewing;
  renewing = (async () => {
    const before = await manager.getUser().catch(() => null);
    if (!before || !before.refresh_token) return null;
    try {
      const user = await manager.signinSilent({ silentRequestTimeoutInSeconds: PROVIDER_TIMEOUT_S });
      current = user && user.access_token ? user : null;
    } catch (err) {
      // Another tab may have rotated the shared refresh token a moment ago; what it stored is the session.
      const after = await manager.getUser().catch(() => null);
      if (after && after.refresh_token && after.refresh_token !== before.refresh_token && !after.expired) current = after;
      else {
        if (err instanceof ErrorResponse) await manager.removeUser().catch(() => {});
        current = null;
      }
    }
    return current;
  })().finally(() => { renewing = null; });
  return renewing;
}

// The session this tab holds, completing a round trip that has just come back. Null means there is
// none and the caller signs in.
async function start() {
  const query = new URLSearchParams(window.location.search);
  if (query.has("code") || query.has("error")) {
    let user = null;
    try { user = await manager.signinRedirectCallback(); } catch { user = null; }
    const hash = (user && user.state && user.state.hash) || "";
    window.history.replaceState(null, "", PATH + hash);
    current = user;
    if (current) return current;
  }
  current = await manager.getUser().catch(() => null);
  if (current && current.expired) current = await renew();
  return current;
}

// The bearer for the next request.
function token() { return current ? current.access_token : null; }

// Who is signed in, as the provider's id_token names them.
function profile() { return current ? current.profile : null; }

// End this browser's sign-in at the provider and come back here.
function signOut() {
  return manager.signoutRedirect({ id_token_hint: current ? current.id_token : undefined })
    .catch(() => manager.removeUser().then(() => window.location.assign(PATH)));
}

export { profile, renew, signIn, signOut, start, token };
