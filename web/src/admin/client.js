// client.js — the admin pages' calls: same-origin, to the provider's admin routes, with the session's
// bearer.
//
// A refused bearer is renewed once and the call made again; a session that cannot be renewed sends
// the person to sign in. Every other refusal is thrown as the provider wrote it — `status`, `envCode`,
// `userMessage` and the body — so a page shows the provider's sentence beside the control it is about.

import { renew, signIn, token } from "./session.js";

class ApiError extends Error {
  constructor(status, body) {
    const envelope = body && body.error;
    super((envelope && envelope.message) || "The provider answered " + status + ".");
    this.status = status;
    this.envCode = (envelope && envelope.code) || null;
    this.userMessage = status === 0 ? "The provider didn’t answer." : this.message;
    this.body = body;
  }
}

async function send(method, path, body) {
  const headers = { Accept: "application/json" };
  const bearer = token();
  if (bearer) headers.Authorization = "Bearer " + bearer;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  try {
    return await fetch(path, {
      method, headers, credentials: "omit",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    return null;
  }
}

async function call(method, path, body) {
  let res = await send(method, path, body);
  if (res && res.status === 401) {
    if (await renew()) res = await send(method, path, body);
    if (res && res.status === 401) {
      await signIn();
      throw new ApiError(401, null);
    }
  }
  if (!res) throw new ApiError(0, null);

  let data = null;
  if (res.status !== 204) {
    try { data = await res.json(); } catch { data = null; }
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

const ACCOUNTS = "/auth/cluster/users";
const EDITS = "/auth/cluster/authority/edits";
const APPLICATIONS = "/auth/cluster/applications";

const one = (id) => "/" + encodeURIComponent(id);

const api = {
  // Every person's account, and what may be done to one.
  users: {
    list: () => call("GET", ACCOUNTS).then((r) => (r && r.data) || []),
    create: (body) => call("POST", ACCOUNTS, body || {}),
    update: (id, body) => call("PATCH", ACCOUNTS + one(id), body || {}),
    remove: (id) => call("DELETE", ACCOUNTS + one(id)),
    setPassword: (id, password) => call("POST", ACCOUNTS + one(id) + "/password", { password }),
  },
  // Where somebody else is signed in, and ending it.
  sessions: {
    list: (id) => call("GET", ACCOUNTS + one(id) + "/sessions").then((r) => (r && r.data) || []),
    revokeOne: (id, sid) => call("POST", ACCOUNTS + one(id) + "/sessions" + one(sid) + "/revoke", {}),
    revokeAll: (id) => call("POST", ACCOUNTS + one(id) + "/sessions/revoke-all", {}),
  },
  // Who may do what: read, one change against the version on screen, and the rules' verdict on edits
  // nobody has made.
  authority: {
    read: () => call("GET", "/auth/cluster/authority"),
    edit: (version, edit) => call("POST", EDITS, { ...edit, version }),
    check: (edits) => call("POST", "/auth/cluster/authority/checks", { edits }).then((r) => (r && r.results) || []),
  },
  // The caller's own actions here, and which action each gated request needs.
  me: () => call("GET", "/me/access"),
  operations: () => call("GET", "/auth/cluster/operations"),
  // The KGSM cluster's members, where this provider holds a cluster's accounts; a 404 standalone.
  members: () => call("GET", "/auth/cluster/members").then((r) => (r && r.members) || []),
  // The applications this provider signs people in to.
  applications: {
    list: () => call("GET", APPLICATIONS).then((r) => (r && r.data) || []),
    add: (body) => call("POST", APPLICATIONS, body),
    set: (id, body) => call("PATCH", APPLICATIONS + one(id), body),
    remove: (id) => call("DELETE", APPLICATIONS + one(id)),
    addClient: (id, body) => call("POST", APPLICATIONS + one(id) + "/clients", body),
    removeClient: (id, clientId) => call("DELETE", APPLICATIONS + one(id) + "/clients" + one(clientId)),
    rotateSecret: (id, clientId) => call("POST", APPLICATIONS + one(id) + "/clients" + one(clientId) + "/secret"),
  },
};

export { ACCOUNTS, APPLICATIONS, EDITS, api };
