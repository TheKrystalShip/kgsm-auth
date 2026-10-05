// api.js — the sign-in, wait and account pages' calls: same-origin, to the provider that served them.
//
// Every one is authenticated by the provider's own cookie, which a same-origin fetch carries and
// nothing here can read. There is no bearer on these pages at all — nothing they hold can call an
// application.
//
// Answers `{ ok, status, body }` or `{ ok: false, status, code, error, unreachable }` and throws nothing,
// so a provider that did not answer (`status: 0`) and one that refused stay different sentences.

async function call(method, path, body) {
  let res;
  try {
    res = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    return { ok: false, status: 0, code: null, error: "The sign-in service didn’t answer.", unreachable: true };
  }

  let data = null;
  if (res.status !== 204) {
    try { data = await res.json(); } catch { data = null; }
  }

  if (res.ok) return { ok: true, status: res.status, body: data };

  const envelope = data && data.error;
  return {
    ok: false,
    status: res.status,
    code: (envelope && envelope.code) || null,
    error: (envelope && envelope.message) || "The sign-in service answered " + res.status + ".",
    // A refusal the provider could not decide — its store unreadable, or no longer the holder — is about
    // the service rather than about what was typed.
    unreachable: res.status >= 500,
  };
}

const getJson = (path) => call("GET", path);
const postJson = (path, body = {}) => call("POST", path, body);
const deleteJson = (path) => call("DELETE", path);

export { deleteJson, getJson, postJson };
