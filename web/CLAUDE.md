# `web/` — tks-auth's pages

A Vite + React 18 app on `@thekrystalship/krystal-ui`, built under `base: "/ui/"` into `dist/`, which
the release and `deploy/deploy.sh` place in `ui/` beside the binary — where the settings file's
`UiPath` points. The daemon reads each document from disk per request (`ProviderBundle`), so new pages
are live the moment the files land.

```bash
npm ci && npm run build   # → dist/
npm run check             # every document within the provider's policy, the floor intact, no bearer on the sign-in pages
npm run lint              # 0 errors
```

## Two applications, four documents

- **`auth-sign-in.html`, `auth-wait.html`, `auth-account.html` → `src/pages/`.** Signing in, the wait
  for approval and the account page. Every call is same-origin and authenticated by the provider's
  cookie; nothing these pages hold can call an application, so they may import nothing from
  `src/admin/` (`npm run check` walks the import graph). Each document carries its own **floor** — a
  sign-in form that posts without script, the providers' marker the daemon fills, a wait that refreshes
  only under `<noscript>` — and the application removes it on mount.
- **`admin.html` → `src/admin/`.** Accounts and approval, roles, permissions, the catalog grouped by
  application, assignments, service requests and applications. An OpenID Connect client of the provider
  that served it — the built-in public client `tks-auth`, its redirect `/admin/` on the issuer's own
  origin (`session.js`) — holding a bearer for tks-auth's own application, which the admin routes
  accept. The bearer is attached in `client.js` alone, which renews it once when it is refused
  (`eslint.config.js` enforces it).

**These pages name no action.** A control is gated on the request it would make, against the
provider's published operations and the caller's `/me/access` (`src/admin/stores.js`, over
`src/lib/operations.js` and `src/lib/access.js`), and a control the rules would refuse stays on screen
with the provider's reason beside it (`authorityStore.check`). The page holds no copy of the rules.

**A page's parameters are in its address** (`src/admin/route.js`): `#/assignments?scope=…&label=…` is
how another surface — a KGSM server's "manage access" — opens the roles held at one scope. A scope
this provider holds no record of is named by the `label` the link carries.

## Policy

Every document is served under the daemon's content security policy: no inline script, no inline
style, `connect-src 'self'`, no framing. A `style` attribute in a document, or a `<style>` element, is
refused by the browser with nothing but a console line; `npm run check` fails the build on either.
React's `style={…}` props are set through the CSSOM and are not affected.

## The stylesheet

`src/styles/kit.css` is a barrel: the design system's sheets and this app's partials, in cascade
order, which is load-bearing (a dialog's `.modal` width wins over the form inside it). The sign-in,
wait and account pages render pixel for pixel as the panel's sign-in family does, and the harness's
`oidc-pages.mjs` compares them against reference shots — a rule changed here is checked there.
