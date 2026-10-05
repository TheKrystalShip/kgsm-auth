// check-bundle.mjs — every document within the provider's policy, the floor intact, and no bearer on
// the sign-in pages.
//
//   npm run build && npm run check
//
// The daemon serves these documents under a content security policy with no inline script and no
// inline style, and fills the sign-in floor's provider links in at a marker. Three things can go wrong
// with that, and none of them shows up anywhere but here:
//
//   1. A document picks up something the policy refuses — an inline script, a `style` attribute — and
//      the page renders broken in every browser with nothing but a console line to say why.
//   2. The sign-in floor loses its marker or its form, and with scripting off nobody can sign in.
//   3. The sign-in, wait or account page grows an import of the admin pages' session, and a page that
//      must hold no bearer ships one — tree-shaking does not remove a static import of a module with
//      side effects.

import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = resolve(ROOT, "src");
const ENTRY = resolve(SRC, "pages/main.jsx");
const DIST = resolve(ROOT, "dist");
const DOCUMENTS = ["auth-sign-in.html", "auth-wait.html", "auth-account.html", "admin.html"];

const IMPORT_RE = /(?:from|import)\s*\(?\s*["']([^"']+)["']/g;

function walk(entry) {
  const seen = new Set();
  const via = new Map();
  const stack = [entry];
  while (stack.length) {
    const file = stack.pop();
    if (seen.has(file) || !existsSync(file)) continue;
    seen.add(file);
    if (!/\.jsx?$/.test(file)) continue;
    for (const [, spec] of readFileSync(file, "utf8").matchAll(IMPORT_RE)) {
      if (!spec.startsWith(".")) continue;
      const target = resolve(dirname(file), spec);
      if (!existsSync(target)) continue;
      if (!via.has(target)) via.set(target, file);
      stack.push(target);
    }
  }
  return { seen, via };
}

let failed = false;
const fail = (line) => { console.error(line); failed = true; };

const { seen, via } = walk(ENTRY);
for (const file of seen) {
  if (file.startsWith(resolve(SRC, "admin") + "/")) {
    fail(`✗ the sign-in pages reach ${relative(SRC, file)}`);
    fail(`    imported by ${relative(SRC, via.get(file))} — cut the edge`);
  }
}
if (!failed) console.log(`✓ sign-in pages: ${seen.size} modules, none of them the admin pages' session`);

if (!existsSync(DIST)) {
  fail("✗ no dist/ — run `npm run build` first");
} else {
  for (const page of DOCUMENTS) {
    const path = resolve(DIST, page);
    if (!existsSync(path)) { fail(`✗ ${page} is not in the build`); continue; }
    const html = readFileSync(path, "utf8");

    // Every script has a src: the policy is script-src 'self'.
    const inline = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)]
      .filter(([, attrs, body]) => !/\bsrc=/.test(attrs) || body.trim().length > 0);
    if (inline.length) fail(`✗ ${page} carries an inline script, which the provider's policy refuses`);

    // No style attribute or <style> element: the policy is style-src 'self'.
    if (/\sstyle\s*=/.test(html) || /<style\b/.test(html))
      fail(`✗ ${page} carries inline style, which the provider's policy refuses`);

    // Everything it loads is under the bundle's own base.
    for (const [, url] of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
      if (/^(\/ui\/|\/authorize\/)/.test(url)) continue;
      fail(`✗ ${page} references ${url}, outside /ui/ — the provider serves nothing else of this bundle`);
    }
  }

  const signIn = existsSync(resolve(DIST, "auth-sign-in.html")) ? readFileSync(resolve(DIST, "auth-sign-in.html"), "utf8") : "";
  if (!signIn.includes("<!--kgsm-floor-providers-->"))
    fail("✗ auth-sign-in.html lost the providers marker — the floor would offer no provider");
  if (!/<form[^>]*method="post"[^>]*action="\/authorize\/credentials"/.test(signIn))
    fail("✗ auth-sign-in.html has no floor form posting to /authorize/credentials");

  if (!failed) console.log("✓ every document within the provider's policy, the floor intact");
}

process.exit(failed ? 1 : 0);
