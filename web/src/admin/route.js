// route.js — where the admin pages are, in the address's fragment: `#/<page>?<name>=<value>&…`.
//
// The fragment is the source of truth, so a link from another surface opens a page with its
// parameters filled in — `#/assignments?scope=instance:<node>/<id>%23<nonce>&label=<name>` opens the
// roles held on one server — and Back and Forward move between pages.

import React from "react";

const PAGES = ["accounts", "roles", "permissions", "catalog", "assignments", "services", "applications"];

function parse(hash) {
  const raw = String(hash || "").replace(/^#\/?/, "");
  const [path, query] = raw.split("?");
  const page = PAGES.includes(path) ? path : PAGES[0];
  return { page, params: Object.fromEntries(new URLSearchParams(query || "")) };
}

function hashOf(page, params) {
  const query = new URLSearchParams(Object.entries(params || {}).filter(([, v]) => v != null && v !== "")).toString();
  return "#/" + page + (query ? "?" + query : "");
}

function useRoute() {
  const [route, setRoute] = React.useState(() => parse(window.location.hash));
  React.useEffect(() => {
    const changed = () => setRoute(parse(window.location.hash));
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);
  return route;
}

function go(page, params) {
  window.location.hash = hashOf(page, params);
}

export { PAGES, go, useRoute };
