// CatalogAdmin — every action declared to this provider, grouped by the application it belongs to:
// tks-auth's own, KGSM's (each component a group of its own) and each registered application's, with
// its effect, the scope kind it is granted at, and who declares it at which version.
//
// *Unmapped* is an action filed into no permission: nobody but an Owner can perform it until it is. It
// is a filter here, and an unmapped action is filed into a permission from its own row.

import React from "react";

import { Select, SettingsSection, useStore } from "@thekrystalship/krystal-ui";
import { applicationsStore } from "./ApplicationsAdmin.jsx";
import { RefusalNote, authorityGate, componentOf, useAuthority } from "./kit.jsx";
import { authorityStore, editRefusal } from "./stores.js";

const APPLICATION = "application:";

// The application an action belongs to: the registered application whose manifest declares it, this
// provider for its own, and KGSM for what a cluster's members declare.
function applicationOf(action) {
  const declarer = (action.declaredBy || []).find((d) => d.member.startsWith(APPLICATION));
  if (declarer) return declarer.member.slice(APPLICATION.length);
  return componentOf(action.action) === "auth" ? "auth" : "kgsm";
}

function CatalogAdmin() {
  const state = useAuthority();
  const view = state.view;
  const applications = useStore(applicationsStore, (s) => s.list);
  const canFile = !editRefusal("permission.actions");
  const [onlyUnmapped, setOnlyUnmapped] = React.useState(false);
  const [refusal, setRefusal] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  const groups = React.useMemo(() => {
    if (!view) return [];
    const named = (id) => {
      if (id === "auth") return "tks-auth";
      const a = (applications || []).find((x) => x.id === id);
      return a ? a.name : id === "kgsm" ? "KGSM" : id;
    };
    const by = {};
    view.catalog
      .filter((a) => !onlyUnmapped || a.unmapped)
      .forEach((a) => {
        const app = applicationOf(a);
        const component = componentOf(a.action);
        ((by[app] = by[app] || {})[component] = by[app][component] || []).push(a);
      });
    const rank = (id) => (id === "auth" ? 0 : id === "kgsm" ? 1 : 2);
    return Object.keys(by)
      .sort((x, y) => rank(x) - rank(y) || named(x).localeCompare(named(y)))
      .map((app) => ({
        app, name: named(app),
        components: Object.keys(by[app]).sort().map((c) => ({
          component: c, actions: by[app][c].sort((a, b) => a.action.localeCompare(b.action)),
        })),
      }));
  }, [view, onlyUnmapped, applications]);

  const gate = authorityGate(state);
  if (gate) return gate;

  const unmapped = view.catalog.filter((a) => a.unmapped).length;

  const fileInto = async (action, permissionId) => {
    const p = view.permissions.find((x) => x.id === permissionId);
    if (!p) return;
    setBusy(true);
    setRefusal(null);
    const r = await authorityStore.edit({ kind: "permission.actions", permissionId, actions: [...p.actions, action] });
    setBusy(false);
    if (!r.ok) setRefusal(r.refusal);
  };

  return (
    <SettingsSection icon="list-checks" title="Catalog"
      meta={view.catalog.length + " actions · " + unmapped + " unmapped"}
      action={
        <div className="access-filter" role="group" aria-label="Show">
          <button type="button" className={"access-filter__opt" + (!onlyUnmapped ? " is-on" : "")}
            aria-pressed={!onlyUnmapped} onClick={() => setOnlyUnmapped(false)}>All</button>
          <button type="button" className={"access-filter__opt" + (onlyUnmapped ? " is-on" : "")}
            aria-pressed={onlyUnmapped} onClick={() => setOnlyUnmapped(true)}>Unmapped</button>
        </div>
      }>
      <RefusalNote refusal={refusal} />
      {groups.length === 0 && <div className="access-sub access-sub--empty">{onlyUnmapped ? "Every action is filed." : "Nothing declares any action."}</div>}
      {groups.map((g) => (
        <div key={g.app} className="access-app" data-application={g.app}>
          <div className="access-app__title">{g.name}</div>
          {g.components.map((c) => (
            <div key={c.component} className="access-group">
              {(g.components.length > 1 || c.component !== g.app) && <div className="access-group__title">{c.component}</div>}
              {c.actions.map((a) => (
                <div key={a.action} className="access-action" data-action={a.action}>
                  <div className="access-action__main">
                    <span className="access-action__title">{a.title}</span>
                    <code className="access-check__id">{a.action}</code>
                  </div>
                  <span className={"access-pill access-pill--" + a.effect}>{a.effect}</span>
                  <span className="access-pill">{a.self ? "self" : a.scope}</span>
                  <span className="access-action__by">
                    {a.declaredBy.map((d) => d.member + (d.version ? " " + d.version : "")).join(", ") || "—"}
                  </span>
                  {a.unmapped && (
                    canFile && view.permissions.length > 0
                      ? (
                        <Select className="access-action__file" value="" aria-label={"File " + a.action + " into a permission"}
                          disabled={busy} onChange={(e) => { if (e.target.value) fileInto(a.action, e.target.value); }}>
                          <option value="">File into…</option>
                          {view.permissions.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                        </Select>
                      )
                      : <span className="access-pill access-pill--warn">unmapped</span>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      ))}
    </SettingsSection>
  );
}

export { CatalogAdmin };
