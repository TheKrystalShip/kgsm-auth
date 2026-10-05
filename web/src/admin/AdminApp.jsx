// AdminApp — administering who may do what here: accounts and their approval, roles, permissions, the
// catalog of declared actions, assignments, service accounts' requests, and the applications this
// provider signs people in to.
//
// One page per tab, each reached at `#/<tab>` (`route.js`). A tab is offered when the request behind
// it may be made; the pages gate their own controls the same way.

import { Icon, SubTabs, useStore } from "@thekrystalship/krystal-ui";
import { AccountsAdmin } from "./AccountsAdmin.jsx";
import { ApplicationsAdmin } from "./ApplicationsAdmin.jsx";
import { AssignmentsPage } from "./AssignmentsPage.jsx";
import { CatalogAdmin } from "./CatalogAdmin.jsx";
import { APPLICATIONS } from "./client.js";
import { Brief } from "./kit.jsx";
import { PermissionsAdmin } from "./PermissionsAdmin.jsx";
import { RolesAdmin } from "./RolesAdmin.jsx";
import { go, useRoute } from "./route.js";
import { ServiceRequests } from "./ServiceRequests.jsx";
import { profile, signOut } from "./session.js";
import { accessStore, administers, callRefusal } from "./stores.js";

const TABS = [
  { id: "accounts", label: "Accounts", icon: "users", render: () => <AccountsAdmin /> },
  { id: "roles", label: "Roles", icon: "shield", render: () => <RolesAdmin /> },
  { id: "permissions", label: "Permissions", icon: "key-round", render: () => <PermissionsAdmin /> },
  { id: "catalog", label: "Catalog", icon: "list-checks", render: () => <CatalogAdmin /> },
  { id: "assignments", label: "Assignments", icon: "user-check", render: (p) => <AssignmentsPage params={p} /> },
  { id: "services", label: "Services", icon: "bot", render: () => <ServiceRequests /> },
  { id: "applications", label: "Applications", icon: "app-window", render: () => <ApplicationsAdmin />,
    offered: () => !callRefusal("GET", APPLICATIONS) },
];

function AdminApp() {
  const access = useStore(accessStore);
  const route = useRoute();
  const who = profile();

  const tabs = TABS.filter((t) => !t.offered || t.offered());
  const tab = tabs.find((t) => t.id === route.page) || tabs[0];

  let body;
  if (access.state === "loading") body = <Brief title="Loading…" />;
  else if (access.state === "unavailable") body = <Brief title="The account store could not be read" />;
  else if (access.state !== "ok") body = <Brief title="Couldn’t reach the provider" />;
  else if (!administers()) body = <Brief title="You don’t have access to this" />;
  else body = tab.render(route.params);

  return (
    <div className="admin-shell">
      <header className="admin-head">
        <img className="admin-head__mark" src={import.meta.env.BASE_URL + "assets/tks-mark.png"} alt="" />
        <span className="admin-head__name">tks-auth</span>
        <span className="admin-spacer" />
        {who && (
          <a className="admin-head__who" href="/account">
            <Icon name="circle-user" size={15} /> {who.name || who.preferred_username || who.sub}
          </a>
        )}
        <button type="button" className="host-btn host-btn--ghost" onClick={() => signOut()}>
          <Icon name="log-out" size={15} /> Sign out
        </button>
      </header>
      {access.state === "ok" && administers() && (
        <SubTabs tabs={tabs} active={tab.id} onChange={(id) => go(id)} />
      )}
      <main className="admin-body">{body}</main>
    </div>
  );
}

export { AdminApp };
