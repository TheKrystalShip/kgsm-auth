// AssignmentsPage — who holds which role at one scope, and giving or taking one away.
//
// The scope is the page's parameter, so another surface links here with it filled in — a KGSM server's
// "manage access" opens the roles held on that install — and the name that surface knows it by rides
// along as `label`, since this provider holds no record of servers.

import { Select, SettingsSection } from "@thekrystalship/krystal-ui";
import { Assignments } from "./Assignments.jsx";
import { authorityGate, nameScope, useAuthority, useScopeOptions } from "./kit.jsx";
import { go } from "./route.js";

function AssignmentsPage({ params }) {
  const scope = params.scope || "cluster";
  nameScope(scope, params.label);
  const state = useAuthority();
  const options = useScopeOptions(state.view, scope);

  const gate = authorityGate(state);
  if (gate) return gate;

  return (
    <SettingsSection icon="user-check" title="Assignments"
      action={
        <Select className="admin-scope" value={scope} aria-label="Scope"
          onChange={(e) => go("assignments", { scope: e.target.value, label: params.label })}>
          {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </Select>
      }>
      <Assignments view={state.view} scope={scope} />
    </SettingsSection>
  );
}

export { AssignmentsPage };
