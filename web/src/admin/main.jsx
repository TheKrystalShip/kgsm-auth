import { createRoot } from "react-dom/client";

import "../styles/kit.css";
import "./admin.css";

import { AdminApp } from "./AdminApp.jsx";
import { signIn, start } from "./session.js";
import { refreshAccess, refreshMembers } from "./stores.js";

// tks-auth's admin pages. The document is served by the provider with a floor of its own; this
// application replaces it once a session is in hand, or leaves for the provider's sign-in when there
// is none.
//
// One appearance, following the reader's colour scheme, as on the provider's other pages.

const light = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
const applyTheme = () =>
  document.documentElement.setAttribute("data-theme", light && light.matches ? "light" : "dark");
applyTheme();
if (light && light.addEventListener) light.addEventListener("change", applyTheme);

start().then((session) => {
  if (!session) { signIn(); return; }

  refreshAccess();
  refreshMembers();
  // What this person may do moves when somebody else changes it; coming back to the tab reads it again.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") refreshAccess();
  });

  const floor = document.getElementById("floor");
  if (floor) floor.remove();
  createRoot(document.getElementById("root")).render(<AdminApp />);
});
