import { createRoot } from "react-dom/client";

import "../styles/kit.css";
import "./pages.css";

import { AccountApp } from "./AccountApp.jsx";
import { SignInApp } from "./SignInApp.jsx";
import { WaitApp } from "./WaitApp.jsx";

// tks-auth's own pages: signing in, waiting for approval, and the account page.
//
// Each page is a document of its own, served by the provider, with its floor already in it — a working
// form, or a wait that polls without script. This application replaces that floor when it mounts, so
// a bundle that fails to load leaves the floor standing rather than an empty page.
//
// One appearance, following the reader's colour scheme. There is no theme picker and no stored
// theme: a theme name carried to the provider would be a parameter a stranger sets, and a stored one
// would be this origin's alone, disagreeing with the application the person came from. The document
// is served under a policy with no inline script, so there is no pre-paint script either; the floor
// renders in the default palette until this runs.

const light = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
const applyTheme = () =>
  document.documentElement.setAttribute("data-theme", light && light.matches ? "light" : "dark");
applyTheme();
if (light && light.addEventListener) light.addEventListener("change", applyTheme);

const PAGES = { "sign-in": SignInApp, wait: WaitApp, account: AccountApp };
const Page = PAGES[document.body.dataset.page] || SignInApp;

const floor = document.getElementById("floor");
if (floor) floor.remove();

createRoot(document.getElementById("root")).render(<Page />);
