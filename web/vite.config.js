import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// tks-auth's pages, built under `base: "/ui/"` because the daemon serves every asset of them there
// and nothing else of its origin belongs to this bundle.
//
// One document per page, each carrying its own floor: the daemon serves the one a request calls for
// (`ProviderBundle`), reading it from disk on every request. The sign-in, wait and account documents
// share one application that replaces the floor on mount; the admin document is its own application,
// an OpenID Connect client of the provider that served it.
const page = (name) => fileURLToPath(new URL(`./${name}.html`, import.meta.url));

export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  server: { port: 5175 },
  build: {
    outDir: "dist",
    sourcemap: true,
    rollupOptions: {
      input: {
        "auth-sign-in": page("auth-sign-in"),
        "auth-wait": page("auth-wait"),
        "auth-account": page("auth-account"),
        admin: page("admin"),
      },
    },
  },
});
