// ESLint flat config (ESLint 9). Deliberately NARROW: the gate catches the static bug classes a build
// passes through silently — undeclared identifiers (`no-undef`, `react/jsx-no-undef`) and
// Rules-of-Hooks violations. Everything else is a warning, not a wall.
import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import react from "eslint-plugin-react";

export default [
  { ignores: ["dist/**", "node_modules/**"] },

  js.configs.recommended,

  {
    files: ["**/*.{js,jsx,mjs}"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser, ...globals.es2023 },
    },
    plugins: { "react-hooks": reactHooks, react },
    settings: { react: { version: "18.3" } },
    rules: {
      // Components referenced in JSX count as used.
      "react/jsx-uses-vars": "error",

      "no-undef": "error",
      "react/jsx-no-undef": "error",
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "no-unused-vars": ["warn", { args: "none", ignoreRestSiblings: true, varsIgnorePattern: "^_" }],

      // A bearer is attached in one place, `src/admin/client.js`, which renews it when it is refused.
      // A call that attaches one by hand works for as long as something else keeps the session fresh
      // and fails silently wherever nothing does.
      "no-restricted-syntax": ["error",
        {
          selector: "Property[key.name='Authorization'], MemberExpression[property.name='Authorization']",
          message: "Attach a bearer only in src/admin/client.js, which renews it when it is refused.",
        },
      ],

      "no-empty": ["warn", { allowEmptyCatch: true }],
    },
  },

  { files: ["src/admin/client.js"], rules: { "no-restricted-syntax": "off" } },

  // Node-side scripts and config run in Node, not the browser.
  {
    files: ["scripts/**", "vite.config.*", "eslint.config.js"],
    languageOptions: { globals: { ...globals.node } },
  },
];
