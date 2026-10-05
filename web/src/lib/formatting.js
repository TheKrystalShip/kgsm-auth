// formatting.js — time as the pages show it. `fmtRelative` is the design system's own, so a relative
// time reads the same here as in every other surface built on it.

import { fmtRelative } from "@thekrystalship/krystal-ui/lib/time";

// A timestamp as the daemon writes one: ISO 8601, or with a space where the `T` goes.
function parseTs(ts) { return new Date(ts.replace(" ", "T")); }

// A timestamp relative to now, or a dash when there is none or it cannot be read.
function when(ts) {
  if (!ts) return "—";
  try { return fmtRelative(parseTs(ts)); } catch { return "—"; }
}

export { fmtRelative, parseTs, when };
