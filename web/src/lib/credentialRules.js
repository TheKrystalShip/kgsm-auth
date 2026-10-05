// credentialRules.js — what a client may check about a username or a password before spending a round
// trip.
//
// Every one of these is also enforced by the daemon, which is the only place the answer is decided.
// They exist so somebody is told what is wrong while typing rather than after submitting. The daemon's
// own refusal names the rule it applied, so THAT is what a refusal renders — these never become a
// second copy of the rules that drifts from the daemon's.

const USERNAME_MIN = 3;
const USERNAME_MAX = 32;
const PASSWORD_MIN = 12;

// Mirrors tks-auth's `Usernames.IsValid`: ASCII letters, digits, '.', '_' or '-', beginning with a
// letter or a digit.
function usernameProblem(username) {
  const v = (username || "").trim();
  if (!v) return null;                       // nothing typed yet is not a complaint
  if (v.length < USERNAME_MIN) return `At least ${USERNAME_MIN} characters.`;
  if (v.length > USERNAME_MAX) return `At most ${USERNAME_MAX} characters.`;
  if (!/^[A-Za-z0-9]/.test(v)) return "Must start with a letter or a digit.";
  if (!/^[A-Za-z0-9._-]+$/.test(v)) return "Letters, digits, dots, underscores and hyphens only.";
  return null;
}

function usernameOk(username) {
  const v = (username || "").trim();
  return !!v && !usernameProblem(v);
}

// Four bands, because a five-point scale invites a number nothing measures. Length is what the
// daemon enforces; the extra bands describe a password comfortably past the floor rather than
// sitting on it.
function passwordStrength(password) {
  const v = password || "";
  if (!v) return { level: 0, label: "" };
  if (v.length < PASSWORD_MIN) return { level: 1, label: "Too short" };
  const variety = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(r => r.test(v)).length;
  if (v.length >= 20 || (v.length >= 16 && variety >= 3)) return { level: 4, label: "Strong" };
  if (v.length >= 14 || variety >= 3) return { level: 3, label: "Good" };
  return { level: 2, label: "Fair" };
}

const passwordOk = (password) => (password || "").length >= PASSWORD_MIN;

export { PASSWORD_MIN, USERNAME_MAX, USERNAME_MIN, passwordOk, passwordStrength, usernameOk, usernameProblem };
