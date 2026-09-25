# `Auth.Journal` — locked decisions

- **It has ZERO package dependencies, and that is the whole design.** It is a wire shape two
  components must agree on, and one of them is a Native AOT daemon holding a cluster's account store.
  Anything that needs a logger, a container or a journal writer belongs in the caller.
- **The names and the payload writers live together and are called, never copied.** kgsm-api writes
  these lines on a host that holds its own accounts; the anchor writes them when a cluster's accounts
  are held by one. A reader deserializes into a fixed shape, so a field spelled differently by one
  writer does not throw — it lands as a null and the row renders with a name missing and nothing
  reported. That failure is why one implementation exists rather than two descriptions of it.
- **An absent value is a real null, never an empty string.** "Nobody looked this up" and "this is
  blank" are different facts, and a reader that meets `""` cannot tell which it has.
- **Facts, not sentences.** No summary, no severity, no formatted value: a reader builds those at read
  time, which is what lets one fact be worded one way in a Control Panel and another in a chat
  surface, and what keeps a wording improvement from applying only to rows written after it.
- **It never takes a password parameter.** What is recorded is that a credential was set and by whom —
  the only signal an account takeover leaves — and the credential is not part of that fact.
