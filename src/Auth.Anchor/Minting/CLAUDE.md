# Minting — locked decisions

Compiled into the anchor and, unchanged, into `Auth.Testing`, so a test presents exactly the session
the anchor would mint.

- **The token layer knows nothing about providers.** It mints and reads whatever `provider:subject`
  it is handed. A Discord sign-in produces the subject `discord:<id>` — `SessionTokenServiceTests`
  pins that string, because changing its spelling is a flag day that invalidates every live token and
  orphans every stored session row at once.
- **One signer, ES256, required.** `SessionTokenService` takes the `EcdsaSessionSigner` and nothing
  else can sign with it; there is no symmetric path, so nothing a member holds can be a key.
- **`RefreshLifetime`, `Audience` and `Issuer` are settings, and all are load-bearing.** The lifetime
  is written once and used for both the token and the row, so there is no second copy to drift. The
  audience and the issuer are validated on every member, so changing either on a running cluster ends
  every session.
- **Two kinds of session, told apart by audience.** `MintAccess`/`MintRefresh` mint KGSM's, audienced
  to the cluster and carrying no claim about access. `MintApplicationAccess` mints an application's
  access token from an `ApplicationAccess` — its audience, its lifetime, `client_id`, the account as
  `sub`, and `ApplicationClaims.Actions` (`tks_actions`) as an array however many it holds — typed
  `at+jwt`; `MintApplicationRefresh` audiences an application's refresh token to the issuer, the one
  place it is presented. `ReadRefreshAsync` accepts either refresh audience and reports which in
  `RefreshClaims.Audience`; `ValidationParameters`, the bearer check, accepts only the cluster's.
- **The files stay free of anything only the anchor has.** `Auth.Testing` compiles them against
  `Auth` and `Auth.Cluster` alone, so a reference to an anchor type here breaks the test package's
  build rather than giving a test a different minter.
