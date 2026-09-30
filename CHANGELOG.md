# Changelog

## 0.2.0

The auth service now applies an app's 2FA policy to OAuth sign-in, as it
already did to `login`.

- `exchangeCode`, `signInWithIdToken` and `handleRedirect` throw
  `TwoFactorRequiredException` when a second factor is pending, and store no
  session. It extends `GhaymaAuthException`: `code` is `two_fa_required` or
  `two_fa_enrollment_required`, and `result` is the `TwoFaRequired` or
  `TwoFaEnrollmentRequired` step `login` returns, finished with `verify2fa`,
  or `enrollTotp` then `confirmTotp`. Signatures are unchanged.
- `handleRedirect` forgets the remembered PKCE verifier when the exchange
  succeeds or answers with a pending second factor: the service has redeemed
  the code either way. After a failure (`invalid_grant`, a network error, a
  timeout) it keeps the verifier, so the app can retry.
- The vendored contract documents the pending bodies of `/oauth/exchange` and
  `/oauth/id-token`, and the `403 email_not_verified` refusal of
  `/oauth/id-token` (Google has not verified the address), which surfaces as a
  `GhaymaAuthException` with that `code`.

Upgrade before turning 2FA on for an app that signs in with OAuth: 0.1.0 reads
a pending answer as a session with empty tokens.

## 0.1.0

Initial release — a pure-Dart client for the Ghayma auth service, mirroring
`@ghayma/sdk/client` 1.2.0.

- Email and password: `register`, `login`, `forgotPassword`, `resetPassword`,
  `verifyResetToken`, `resendVerification`. `register` and `login` return
  sealed results, so the pending-verification and pending-2FA shapes are part
  of the type rather than a runtime surprise.
- Sessions: `init`, `getAccessToken`, `refresh` with token rotation, `logout`,
  `currentSession` / `currentUser` / `isAuthenticated`, and an
  `onAuthStateChange` stream. Refresh runs automatically 60 s before expiry and
  on demand within 30 s of it; a rejected refresh clears the session and emits
  `signedOut`.
- Two-factor: `verify2fa`, `enrollTotp`, `confirmTotp`,
  `regenerateRecoveryCodes`, `disable2fa`, including the enforced-enrolment
  path that completes a login.
- Profile: `getUser`, `updateUser`, `deleteAccount`, `changePassword`,
  `changeEmail`, `cancelEmailChange`.
- OAuth, PKCE only: `oauthUrl`, `startOAuth`, `handleRedirect`, `exchangeCode`,
  and `signInWithIdToken` for native Google sign-in. No implicit/fragment flow,
  so no token passes through the OS URL handler.
- Persistence through a `TokenStorage` seam with an in-memory default, so a
  Flutter app can drop in secure storage without the package depending on
  Flutter.
- Server callers can pass a `serverKey` and per-call `RequestOptions(clientIp)`
  so rate limits are charged to the end user's address.
- Contract-conformance tested: every method runs against a Prism mock of the
  published OpenAPI contract, in addition to the unit suite.
