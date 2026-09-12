# Changelog

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
