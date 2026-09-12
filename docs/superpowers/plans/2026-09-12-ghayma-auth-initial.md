# `ghayma_auth` 0.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pure-Dart client for the Ghayma auth service that mirrors `@ghayma/sdk/client` 1.2.0 (email/password, 2FA, sessions with refresh, profile, PKCE OAuth, native Google sign-in), tested against a mock of the published contract, ready to publish as `ghayma_auth` 0.1.0.

**Architecture:** One package. `GhaymaAuth` (lib/src/client.dart) composes a request layer (`lib/src/http.dart`: URL, headers, JSON, error mapping), a session store (`lib/src/session.dart`: `TokenStorage` seam, expiry, persistence, refresh timer), PKCE helpers, and immutable models parsed from the contract's schemas. Unit tests use `package:http/testing.dart` `MockClient`; conformance tests run against a Prism mock of `spec/auth.v1.yaml`.

**Tech Stack:** Dart `>=3.6.0 <4.0.0` (local toolchain 3.11.4), `http ^1.2.0`, `crypto ^3.0.0`, dev `test`, `lints`; Prism 5 via `npx` for conformance; GitHub Actions with `dart-lang/setup-dart`.

**Spec (read first):** `/Users/bouzi/Projects/THROCT/GHAYMA/DART-SDK-DESIGN-2026-09-12.md` — the public API in §2 is fixed; the models' field names come from `spec/auth.v1.yaml` in this repo. The JS reference for behaviour (not for names) is readable with `git -C /Users/bouzi/Projects/THROCT/GHAYMA/Admin-SDK show origin/main:src/client/index.ts` (and `client.ts`, `token.ts`, `types.ts`) — read-only, do not check anything out there.

## Global Constraints

- Work only in `/Users/bouzi/Projects/THROCT/worktrees/Dart-SDK/feat-initial-sdk` (branch `feat/initial-sdk`, base = the scaffold commit on `main`).
- No AI attribution anywhere (commits, comments, files, pubspec). Minimal clean comments; public API gets short dartdoc.
- `dart format --output=none --set-exit-if-changed .`, `dart analyze --fatal-infos`, `dart test` (unit) must be green before every commit that touches code; the conformance suite (`tool/conformance.sh`) must be green before the final task.
- Never invent a field or an error string: every wire shape is in `spec/auth.v1.yaml`. When the JS client and the contract disagree, the contract wins (it was read from the handlers).
- No Flutter imports anywhere. No dependency beyond `http` and `crypto` at runtime.
- Do not push, do not tag, do not publish. Commit after every task.

---

### Task 1: Package skeleton, analysis, CI workflows

**Files:** `pubspec.yaml`, `analysis_options.yaml`, `dart_test.yaml`, `lib/ghayma_auth.dart` (empty export list for now), `.github/workflows/ci.yml`, `.github/workflows/publish.yml`, `tool/sync_spec.sh`, `README.md` (keep the stub; Task 9 rewrites it).

- [ ] `pubspec.yaml`: `name: ghayma_auth`, `description: Client for the Ghayma auth service: sign-in, sessions, 2FA, PKCE OAuth and native Google sign-in for Dart and Flutter apps.`, `version: 0.1.0`, `repository: https://github.com/bz-reda/Ghayma-Dart-SDK`, `homepage: https://docs.ghayma.cloud`, `environment: sdk: '>=3.6.0 <4.0.0'`, deps `http: ^1.2.0`, `crypto: ^3.0.0`, dev deps `test: ^1.25.0`, `lints: ^5.0.0` (use the latest versions `dart pub add` resolves; record them).
- [ ] `analysis_options.yaml`: `include: package:lints/recommended.yaml` plus `language: strict-casts: true, strict-inference: true, strict-raw-types: true`.
- [ ] `dart_test.yaml`: `tags: conformance: { skip: "run with tool/conformance.sh" }` so `dart test` alone skips them and `dart test -t conformance --run-skipped` runs them (verify the exact flag combination works; alternative: give the tag no skip and have the tests `skip` themselves when `GHAYMA_AUTH_URL` is unset — pick the one that keeps `dart test` green without Prism).
- [ ] `tool/sync_spec.sh`: `curl -fsSL https://auth.ghayma.tech/openapi.yaml -o spec/auth.v1.yaml`; CI runs it and fails on `git diff --exit-code spec/`.
- [ ] `.github/workflows/ci.yml`: on push/PR; steps: `dart-lang/setup-dart@v1` (stable), `dart pub get`, format check, `dart analyze --fatal-infos`, `dart test`, spec freshness, then a `conformance` job with `actions/setup-node@v4` (node 22), `tool/conformance.sh`.
- [ ] `.github/workflows/publish.yml`: `on: push: tags: ['v[0-9]+.[0-9]+.[0-9]+']`, `permissions: id-token: write`, `jobs: publish: uses: dart-lang/setup-dart/.github/workflows/publish.yml@v1`.
- [ ] `dart pub get && dart analyze --fatal-infos` clean. Commit `chore: package skeleton and CI`.

### Task 2: Errors and the request layer

**Files:** `lib/src/errors.dart`, `lib/src/http.dart`, `test/unit/http_test.dart`.

- `GhaymaAuthException` per spec §2 (`toString()` → `GhaymaAuthException(status, code): message`).
- `AuthHttp` (internal): constructor `(baseUrl, appSlug, http.Client client, {String? serverKey})`; `Future<Map<String, Object?>> send(String method, String path, {Object? body, String? accessToken, RequestOptions? options, Duration timeout = const Duration(seconds: 30)})` → builds `$baseUrl/v1/$appSlug$path`, JSON body, `Authorization: Bearer` when a token is given, server-key + `X-Ghayma-Client-IP` only when both `serverKey` and `options.clientIp` are set; non-2xx → parse `{error, code}` and throw `GhaymaAuthException` (429 → code `rate_limited` unless the body carries one, `retryAfter` from the header as seconds or HTTP-date); transport errors → `network_error`; `TimeoutException` → `timeout` (status 408). 204/empty bodies return `{}`.
- Tests (MockClient): URL/headers/body for a POST; bearer header; both-or-neither server-key rule; error mapping for 400 with code, 401 without code, 429 with `Retry-After: 7`, invalid JSON body, timeout.
- Commit `feat: request layer and error type`.

### Task 3: Models from the contract

**Files:** `lib/src/models/user.dart`, `session.dart`, `login_result.dart`, `register_result.dart`, `two_factor.dart`, `misc.dart` (ResetTokenInfo, EmailChangeRequest, RequestOptions, OAuthProvider, OAuthStart, AuthEvent, AuthState); `test/unit/models_test.dart`.

- Read `components.schemas` in `spec/auth.v1.yaml` and mirror every property with the right Dart type; unknown JSON keys are ignored; `expires_at`/`created_at`/`last_login_at` parse as `DateTime` (UTC). `Session.fromJson` computes `expiresAt = now + expiresIn` and `toJson` persists it as `expires_at_ms`.
- `LoginResult.fromJson(Map)` picks the variant by the discriminating keys `two_fa_required` / `two_fa_enrollment_required`; `RegisterResult.fromJson` by the presence of `access_token`.
- Tests: parse every `success` example from the spec (load the YAML in the test with `package:yaml`? — no new runtime dep; a dev dep `yaml` is fine) and round-trip `Session` through `toJson`/`fromJson`.
- Commit `feat: models mirrored from the contract`.

### Task 4: Session store, storage seam, refresh scheduling

**Files:** `lib/src/session.dart`, `test/unit/session_test.dart`.

- `TokenStorage`, `InMemoryTokenStorage` (spec §2).
- `SessionStore` (internal): holds `Session?`, `load(storage)`, `save`, `clear`, `isExpiringWithin(Duration)`; JSON string persistence.
- Refresh scheduling lives in `GhaymaAuth` (Task 5) with an injectable `Timer`-free seam: `Duration? get refreshDelay` computed from `expiresAt - 60 s`; tests assert the delay, not real time.
- Tests: persist/restore, expiry math, clear.
- Commit `feat: session store and TokenStorage`.

### Task 5: `GhaymaAuth` core — sessions, email/password, profile

**Files:** `lib/src/client.dart`, `lib/ghayma_auth.dart` (exports), `test/unit/client_test.dart`.

- Implement the constructor, `init`, `dispose`, state getters, `onAuthStateChange` (broadcast `StreamController`), `getAccessToken` (refresh when within 30 s of expiry), the email/password and profile methods from spec §2, `refresh` (rotation: store the returned pair; on 401 clear + `signedOut` + rethrow), `logout` (best-effort POST, always clears), the refresh `Timer` (60 s before expiry; cancelled on dispose/clear/new session).
- Every method's path, body and response come from the contract: `/register`, `/login`, `/2fa/verify`, `/2fa/totp/enroll`, `/2fa/totp/confirm`, `/2fa/recovery/regenerate`, `/2fa/disable`, `/refresh`, `/logout`, `/forgot-password`, `/reset-password`, `/verify-reset-token`, `/resend-verification`, `/me` (GET/PATCH/DELETE), `/change-password`, `/email/change-request` (POST/DELETE).
- Tests with MockClient: register (session + verification_required), login (three shapes), verify2fa stores the session and emits `signedIn`, refresh rotation + failure path, logout clears even when the POST fails, getAccessToken triggers refresh when near expiry, updateUser emits `userUpdated`, `init` restores from storage, both-or-neither headers via `RequestOptions(clientIp)`.
- Commit `feat: GhaymaAuth core`.

### Task 6: PKCE and OAuth

**Files:** `lib/src/pkce.dart`, `lib/src/client.dart` (OAuth section), `test/unit/pkce_test.dart`, `test/unit/oauth_test.dart`.

- `Pkce.generate()`: 32 random bytes from `Random.secure()` → base64url without padding (43 chars); `Pkce.challenge(verifier)` = base64url-nopad(sha256). Pin the RFC 7636 vector (`dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`).
- `oauthUrl`: `$baseUrl/v1/$appSlug/auth/${provider.name}?redirect_uri=<percent-encoded>` plus `&code_challenge=…&code_challenge_method=S256` when given (use `Uri.encodeComponent`).
- `startOAuth`: generate, remember the verifier, return `OAuthStart(url, codeVerifier, codeChallenge)`.
- `handleRedirect(uri, {codeVerifier})`: `error` query param → throw `GhaymaAuthException(400, 'oauth_error', error)`; no `code` → throw `invalid_request`; verifier = argument ?? remembered ?? throw `invalid_grant` ("no PKCE verifier for this redirect"); `exchangeCode`; forget the verifier on success.
- `exchangeCode` → POST `/oauth/exchange` `{code, code_verifier}` → Session, store, `signedIn`. `signInWithIdToken` → POST `/oauth/id-token` `{provider, id_token, nonce?}` → Session, store, `signedIn`.
- Tests: vector, URL bytes (a redirect URI with `~` and `!` stays as `Uri.encodeComponent` encodes it), startOAuth/handleRedirect happy path with a custom-scheme redirect `com.example.app://callback?code=abc`, `?error=denied`, missing verifier, explicit verifier override, exchange body, id-token body with and without nonce.
- Commit `feat: PKCE OAuth and native sign-in`.

### Task 7: Conformance suite against Prism

**Files:** `tool/conformance.sh`, `test/conformance/conformance_test.dart`, `test/conformance/prefer_client.dart`.

- `PreferClient extends http.BaseClient` wrapping the real client and adding a `Prefer` header set per test (`code=…`, `example=…`).
- `tool/conformance.sh`: `npx --yes @stoplight/prism-cli@5 mock spec/auth.v1.yaml -p 4010 --errors &`, poll `http://127.0.0.1:4010/v1/demo/.well-known/jwks.json` until 200 (max 30 s), `GHAYMA_AUTH_URL=http://127.0.0.1:4010 dart test -t conformance --run-skipped` (or the equivalent chosen in Task 1), kill Prism, propagate the exit code.
- Tests (skipped unless `GHAYMA_AUTH_URL` is set): one per SDK method against its `success` example asserting a parsed result and no 422; plus `login` → `two_fa_required` and `enrollment_required` (`Prefer: example=…`), `register` → `verification_required` (`Prefer: code=201, example=verification_required` — check the exact status the spec documents), `login` 401 `invalid_credentials`, `exchangeCode` 400 `invalid_grant`, `signInWithIdToken` 401 `invalid_token`, a 429 with `Retry-After` mapped to `retryAfter`, `oauthUrl` GET → Prism answers the 307 (assert the status only).
- Run `tool/conformance.sh` locally → green. Commit `test: conformance suite against the published contract`.

### Task 8: Example

**Files:** `example/main.dart` — a runnable pure-Dart walkthrough (register, login handling the three shapes, getUser, PKCE URL + exchange with a pasted code, signInWithIdToken), reading `GHAYMA_APP_SLUG` from the environment. `dart analyze` clean. Commit `docs: example`.

### Task 9: README and CHANGELOG

**Files:** `README.md`, `CHANGELOG.md`.

README sections: Install (`dart pub add ghayma_auth`), Quick start (Dart), Flutter integration — (a) a `SecureTokenStorage implements TokenStorage` adapter over `flutter_secure_storage` (12 lines), (b) OAuth with `flutter_web_auth_2` 5.x: `final start = await auth.startOAuth(OAuthProvider.google, redirectUri: 'com.example.app://callback'); final result = await FlutterWebAuth2.authenticate(url: start.url, callbackUrlScheme: 'com.example.app'); await auth.handleRedirect(Uri.parse(result));`, (c) native Google sign-in with `google_sign_in` 7.x → `idToken` → `signInWithIdToken`, (d) `init()` at startup and `onAuthStateChange` for routing; Server usage (`serverKey`, `clientIp`); Errors (`GhaymaAuthException` codes); Console setup (Allowed Origins deep link, Native client IDs) with a link to https://docs.ghayma.cloud/guides/oauth-mobile; Contract & conformance (spec URL, `tool/conformance.sh`); Development; License.
CHANGELOG: `## 0.1.0` — initial release, the surface list, PKCE-only OAuth, contract-conformance tested.
Commit `docs: README and changelog for 0.1.0`.

### Task 10: Final verification

- [ ] `dart format --output=none --set-exit-if-changed . && dart analyze --fatal-infos && dart test && tool/conformance.sh` all green; `dart pub publish --dry-run` reports no errors (warnings about the private repo are fine).
- [ ] `git status` clean apart from `.superpowers/`. Write `.superpowers/pr-body.md` (untracked): what the package covers, the two test layers, how to publish 0.1.0 (Reda: `dart pub publish` from the tagged checkout, then enable automated publishing for the package on pub.dev with tag pattern `v{{version}}`), and the Flutter companion as a follow-up. No attribution. Do not push.
