# ghayma_auth

Dart client for the [Ghayma](https://ghayma.cloud) auth service: email/password
sign-in, sessions with automatic refresh, TOTP two-factor, profile management,
PKCE OAuth and native Google sign-in.

Pure Dart — `http` and `crypto` only, no Flutter dependency — so the same
client runs in a Flutter app, a CLI and a server. Flutter integrates through
two seams: a `TokenStorage` adapter for persistence, and handing the OAuth
redirect URI to `handleRedirect`.

## Install

```sh
dart pub add ghayma_auth
```

## Quick start

```dart
import 'package:ghayma_auth/ghayma_auth.dart';

final auth = GhaymaAuth(appSlug: 'my-app');

await auth.init(); // restore a persisted session

final result = await auth.login(
  email: 'user@example.com',
  password: 's3cret-passphrase',
);

switch (result) {
  case LoginSuccess(:final session):
    print('signed in as ${session.user.email}');
  case TwoFaRequired(:final challengeToken):
    await auth.verify2fa(challengeToken: challengeToken, code: '123456');
  case TwoFaEnrollmentRequired(:final enrollToken):
    final enrollment = await auth.enrollTotp(enrollToken: enrollToken);
    final confirmation = await auth.confirmTotp(
      code: '123456',
      enrollToken: enrollToken,
    );
    print('recovery codes: ${confirmation.recoveryCodes}');
}

final user = await auth.getUser();
await auth.logout();
auth.dispose();
```

`register` answers the same way: `RegisterSuccess` when tokens are issued,
`VerificationRequired` when the app requires a verified email first.

See [`example/main.dart`](example/main.dart) for a runnable walkthrough.

## Flutter integration

### Persist the session

The default `InMemoryTokenStorage` forgets everything when the process exits.
Implement `TokenStorage` over the store of your choice — here
[`flutter_secure_storage`](https://pub.dev/packages/flutter_secure_storage) 11.x:

```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:ghayma_auth/ghayma_auth.dart';

class SecureTokenStorage implements TokenStorage {
  static const _key = 'ghayma_session';
  final _storage = const FlutterSecureStorage();

  @override
  Future<String?> read() => _storage.read(key: _key);

  @override
  Future<void> write(String value) => _storage.write(key: _key, value: value);

  @override
  Future<void> delete() => _storage.delete(key: _key);
}

final auth = GhaymaAuth(appSlug: 'my-app', storage: SecureTokenStorage());
```

### Startup and routing

Call `init()` once before the first frame and route on
`onAuthStateChange` afterwards:

```dart
await auth.init();
runApp(MyApp(signedIn: auth.isAuthenticated));

auth.onAuthStateChange.listen((state) {
  switch (state.event) {
    case AuthEvent.signedIn:
      router.go('/home');
    case AuthEvent.signedOut:
      router.go('/login');
    case AuthEvent.tokenRefreshed:
    case AuthEvent.userUpdated:
      break;
  }
});
```

`getAccessToken()` refreshes when the token is within 30 s of expiry, and a
background timer rotates it 60 s before it lapses, so calling it before each
API request is enough.

### OAuth in a browser tab

PKCE only: no token ever travels through the OS URL handler. Open the URL with
[`flutter_web_auth_2`](https://pub.dev/packages/flutter_web_auth_2) 5.x and hand
the callback straight back:

```dart
final start = await auth.startOAuth(
  OAuthProvider.google,
  redirectUri: 'com.example.app://callback',
);

final result = await FlutterWebAuth2.authenticate(
  url: start.url,
  callbackUrlScheme: 'com.example.app',
);

await auth.handleRedirect(Uri.parse(result));
```

`startOAuth` keeps the verifier in memory and also returns it in
`OAuthStart.codeVerifier`, so an app that hands off to an external browser can
persist it and pass it back: `handleRedirect(uri, codeVerifier: saved)`.

### Native Google sign-in

With [`google_sign_in`](https://pub.dev/packages/google_sign_in) 7.x the
platform hands you an ID token and no browser is involved:

```dart
final account = await GoogleSignIn.instance.authenticate();
final idToken = account.authentication.idToken;

if (idToken != null) {
  await auth.signInWithIdToken(idToken: idToken);
}
```

### Console setup

In the Ghayma console, for your auth app:

- **Allowed Origins** must list the deep link you pass as `redirectUri`
  (`com.example.app://callback`), exactly as written.
- **Native client IDs** must list the iOS and Android OAuth client ids you use
  with `google_sign_in`; the service verifies the ID token against them.

Full walkthrough: <https://docs.ghayma.cloud/guides/oauth-mobile>.

## Server usage

On a Dart server, pass the app's server key (`ghs_…`) and forward the end
user's IP so rate limits are charged to that address rather than to your
server:

```dart
final auth = GhaymaAuth(appSlug: 'my-app', serverKey: Platform.environment['GHAYMA_SERVER_KEY']);

await auth.login(
  email: email,
  password: password,
  options: RequestOptions(clientIp: request.remoteAddress.address),
);
```

The two headers travel together or not at all: without a `serverKey` the
`clientIp` is dropped, and anything that is not a bare IP literal (a whole
`x-forwarded-for` chain, for instance) is dropped too. Never ship a server key
to a client app.

## Errors

Every failure is a `GhaymaAuthException` with a `status`, a `code`, a `message`
and, on rate limits, `retryAfter` in seconds.

| `code` | When |
| --- | --- |
| `invalid_request` | the request was malformed or a field was rejected |
| `invalid_credentials` | wrong password, wrong 2FA code |
| `invalid_grant` | a spent or expired one-time code, challenge or reset token |
| `invalid_token` | a provider ID token that failed verification |
| `rate_limited` | 429; read `retryAfter` |
| `oauth_error` | the provider handed back `?error=` on the redirect |
| `network_error` | the request never reached the service (`status` 0) |
| `timeout` | no answer within 30 s (`status` 408) |
| `auth_error` | anything else the service did not label |

```dart
try {
  await auth.login(email: email, password: password);
} on GhaymaAuthException catch (err) {
  if (err.code == 'rate_limited') {
    print('try again in ${err.retryAfter} s');
  }
}
```

A refresh the service rejects clears the session and emits
`AuthEvent.signedOut` before the error reaches you.

## Contract and conformance

Every request body, response field and error string in this package comes from
the published contract, vendored at
[`spec/auth.v1.yaml`](spec/auth.v1.yaml) and refreshed with `tool/sync_spec.sh`
from <https://auth.ghayma.tech/openapi.yaml>. CI fails when the copy is stale.

Two test layers:

```sh
dart test              # unit tests against a mock transport
tool/conformance.sh    # every method against a Prism mock of the contract
```

The conformance suite starts `@stoplight/prism-cli` on the vendored spec with
`--errors`, so an off-contract request fails the run rather than passing
silently. It needs Node 22 with `npx`.

## Development

```sh
dart pub get
dart format --output=none --set-exit-if-changed .
dart analyze --fatal-infos
dart test
tool/conformance.sh
```

## License

MIT — see [LICENSE](LICENSE).
