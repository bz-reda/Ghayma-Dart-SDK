@Tags(['conformance'])
library;

import 'dart:io';

import 'package:ghayma_auth/ghayma_auth.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

import 'prefer_client.dart';

/// The Prism mock of `spec/auth.v1.yaml`; `tool/conformance.sh` starts it.
final String baseUrl = Platform.environment['GHAYMA_AUTH_URL'] ??
    (throw StateError('GHAYMA_AUTH_URL is unset — run tool/conformance.sh'));

const _appSlug = 'demo';
const _email = 'user@example.com';
const _password = 's3cret-passphrase';
const _redirectUri = 'com.example.app://callback';

/// A client against the mock, plus the transport whose `Prefer` header picks
/// which documented response comes back.
class Harness {
  final PreferClient transport;
  final GhaymaAuth auth;

  Harness(this.transport, this.auth);

  set prefer(String? value) => transport.prefer = value;
}

Harness harness() {
  final transport = PreferClient(http.Client());
  final auth = GhaymaAuth(
    appSlug: _appSlug,
    baseUrl: baseUrl,
    autoRefresh: false,
    httpClient: transport,
  );
  addTearDown(() {
    auth.dispose();
    transport.close();
  });
  return Harness(transport, auth);
}

/// A harness holding the session the authenticated endpoints need.
Future<Harness> signedIn() async {
  final h = harness();
  final result = await h.auth.login(email: _email, password: _password);
  expect(result, isA<LoginSuccess>());
  return h;
}

void main() {
  group('registration', () {
    test('register returns the session of the success example', () async {
      final h = harness();

      final result = await h.auth
          .register(email: _email, password: _password, name: 'Sample User');

      expect(result, isA<RegisterSuccess>());
      final session = (result as RegisterSuccess).session;
      expect(session.tokenType, 'Bearer');
      expect(session.expiresIn, 900);
      expect(session.user.email, _email);
      expect(h.auth.isAuthenticated, isTrue);
    });

    test('register answers verification_required without tokens', () async {
      final h = harness()..prefer = 'code=201, example=verification_required';

      final result = await h.auth.register(email: _email, password: _password);

      expect(result, isA<VerificationRequired>());
      expect((result as VerificationRequired).user.emailVerified, isFalse);
      expect(h.auth.isAuthenticated, isFalse);
    });
  });

  group('login', () {
    test('the success example signs in', () async {
      final h = harness();

      final result = await h.auth.login(email: _email, password: _password);

      expect(result, isA<LoginSuccess>());
      expect(h.auth.currentUser!.email, _email);
    });

    test('two_fa_required carries a challenge token', () async {
      final h = harness()..prefer = 'example=two_fa_required';

      final result = await h.auth.login(email: _email, password: _password);

      expect(result, isA<TwoFaRequired>());
      expect((result as TwoFaRequired).challengeToken, isNotEmpty);
      expect(result.methods, contains('totp'));
    });

    test('enrollment_required carries an enrol token', () async {
      final h = harness()..prefer = 'example=enrollment_required';

      final result = await h.auth.login(email: _email, password: _password);

      expect(result, isA<TwoFaEnrollmentRequired>());
      expect((result as TwoFaEnrollmentRequired).enrollToken, isNotEmpty);
    });

    test('invalid_credentials maps to a 401 exception', () async {
      final h = harness()..prefer = 'code=401, example=invalid_credentials';

      await expectLater(
        h.auth.login(email: _email, password: 'wrong-passphrase'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 401)
            .having((e) => e.message, 'message', 'invalid email or password')),
      );
    });

    test('a disabled account maps to a 403 exception', () async {
      final h = harness()..prefer = 'code=403, example=disabled';

      await expectLater(
        h.auth.login(email: _email, password: _password),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 403)
            .having((e) => e.message, 'message', 'account is disabled')),
      );
    });

    test('rate limiting maps to retryAfter', () async {
      final h = harness()..prefer = 'code=429, example=rate_limited';

      await expectLater(
        h.auth.login(email: _email, password: _password),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 429)
            .having((e) => e.code, 'code', 'rate_limited')
            .having((e) => e.retryAfter, 'retryAfter', isNotNull)),
      );
    });
  });

  group('two-factor', () {
    test('verify2fa returns the withheld session', () async {
      final h = harness();

      final session = await h.auth
          .verify2fa(challengeToken: '4c1d8ab2e3f5', code: '123456');

      expect(session.accessToken, isNotEmpty);
      expect(h.auth.isAuthenticated, isTrue);
    });

    test('enrollTotp with an enrol token returns a secret', () async {
      final h = harness();

      final enrollment = await h.auth.enrollTotp(enrollToken: '7b2e9c40a1d6');

      expect(enrollment.secret, isNotEmpty);
      expect(enrollment.otpauthUri, startsWith('otpauth://'));
    });

    test('enrollTotp works with a bearer token too', () async {
      final h = await signedIn();

      final enrollment = await h.auth.enrollTotp();

      expect(enrollment.secret, isNotEmpty);
    });

    test('confirmTotp returns the recovery codes', () async {
      final h = await signedIn();

      final confirmation = await h.auth.confirmTotp(code: '123456');

      expect(confirmation.enabled, isTrue);
      expect(confirmation.recoveryCodes, isNotEmpty);
      expect(confirmation.session, isNull);
    });

    test('the enforced-enrolment example completes the login', () async {
      final h = harness()..prefer = 'example=success_forced_enrollment';

      final confirmation =
          await h.auth.confirmTotp(code: '123456', enrollToken: '7b2e9c40a1d6');

      expect(confirmation.session, isNotNull);
      expect(h.auth.isAuthenticated, isTrue);
    });

    test('regenerateRecoveryCodes returns a fresh set', () async {
      final h = await signedIn();

      final codes = await h.auth
          .regenerateRecoveryCodes(password: _password, code: '123456');

      expect(codes, isNotEmpty);
    });

    test('disable2fa succeeds', () async {
      final h = await signedIn();

      await h.auth.disable2fa(password: _password, code: '123456');

      expect(h.auth.isAuthenticated, isTrue);
    });
  });

  group('session', () {
    test('refresh rotates the pair', () async {
      final h = await signedIn();

      final pair = await h.auth.refresh();

      expect(pair.accessToken, isNotEmpty);
      expect(pair.refreshToken, isNotEmpty);
      expect(pair.tokenType, 'Bearer');
      expect(h.auth.currentSession!.refreshToken, pair.refreshToken);
    });

    test('a rejected refresh token clears the session', () async {
      final h = await signedIn();
      h.prefer = 'code=401, example=invalid_token';

      await expectLater(h.auth.refresh(), throwsA(isA<GhaymaAuthException>()));

      expect(h.auth.isAuthenticated, isFalse);
    });

    test('logout revokes the token and clears the session', () async {
      final h = await signedIn();

      await h.auth.logout();

      expect(h.auth.isAuthenticated, isFalse);
    });

    test('getAccessToken hands back the issued token', () async {
      final h = await signedIn();

      expect(await h.auth.getAccessToken(), h.auth.currentSession!.accessToken);
    });
  });

  group('password and verification', () {
    test('forgotPassword is accepted', () async {
      await harness().auth.forgotPassword(email: _email);
    });

    test('resetPassword is accepted', () async {
      await harness()
          .auth
          .resetPassword(token: '5e1f0a7c9d24', password: 'new-passphrase');
    });

    test('verifyResetToken returns the account email', () async {
      final info = await harness().auth.verifyResetToken(token: '5e1f0a7c9d24');

      expect(info.valid, isTrue);
      expect(info.email, _email);
    });

    test('resendVerification is accepted', () async {
      await harness().auth.resendVerification(email: _email);
    });
  });

  group('profile', () {
    test('getUser returns the profile behind the envelope', () async {
      final h = await signedIn();

      final user = await h.auth.getUser();

      expect(user.email, _email);
      expect(user.provider, 'email');
      expect(user.createdAt.isUtc, isTrue);
    });

    test('updateUser returns the updated profile', () async {
      final h = await signedIn();

      final user = await h.auth
          .updateUser(name: 'Sample User', metadata: {'locale': 'fr'});

      expect(user.id, isNotEmpty);
    });

    test('changeEmail returns the confirmation expiry', () async {
      final h = await signedIn();

      final request = await h.auth.changeEmail(
          newEmail: 'new-address@example.com', currentPassword: _password);

      expect(request.message, isNotEmpty);
      expect(request.expiresAt.isUtc, isTrue);
    });

    test('cancelEmailChange is accepted', () async {
      final h = await signedIn();

      await h.auth.cancelEmailChange();
    });

    test('changePassword clears the revoked session', () async {
      final h = await signedIn();

      await h.auth.changePassword(
          currentPassword: _password, newPassword: 'new-passphrase');

      expect(h.auth.isAuthenticated, isFalse);
    });

    test('deleteAccount clears the session', () async {
      final h = await signedIn();

      await h.auth.deleteAccount(password: _password);

      expect(h.auth.isAuthenticated, isFalse);
    });
  });

  group('OAuth', () {
    test('the sign-in URL redirects to the provider', () async {
      final auth = harness().auth;
      final client = http.Client();
      addTearDown(client.close);

      final url = auth.oauthUrl(OAuthProvider.google,
          redirectUri: _redirectUri,
          codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
      final request = http.Request('GET', Uri.parse(url))
        ..followRedirects = false;
      final response = await client.send(request);
      await response.stream.drain<void>();

      expect(response.statusCode, 307);
    });

    test('startOAuth then handleRedirect exchanges the code', () async {
      final h = harness();

      final start = await h.auth
          .startOAuth(OAuthProvider.google, redirectUri: _redirectUri);
      expect(start.codeChallenge, Pkce.challenge(start.codeVerifier));

      final session = await h.auth
          .handleRedirect(Uri.parse('$_redirectUri?code=6d3b17f0c94a'));

      expect(session.user.provider, 'google');
      expect(h.auth.isAuthenticated, isTrue);
    });

    test('exchangeCode returns a session', () async {
      final h = harness();
      final pkce = await Pkce.generate();

      final session = await h.auth
          .exchangeCode(code: '6d3b17f0c94a', codeVerifier: pkce.codeVerifier);

      expect(session.accessToken, isNotEmpty);
      expect(session.user.email, _email);
    });

    test('a spent code maps to invalid_grant', () async {
      final h = harness()..prefer = 'code=400, example=invalid_grant';
      final pkce = await Pkce.generate();

      await expectLater(
        h.auth.exchangeCode(code: 'spent', codeVerifier: pkce.codeVerifier),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 400)
            .having((e) => e.code, 'code', 'invalid_grant')),
      );
    });

    test('signInWithIdToken returns a session', () async {
      final h = harness();

      final session = await h.auth
          .signInWithIdToken(idToken: 'eyJhbGciOiJSUzI1NiJ9', nonce: '7f3a1c');

      expect(session.user.provider, 'google');
      expect(h.auth.isAuthenticated, isTrue);
    });

    test('a rejected ID token maps to invalid_token', () async {
      final h = harness()..prefer = 'code=401, example=invalid_token';

      await expectLater(
        h.auth.signInWithIdToken(idToken: 'forged'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 401)
            .having((e) => e.code, 'code', 'invalid_token')),
      );
    });
  });
}
