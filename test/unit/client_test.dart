import 'dart:convert';

import 'package:ghayma_auth/ghayma_auth.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

const _base = 'https://auth.example.test';

GhaymaAuth build(
  Recorder recorder, {
  TokenStorage? storage,
  String? serverKey,
  bool autoRefresh = false,
}) =>
    GhaymaAuth(
      appSlug: 'my-app',
      baseUrl: _base,
      storage: storage,
      autoRefresh: autoRefresh,
      serverKey: serverKey,
      httpClient: recorder.client,
    );

/// Signs [auth] in with a plain login so authenticated calls have a token.
Future<void> signIn(Recorder recorder, GhaymaAuth auth,
    {int expiresIn = 900}) async {
  recorder.on('POST', '/v1/my-app/login',
      json: sessionJson(expiresIn: expiresIn));
  await auth.login(email: 'user@example.com', password: 's3cret-passphrase');
}

void main() {
  group('construction', () {
    test('rejects an empty app slug', () {
      expect(() => GhaymaAuth(appSlug: ''), throwsArgumentError);
    });

    test('starts signed out', () {
      final auth = build(Recorder());
      addTearDown(auth.dispose);

      expect(auth.isAuthenticated, isFalse);
      expect(auth.currentSession, isNull);
      expect(auth.currentUser, isNull);
    });

    test('trims trailing slashes off the base URL', () async {
      final recorder = Recorder();
      final auth = GhaymaAuth(
        appSlug: 'my-app',
        baseUrl: '$_base//',
        autoRefresh: false,
        httpClient: recorder.client,
      );
      addTearDown(auth.dispose);
      recorder.on('POST', '/v1/my-app/login', json: sessionJson());

      await auth.login(email: 'a@b.c', password: 'x');

      expect(recorder.requests.single.url.toString(), '$_base/v1/my-app/login');
    });
  });

  group('register', () {
    test('stores the session and emits signedIn', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/register', json: sessionJson(), status: 201);
      final auth = build(recorder);
      addTearDown(auth.dispose);
      final events = auth.onAuthStateChange.toList();

      final result = await auth.register(
          email: 'user@example.com',
          password: 's3cret-passphrase',
          name: 'Sample User');

      expect(result, isA<RegisterSuccess>());
      expect(auth.isAuthenticated, isTrue);
      expect(auth.currentUser!.email, 'user@example.com');
      expect(recorder.bodyOf('POST', '/v1/my-app/register'), {
        'email': 'user@example.com',
        'password': 's3cret-passphrase',
        'name': 'Sample User',
      });

      auth.dispose();
      expect((await events).map((e) => e.event), [AuthEvent.signedIn]);
    });

    test('omits a name that was not given', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/register', json: sessionJson(), status: 201);
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.register(email: 'user@example.com', password: 'passphrase');

      expect(recorder.bodyOf('POST', '/v1/my-app/register').containsKey('name'),
          isFalse);
    });

    test('verification_required stores nothing', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/register', status: 201, json: {
          'message': 'account created, please verify your email',
          'user': userJson(),
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);

      final result =
          await auth.register(email: 'user@example.com', password: 'pass1234');

      expect(result, isA<VerificationRequired>());
      expect((result as VerificationRequired).message,
          'account created, please verify your email');
      expect(auth.isAuthenticated, isFalse);
    });
  });

  group('login', () {
    test('a session signs in', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);

      recorder.on('POST', '/v1/my-app/login', json: sessionJson());
      final result =
          await auth.login(email: 'user@example.com', password: 'pass');

      expect(result, isA<LoginSuccess>());
      expect((result as LoginSuccess).session.accessToken, 'access-1');
      expect(auth.isAuthenticated, isTrue);
    });

    test('two_fa_required leaves the client signed out', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/login', json: {
          'two_fa_required': true,
          'challenge_token': '4c1d8ab2e3f5',
          'methods': ['totp'],
          'phone_hint': '',
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);

      final result = await auth.login(email: 'user@example.com', password: 'p');

      expect(result, isA<TwoFaRequired>());
      expect((result as TwoFaRequired).challengeToken, '4c1d8ab2e3f5');
      expect(auth.isAuthenticated, isFalse);
    });

    test('two_fa_enrollment_required leaves the client signed out', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/login', json: {
          'two_fa_enrollment_required': true,
          'enroll_token': '7b2e9c40a1d6',
          'methods': ['totp'],
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);

      final result = await auth.login(email: 'user@example.com', password: 'p');

      expect(result, isA<TwoFaEnrollmentRequired>());
      expect((result as TwoFaEnrollmentRequired).enrollToken, '7b2e9c40a1d6');
      expect(auth.isAuthenticated, isFalse);
    });

    test('401 throws the service error', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/login',
            status: 401, json: {'error': 'invalid email or password'});
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await expectLater(
        auth.login(email: 'user@example.com', password: 'wrong'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 401)
            .having((e) => e.message, 'message', 'invalid email or password')),
      );
      expect(auth.isAuthenticated, isFalse);
    });
  });

  group('two-factor', () {
    test('verify2fa stores the session and emits signedIn', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/2fa/verify', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);
      final events = auth.onAuthStateChange.toList();

      final session =
          await auth.verify2fa(challengeToken: 'challenge', code: '123456');

      expect(session.accessToken, 'access-1');
      expect(auth.isAuthenticated, isTrue);
      expect(recorder.bodyOf('POST', '/v1/my-app/2fa/verify'),
          {'challenge_token': 'challenge', 'code': '123456'});

      auth.dispose();
      expect((await events).map((e) => e.event), [AuthEvent.signedIn]);
    });

    test('enrollTotp uses the bearer token when signed in', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/2fa/totp/enroll', json: {
        'secret': 'JBSWY3DPEHPK3PXP',
        'otpauth_uri': 'otpauth://totp/My%20App:user%40example.com',
      });

      final enrollment = await auth.enrollTotp();

      expect(enrollment.secret, 'JBSWY3DPEHPK3PXP');
      final request = recorder.last('POST', '/v1/my-app/2fa/totp/enroll');
      expect(request.headers['Authorization'], 'Bearer access-1');
      expect(jsonDecode(request.body), isEmpty);
    });

    test('enrollTotp with an enroll token sends no bearer', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/2fa/totp/enroll', json: {
          'secret': 'JBSWY3DPEHPK3PXP',
          'otpauth_uri': 'otpauth://totp/My%20App:user%40example.com',
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.enrollTotp(enrollToken: '7b2e9c40a1d6');

      final request = recorder.last('POST', '/v1/my-app/2fa/totp/enroll');
      expect(request.headers.containsKey('Authorization'), isFalse);
      expect(jsonDecode(request.body), {'enroll_token': '7b2e9c40a1d6'});
    });

    test('confirmTotp returns the recovery codes without a session', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/2fa/totp/confirm', json: {
        'enabled': true,
        'recovery_codes': ['K7T2M-9BQXR', '4WD8N-YH3ZC'],
      });

      final confirmation = await auth.confirmTotp(code: '123456');

      expect(confirmation.enabled, isTrue);
      expect(confirmation.recoveryCodes, ['K7T2M-9BQXR', '4WD8N-YH3ZC']);
      expect(confirmation.session, isNull);
      expect(recorder.bodyOf('POST', '/v1/my-app/2fa/totp/confirm'),
          {'code': '123456'});
    });

    test('confirmTotp on the enforced path completes the login', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/2fa/totp/confirm', json: {
          'enabled': true,
          'recovery_codes': ['K7T2M-9BQXR'],
          ...sessionJson(accessToken: 'forced-access'),
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);
      final events = auth.onAuthStateChange.toList();

      final confirmation =
          await auth.confirmTotp(code: '123456', enrollToken: '7b2e9c40a1d6');

      expect(confirmation.session, isNotNull);
      expect(auth.currentSession!.accessToken, 'forced-access');
      final request = recorder.last('POST', '/v1/my-app/2fa/totp/confirm');
      expect(request.headers.containsKey('Authorization'), isFalse);
      expect(jsonDecode(request.body),
          {'code': '123456', 'enroll_token': '7b2e9c40a1d6'});

      auth.dispose();
      expect((await events).map((e) => e.event), [AuthEvent.signedIn]);
    });

    test('regenerateRecoveryCodes returns the fresh set', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/2fa/recovery/regenerate', json: {
        'recovery_codes': ['K7T2M-9BQXR', '4WD8N-YH3ZC', 'R5PJ6-T1XVA'],
      });

      final codes = await auth.regenerateRecoveryCodes(
          password: 's3cret-passphrase', code: '123456');

      expect(codes, ['K7T2M-9BQXR', '4WD8N-YH3ZC', 'R5PJ6-T1XVA']);
      expect(recorder.bodyOf('POST', '/v1/my-app/2fa/recovery/regenerate'),
          {'password': 's3cret-passphrase', 'code': '123456'});
    });

    test('disable2fa posts the password and code', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/2fa/disable',
          json: {'message': '2FA disabled'});

      await auth.disable2fa(password: 's3cret-passphrase', code: '123456');

      expect(recorder.bodyOf('POST', '/v1/my-app/2fa/disable'),
          {'password': 's3cret-passphrase', 'code': '123456'});
      expect(auth.isAuthenticated, isTrue);
    });
  });

  group('refresh', () {
    test('rotates the pair, keeps the user, emits tokenRefreshed', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      final events = auth.onAuthStateChange.toList();
      recorder.on('POST', '/v1/my-app/refresh', json: {
        'access_token': 'access-2',
        'refresh_token': 'refresh-2',
        'expires_in': 900,
        'token_type': 'Bearer',
      });

      final pair = await auth.refresh();

      expect(pair.accessToken, 'access-2');
      expect(recorder.bodyOf('POST', '/v1/my-app/refresh'),
          {'refresh_token': 'refresh-1'});
      expect(auth.currentSession!.accessToken, 'access-2');
      expect(auth.currentSession!.refreshToken, 'refresh-2');
      expect(auth.currentUser!.email, 'user@example.com');

      auth.dispose();
      expect((await events).map((e) => e.event), [AuthEvent.tokenRefreshed]);
    });

    test('401 clears the session, emits signedOut and rethrows', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      final events = auth.onAuthStateChange.toList();
      recorder.on('POST', '/v1/my-app/refresh',
          status: 401, json: {'error': 'invalid refresh token'});

      await expectLater(
        auth.refresh(),
        throwsA(
            isA<GhaymaAuthException>().having((e) => e.status, 'status', 401)),
      );

      expect(auth.isAuthenticated, isFalse);
      auth.dispose();
      expect((await events).map((e) => e.event), [AuthEvent.signedOut]);
    });

    test('403 reuse detection clears the session too', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/refresh', status: 403, json: {
        'error': 'refresh token reuse detected, all sessions revoked',
      });

      await expectLater(auth.refresh(), throwsA(isA<GhaymaAuthException>()));
      expect(auth.isAuthenticated, isFalse);
    });

    test('a transport failure keeps the session', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/refresh',
          status: 503, body: 'upstream down');

      await expectLater(auth.refresh(), throwsA(isA<GhaymaAuthException>()));
      expect(auth.isAuthenticated, isTrue);
    });

    test('without a session it throws and sends nothing', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await expectLater(
        auth.refresh(),
        throwsA(
            isA<GhaymaAuthException>().having((e) => e.status, 'status', 401)),
      );
      expect(recorder.requests, isEmpty);
    });

    test('concurrent callers share one rotation', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/refresh', json: {
        'access_token': 'access-2',
        'refresh_token': 'refresh-2',
        'expires_in': 900,
        'token_type': 'Bearer',
      });

      await Future.wait([auth.refresh(), auth.refresh(), auth.refresh()]);

      expect(recorder.count('POST', '/v1/my-app/refresh'), 1);
    });
  });

  group('getAccessToken', () {
    test('hands back the stored token when it is fresh', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);

      expect(await auth.getAccessToken(), 'access-1');
      expect(recorder.count('POST', '/v1/my-app/refresh'), 0);
    });

    test('refreshes when the token is within 30 s of expiry', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth, expiresIn: 10);
      recorder.on('POST', '/v1/my-app/refresh', json: {
        'access_token': 'access-2',
        'refresh_token': 'refresh-2',
        'expires_in': 900,
        'token_type': 'Bearer',
      });

      expect(await auth.getAccessToken(), 'access-2');
      expect(recorder.count('POST', '/v1/my-app/refresh'), 1);
    });

    test('throws when signed out', () async {
      final auth = build(Recorder());
      addTearDown(auth.dispose);

      await expectLater(
        auth.getAccessToken(),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 401)
            .having((e) => e.code, 'code', 'auth_error')),
      );
    });
  });

  group('logout', () {
    test('revokes the refresh token and clears the session', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      final events = auth.onAuthStateChange.toList();
      recorder.on('POST', '/v1/my-app/logout', json: {'message': 'logged out'});

      await auth.logout();

      expect(recorder.bodyOf('POST', '/v1/my-app/logout'),
          {'refresh_token': 'refresh-1'});
      expect(auth.isAuthenticated, isFalse);
      auth.dispose();
      expect((await events).map((e) => e.event), [AuthEvent.signedOut]);
    });

    test('clears the session even when the POST fails', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/logout',
          status: 500, json: {'error': 'boom'});

      await auth.logout();

      expect(auth.isAuthenticated, isFalse);
    });

    test('is a no-op when already signed out', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.logout();

      expect(recorder.requests, isEmpty);
    });
  });

  group('password and verification', () {
    test('forgotPassword posts the email without a token', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/forgot-password', json: {
          'message': 'if an account exists with that email, a reset link has '
              'been sent',
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.forgotPassword(email: 'user@example.com');

      final request = recorder.last('POST', '/v1/my-app/forgot-password');
      expect(jsonDecode(request.body), {'email': 'user@example.com'});
      expect(request.headers.containsKey('Authorization'), isFalse);
    });

    test('resetPassword posts the token and the new password', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/reset-password',
            json: {'message': 'password reset successfully, please log in'});
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.resetPassword(token: '5e1f0a7c', password: 'new-passphrase');

      expect(recorder.bodyOf('POST', '/v1/my-app/reset-password'),
          {'token': '5e1f0a7c', 'password': 'new-passphrase'});
    });

    test('verifyResetToken returns the account email', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/verify-reset-token',
            json: {'valid': true, 'email': 'user@example.com'});
      final auth = build(recorder);
      addTearDown(auth.dispose);

      final info = await auth.verifyResetToken(token: '5e1f0a7c');

      expect(info.valid, isTrue);
      expect(info.email, 'user@example.com');
    });

    test('resendVerification posts the email', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/resend-verification', json: {
          'message': 'if an account exists with that email, a verification '
              'link has been sent',
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.resendVerification(email: 'user@example.com');

      expect(recorder.bodyOf('POST', '/v1/my-app/resend-verification'),
          {'email': 'user@example.com'});
    });
  });

  group('profile', () {
    test('getUser unwraps the envelope and updates currentUser', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('GET', '/v1/my-app/me',
          json: {'user': userJson(name: 'Renamed', totpEnabled: true)});

      final user = await auth.getUser();

      expect(user.name, 'Renamed');
      expect(user.totpEnabled, isTrue);
      expect(auth.currentUser!.name, 'Renamed');
      expect(recorder.last('GET', '/v1/my-app/me').headers['Authorization'],
          'Bearer access-1');
    });

    test('updateUser sends only the given fields and emits userUpdated',
        () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      final events = auth.onAuthStateChange.toList();
      recorder.on('PATCH', '/v1/my-app/me',
          json: {'user': userJson(name: 'Renamed')});

      final user =
          await auth.updateUser(name: 'Renamed', metadata: {'locale': 'fr'});

      expect(user.name, 'Renamed');
      expect(recorder.bodyOf('PATCH', '/v1/my-app/me'), {
        'name': 'Renamed',
        'metadata': {'locale': 'fr'},
      });
      auth.dispose();
      expect((await events).map((e) => e.event), [AuthEvent.userUpdated]);
    });

    test('deleteAccount sends the password and clears the session', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder
          .on('DELETE', '/v1/my-app/me', json: {'message': 'account deleted'});

      await auth.deleteAccount(password: 's3cret-passphrase');

      expect(recorder.bodyOf('DELETE', '/v1/my-app/me'),
          {'password': 's3cret-passphrase'});
      expect(auth.isAuthenticated, isFalse);
    });

    test('deleteAccount sends no body for a provider account', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder
          .on('DELETE', '/v1/my-app/me', json: {'message': 'account deleted'});

      await auth.deleteAccount();

      expect(recorder.last('DELETE', '/v1/my-app/me').body, isEmpty);
    });

    test('changePassword clears the session the service revoked', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/change-password',
          json: {'message': 'password changed successfully'});

      await auth.changePassword(
          currentPassword: 'old-passphrase', newPassword: 'new-passphrase');

      expect(recorder.bodyOf('POST', '/v1/my-app/change-password'), {
        'current_password': 'old-passphrase',
        'new_password': 'new-passphrase',
      });
      expect(auth.isAuthenticated, isFalse);
    });

    test('changeEmail returns the expiry and keeps the session', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/email/change-request', json: {
        'message': 'check your new email to confirm the change',
        'expires_at': '2026-09-09T09:30:00Z',
      });

      final request = await auth.changeEmail(
          newEmail: 'new@example.com', currentPassword: 's3cret-passphrase');

      expect(request.expiresAt, DateTime.utc(2026, 9, 9, 9, 30));
      expect(recorder.bodyOf('POST', '/v1/my-app/email/change-request'), {
        'new_email': 'new@example.com',
        'current_password': 's3cret-passphrase',
      });
      expect(auth.isAuthenticated, isTrue);
    });

    test('cancelEmailChange sends an authenticated DELETE', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('DELETE', '/v1/my-app/email/change-request',
          json: {'message': 'pending email change cancelled'});

      await auth.cancelEmailChange();

      expect(
          recorder
              .last('DELETE', '/v1/my-app/email/change-request')
              .headers['Authorization'],
          'Bearer access-1');
    });

    test('an authenticated call without a session throws before sending',
        () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await expectLater(auth.getUser(), throwsA(isA<GhaymaAuthException>()));
      expect(recorder.requests, isEmpty);
    });
  });

  group('storage', () {
    test('init restores the session written by an earlier run', () async {
      final storage = InMemoryTokenStorage();
      final recorder = Recorder();
      final first = build(recorder, storage: storage);
      await signIn(recorder, first);
      first.dispose();

      final second = build(Recorder(), storage: storage);
      addTearDown(second.dispose);
      expect(second.isAuthenticated, isFalse);

      await second.init();

      expect(second.isAuthenticated, isTrue);
      expect(second.currentSession!.accessToken, 'access-1');
      expect(second.currentUser!.email, 'user@example.com');
    });

    test('init on an empty store leaves the client signed out', () async {
      final auth = build(Recorder(), storage: InMemoryTokenStorage());
      addTearDown(auth.dispose);

      await auth.init();

      expect(auth.isAuthenticated, isFalse);
    });

    test('logout wipes the persisted session', () async {
      final storage = InMemoryTokenStorage();
      final recorder = Recorder();
      final auth = build(recorder, storage: storage);
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/logout', json: {'message': 'logged out'});

      await auth.logout();

      expect(await storage.read(), isNull);
    });
  });

  group('server key', () {
    test('forwards the client IP alongside the key', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/login', json: sessionJson());
      final auth = build(recorder, serverKey: 'ghs_secret');
      addTearDown(auth.dispose);

      await auth.login(
          email: 'user@example.com',
          password: 'pass',
          options: const RequestOptions(clientIp: '203.0.113.7'));

      final headers = recorder.last('POST', '/v1/my-app/login').headers;
      expect(headers['X-Ghayma-Server-Key'], 'ghs_secret');
      expect(headers['X-Ghayma-Client-IP'], '203.0.113.7');
    });

    test('sends neither header without a key', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/login', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.login(
          email: 'user@example.com',
          password: 'pass',
          options: const RequestOptions(clientIp: '203.0.113.7'));

      final headers = recorder.last('POST', '/v1/my-app/login').headers;
      expect(headers.containsKey('X-Ghayma-Server-Key'), isFalse);
      expect(headers.containsKey('X-Ghayma-Client-IP'), isFalse);
    });

    test('verify2fa forwards the client IP alongside the key', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/2fa/verify', json: sessionJson());
      final auth = build(recorder, serverKey: 'ghs_secret');
      addTearDown(auth.dispose);

      await auth.verify2fa(
          challengeToken: 'challenge',
          code: '123456',
          options: const RequestOptions(clientIp: '1.2.3.4'));

      final headers = recorder.last('POST', '/v1/my-app/2fa/verify').headers;
      expect(headers['X-Ghayma-Server-Key'], 'ghs_secret');
      expect(headers['X-Ghayma-Client-IP'], '1.2.3.4');
    });

    test('refresh forwards the client IP alongside the key', () async {
      final recorder = Recorder();
      final auth = build(recorder, serverKey: 'ghs_secret');
      addTearDown(auth.dispose);
      await signIn(recorder, auth);
      recorder.on('POST', '/v1/my-app/refresh', json: {
        'access_token': 'access-2',
        'refresh_token': 'refresh-2',
        'expires_in': 900,
        'token_type': 'Bearer',
      });

      await auth.refresh(options: const RequestOptions(clientIp: '1.2.3.4'));

      final headers = recorder.last('POST', '/v1/my-app/refresh').headers;
      expect(headers['X-Ghayma-Server-Key'], 'ghs_secret');
      expect(headers['X-Ghayma-Client-IP'], '1.2.3.4');
    });

    test('verifyResetToken forwards the client IP alongside the key', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/verify-reset-token',
            json: {'valid': true, 'email': 'user@example.com'});
      final auth = build(recorder, serverKey: 'ghs_secret');
      addTearDown(auth.dispose);

      await auth.verifyResetToken(
          token: '5e1f0a7c',
          options: const RequestOptions(clientIp: '1.2.3.4'));

      final headers =
          recorder.last('POST', '/v1/my-app/verify-reset-token').headers;
      expect(headers['X-Ghayma-Server-Key'], 'ghs_secret');
      expect(headers['X-Ghayma-Client-IP'], '1.2.3.4');
    });
  });

  group('auto refresh', () {
    // A 61 s token leaves the timer ~1 s to run once the 60 s lead comes off.
    Recorder shortLivedLogin() => Recorder()
      ..on('POST', '/v1/my-app/login',
          json: {...sessionJson(), 'expires_in': 61})
      ..on('POST', '/v1/my-app/refresh', json: {
        'access_token': 'access-2',
        'refresh_token': 'refresh-2',
        'expires_in': 900,
        'token_type': 'Bearer',
      });

    GhaymaAuth withTimer(Recorder recorder) => GhaymaAuth(
          appSlug: 'my-app',
          baseUrl: _base,
          httpClient: recorder.client,
        );

    test('rotates the token 60 s before it expires', () async {
      final recorder = shortLivedLogin();
      final auth = withTimer(recorder);
      addTearDown(auth.dispose);

      await auth.login(email: 'user@example.com', password: 'p');
      expect(recorder.count('POST', '/v1/my-app/refresh'), 0);

      await Future<void>.delayed(const Duration(milliseconds: 1500));

      expect(recorder.count('POST', '/v1/my-app/refresh'), 1);
      expect(auth.currentSession!.accessToken, 'access-2');
    });

    test('a disposed client stops refreshing', () async {
      final recorder = shortLivedLogin();
      final auth = withTimer(recorder);
      await auth.login(email: 'user@example.com', password: 'p');

      auth.dispose();

      await Future<void>.delayed(const Duration(milliseconds: 1500));
      expect(recorder.count('POST', '/v1/my-app/refresh'), 0);
    });

    test('logout cancels the pending refresh', () async {
      final recorder = shortLivedLogin()
        ..on('POST', '/v1/my-app/logout', json: {'message': 'logged out'});
      final auth = withTimer(recorder);
      addTearDown(auth.dispose);
      await auth.login(email: 'user@example.com', password: 'p');

      await auth.logout();

      await Future<void>.delayed(const Duration(milliseconds: 1500));
      expect(recorder.count('POST', '/v1/my-app/refresh'), 0);
    });
  });
}
