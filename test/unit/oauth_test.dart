import 'package:ghayma_auth/ghayma_auth.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

const _base = 'https://auth.example.test';
const _redirect = 'com.example.app://callback';

GhaymaAuth build(Recorder recorder) => GhaymaAuth(
      appSlug: 'my-app',
      baseUrl: _base,
      autoRefresh: false,
      httpClient: recorder.client,
    );

void main() {
  group('oauthUrl', () {
    test('percent-encodes the redirect URI', () {
      final auth = build(Recorder());
      addTearDown(auth.dispose);

      expect(
        auth.oauthUrl(OAuthProvider.google, redirectUri: _redirect),
        '$_base/v1/my-app/auth/google'
        '?redirect_uri=com.example.app%3A%2F%2Fcallback',
      );
    });

    test('keeps the bytes of the sub-delimiters a form encoding would move',
        () {
      final auth = build(Recorder());
      addTearDown(auth.dispose);

      final url = auth.oauthUrl(OAuthProvider.github,
          redirectUri: 'https://app.example.com/cb~(1)!?a=b c');

      expect(
        url,
        '$_base/v1/my-app/auth/github?redirect_uri='
        'https%3A%2F%2Fapp.example.com%2Fcb~(1)!%3Fa%3Db%20c',
      );
    });

    test('adds the challenge and pins S256', () {
      final auth = build(Recorder());
      addTearDown(auth.dispose);

      final url = auth.oauthUrl(OAuthProvider.google,
          redirectUri: _redirect, codeChallenge: 'abc-123_x');

      expect(url,
          endsWith('&code_challenge=abc-123_x&code_challenge_method=S256'));
    });
  });

  group('startOAuth', () {
    test('mints a verifier and puts its challenge in the URL', () async {
      final auth = build(Recorder());
      addTearDown(auth.dispose);

      final start =
          await auth.startOAuth(OAuthProvider.google, redirectUri: _redirect);

      expect(start.codeChallenge, Pkce.challenge(start.codeVerifier));
      expect(start.url, contains('code_challenge=${start.codeChallenge}'));
      expect(start.url, contains('code_challenge_method=S256'));
      expect(start.url, startsWith('$_base/v1/my-app/auth/google?'));
    });
  });

  group('handleRedirect', () {
    test('exchanges the code with the remembered verifier', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/exchange', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);
      final events = auth.onAuthStateChange.toList();

      final start =
          await auth.startOAuth(OAuthProvider.google, redirectUri: _redirect);
      final session =
          await auth.handleRedirect(Uri.parse('$_redirect?code=abc'));

      expect(session.accessToken, 'access-1');
      expect(auth.isAuthenticated, isTrue);
      expect(recorder.bodyOf('POST', '/v1/my-app/oauth/exchange'),
          {'code': 'abc', 'code_verifier': start.codeVerifier});

      auth.dispose();
      expect((await events).map((e) => e.event), [AuthEvent.signedIn]);
    });

    test('forgets the verifier once the exchange succeeds', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/exchange', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.startOAuth(OAuthProvider.google, redirectUri: _redirect);
      await auth.handleRedirect(Uri.parse('$_redirect?code=abc'));

      await expectLater(
        auth.handleRedirect(Uri.parse('$_redirect?code=def')),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.code, 'code', 'invalid_grant')),
      );
    });

    test('an explicit verifier overrides the remembered one', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/exchange', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.startOAuth(OAuthProvider.google, redirectUri: _redirect);
      await auth.handleRedirect(Uri.parse('$_redirect?code=abc'),
          codeVerifier: 'a-verifier-from-storage');

      expect(recorder.bodyOf('POST', '/v1/my-app/oauth/exchange'),
          {'code': 'abc', 'code_verifier': 'a-verifier-from-storage'});
    });

    test('works with no startOAuth when the verifier is supplied', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/exchange', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);

      final session = await auth.handleRedirect(
          Uri.parse('$_redirect?code=abc'),
          codeVerifier: 'a-verifier-from-storage');

      expect(session.accessToken, 'access-1');
    });

    test('a provider error becomes oauth_error', () async {
      final recorder = Recorder();
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await expectLater(
        auth.handleRedirect(Uri.parse('$_redirect?error=denied')),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 400)
            .having((e) => e.code, 'code', 'oauth_error')
            .having((e) => e.message, 'message', 'denied')),
      );
      expect(recorder.requests, isEmpty);
    });

    test('a redirect with no code is invalid_request', () async {
      final auth = build(Recorder());
      addTearDown(auth.dispose);

      await expectLater(
        auth.handleRedirect(Uri.parse('$_redirect?state=xyz')),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 400)
            .having((e) => e.code, 'code', 'invalid_request')),
      );
    });

    test('no verifier at all is invalid_grant', () async {
      final auth = build(Recorder());
      addTearDown(auth.dispose);

      await expectLater(
        auth.handleRedirect(Uri.parse('$_redirect?code=abc')),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 400)
            .having((e) => e.code, 'code', 'invalid_grant')
            .having((e) => e.message, 'message',
                'no PKCE verifier for this redirect')),
      );
    });

    test('keeps the verifier when the exchange fails', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/exchange',
            status: 400,
            json: {'error': 'invalid or expired code', 'code': 'invalid_grant'})
        ..on('POST', '/v1/my-app/oauth/exchange', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);

      final start =
          await auth.startOAuth(OAuthProvider.google, redirectUri: _redirect);
      await expectLater(auth.handleRedirect(Uri.parse('$_redirect?code=abc')),
          throwsA(isA<GhaymaAuthException>()));

      await auth.handleRedirect(Uri.parse('$_redirect?code=def'));
      expect(recorder.bodyOf('POST', '/v1/my-app/oauth/exchange'),
          {'code': 'def', 'code_verifier': start.codeVerifier});
    });
  });

  group('exchangeCode', () {
    test('posts the code and verifier and signs in', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/exchange', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);

      final session = await auth.exchangeCode(
          code: '6d3b17f0c94a',
          codeVerifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');

      expect(session.user.email, 'user@example.com');
      expect(auth.isAuthenticated, isTrue);
      expect(recorder.bodyOf('POST', '/v1/my-app/oauth/exchange'), {
        'code': '6d3b17f0c94a',
        'code_verifier': 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      });
    });

    test('surfaces invalid_grant from the service', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/exchange', status: 400, json: {
          'error': 'invalid or expired code',
          'code': 'invalid_grant',
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await expectLater(
        auth.exchangeCode(code: 'spent', codeVerifier: 'v'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.code, 'code', 'invalid_grant')),
      );
      expect(auth.isAuthenticated, isFalse);
    });
  });

  group('signInWithIdToken', () {
    test('defaults to google and omits an absent nonce', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/id-token', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.signInWithIdToken(idToken: 'eyJhbGciOi');

      expect(recorder.bodyOf('POST', '/v1/my-app/oauth/id-token'),
          {'provider': 'google', 'id_token': 'eyJhbGciOi'});
      expect(auth.isAuthenticated, isTrue);
    });

    test('sends the nonce when there is one', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/id-token', json: sessionJson());
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await auth.signInWithIdToken(
          idToken: 'eyJhbGciOi', nonce: '7f3a1c9e0b52');

      expect(recorder.bodyOf('POST', '/v1/my-app/oauth/id-token'), {
        'provider': 'google',
        'id_token': 'eyJhbGciOi',
        'nonce': '7f3a1c9e0b52',
      });
    });

    test('surfaces invalid_token from the service', () async {
      final recorder = Recorder()
        ..on('POST', '/v1/my-app/oauth/id-token', status: 401, json: {
          'error': 'invalid id token',
          'code': 'invalid_token',
        });
      final auth = build(recorder);
      addTearDown(auth.dispose);

      await expectLater(
        auth.signInWithIdToken(idToken: 'forged'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 401)
            .having((e) => e.code, 'code', 'invalid_token')),
      );
    });
  });
}
