import 'dart:async';
import 'dart:convert';

import 'package:ghayma_auth/src/errors.dart';
import 'package:ghayma_auth/src/http.dart';
import 'package:ghayma_auth/src/models/misc.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

AuthHttp _http(MockClient client, {String? serverKey}) =>
    AuthHttp('https://auth.example.test/', 'my-app', client,
        serverKey: serverKey);

void main() {
  group('send', () {
    test('builds the URL, headers and JSON body of a POST', () async {
      late http.Request seen;
      final api = _http(MockClient((request) async {
        seen = request;
        return http.Response('{"message":"ok"}', 200);
      }));

      final result = await api
          .send('POST', '/login', body: {'email': 'a@b.c', 'password': 'x'});

      expect(seen.method, 'POST');
      expect(seen.url.toString(), 'https://auth.example.test/v1/my-app/login');
      expect(seen.headers['Content-Type'], startsWith('application/json'));
      expect(jsonDecode(seen.body), {'email': 'a@b.c', 'password': 'x'});
      expect(seen.headers.containsKey('Authorization'), isFalse);
      expect(result, {'message': 'ok'});
    });

    test('sends the bearer header when a token is given', () async {
      late http.Request seen;
      final api = _http(MockClient((request) async {
        seen = request;
        return http.Response('{}', 200);
      }));

      await api.send('GET', '/me', accessToken: 'tok');

      expect(seen.headers['Authorization'], 'Bearer tok');
    });

    test('sends server key and client IP together, or neither', () async {
      final seen = <String, String>{};
      Future<http.Response> record(http.Request request) async {
        seen
          ..clear()
          ..addAll(request.headers);
        return http.Response('{}', 200);
      }

      final withKey = _http(MockClient(record), serverKey: 'ghs_secret');
      await withKey.send('POST', '/login',
          options: const RequestOptions(clientIp: '203.0.113.7'));
      expect(seen['X-Ghayma-Server-Key'], 'ghs_secret');
      expect(seen['X-Ghayma-Client-IP'], '203.0.113.7');

      // A key but no IP: neither header.
      await withKey.send('POST', '/login');
      expect(seen.containsKey('X-Ghayma-Server-Key'), isFalse);
      expect(seen.containsKey('X-Ghayma-Client-IP'), isFalse);

      // An IP but no key: neither header.
      final noKey = _http(MockClient(record));
      await noKey.send('POST', '/login',
          options: const RequestOptions(clientIp: '203.0.113.7'));
      expect(seen.containsKey('X-Ghayma-Server-Key'), isFalse);
      expect(seen.containsKey('X-Ghayma-Client-IP'), isFalse);
    });

    test('drops a client IP that is not a bare literal', () async {
      final seen = <String, String>{};
      final api = _http(MockClient((request) async {
        seen
          ..clear()
          ..addAll(request.headers);
        return http.Response('{}', 200);
      }), serverKey: 'ghs_secret');

      await api.send('POST', '/login',
          options: const RequestOptions(clientIp: '203.0.113.7, 198.51.100.2'));

      expect(seen.containsKey('X-Ghayma-Server-Key'), isFalse);
      expect(seen.containsKey('X-Ghayma-Client-IP'), isFalse);
    });

    test('treats an empty body as an empty object', () async {
      final api = _http(MockClient((_) async => http.Response('', 204)));
      expect(await api.send('DELETE', '/email/change-request'), isEmpty);
    });
  });

  group('error mapping', () {
    test('400 with a code keeps the service code and message', () async {
      final api = _http(MockClient((_) async => http.Response(
          '{"error":"invalid or expired code","code":"invalid_grant"}', 400)));

      await expectLater(
        api.send('POST', '/oauth/exchange'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 400)
            .having((e) => e.code, 'code', 'invalid_grant')
            .having((e) => e.message, 'message', 'invalid or expired code')
            .having((e) => e.retryAfter, 'retryAfter', isNull)),
      );
    });

    test('401 without a code falls back to auth_error', () async {
      final api = _http(MockClient((_) async =>
          http.Response('{"error":"invalid email or password"}', 401)));

      await expectLater(
        api.send('POST', '/login'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 401)
            .having((e) => e.code, 'code', 'auth_error')
            .having((e) => e.message, 'message', 'invalid email or password')),
      );
    });

    test('429 defaults to rate_limited and reads Retry-After', () async {
      final api = _http(MockClient((_) async => http.Response(
            '{"error":"too many requests, please try again later"}',
            429,
            headers: {'retry-after': '7'},
          )));

      await expectLater(
        api.send('POST', '/login'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.code, 'code', 'rate_limited')
            .having((e) => e.retryAfter, 'retryAfter', 7)),
      );
    });

    test('a body that is not JSON still produces a status message', () async {
      final api = _http(
          MockClient((_) async => http.Response('<html>gateway</html>', 502)));

      await expectLater(
        api.send('GET', '/me'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 502)
            .having((e) => e.code, 'code', 'auth_error')
            .having(
                (e) => e.message, 'message', 'Request failed with status 502')),
      );
    });

    test('a transport failure maps to network_error', () async {
      final api = _http(MockClient((_) async => throw const SocketFailure()));

      await expectLater(
        api.send('GET', '/me'),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 0)
            .having((e) => e.code, 'code', 'network_error')),
      );
    });

    test('a slow response maps to timeout with status 408', () async {
      final api = _http(MockClient((_) async {
        await Future<void>.delayed(const Duration(milliseconds: 200));
        return http.Response('{}', 200);
      }));

      await expectLater(
        api.send('GET', '/me', timeout: const Duration(milliseconds: 20)),
        throwsA(isA<GhaymaAuthException>()
            .having((e) => e.status, 'status', 408)
            .having((e) => e.code, 'code', 'timeout')),
      );
    });

    test('toString names the status and code', () {
      expect(
        const GhaymaAuthException(401, 'invalid_token', 'invalid id token')
            .toString(),
        'GhaymaAuthException(401, invalid_token): invalid id token',
      );
    });
  });

  group('parseRetryAfter', () {
    final now = DateTime.utc(1994, 11, 6, 8, 49, 37);

    test('reads whole seconds', () {
      expect(parseRetryAfter('7'), 7);
      expect(parseRetryAfter(' 7 '), 7);
      expect(parseRetryAfter('0.4'), 1);
    });

    test('reads an HTTP-date as seconds from now', () {
      expect(parseRetryAfter('Sun, 06 Nov 1994 08:50:07 GMT', now: now), 30);
    });

    test('never goes negative', () {
      expect(parseRetryAfter('-5'), 0);
      expect(parseRetryAfter('Sun, 06 Nov 1994 08:49:07 GMT', now: now), 0);
    });

    test('is null when absent or unparsable', () {
      expect(parseRetryAfter(null), isNull);
      expect(parseRetryAfter(''), isNull);
      expect(parseRetryAfter('soon'), isNull);
    });
  });
}

class SocketFailure implements Exception {
  const SocketFailure();
}
