import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

Map<String, Object?> userJson({
  String id = '3f7c2b90-5e1a-4f2b-9c3d-8a1b2c3d4e5f',
  String email = 'user@example.com',
  String name = 'Sample User',
  bool totpEnabled = false,
}) =>
    {
      'id': id,
      'email': email,
      'name': name,
      'email_verified': true,
      'provider': 'email',
      'totp_enabled': totpEnabled,
      'whatsapp_otp_enabled': false,
      'recovery_codes_left': 0,
      'created_at': '2026-09-01T10:15:00Z',
    };

Map<String, Object?> sessionJson({
  String accessToken = 'access-1',
  String refreshToken = 'refresh-1',
  int expiresIn = 900,
  Map<String, Object?>? user,
}) =>
    {
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'expires_in': expiresIn,
      'token_type': 'Bearer',
      'user': user ?? userJson(),
    };

/// A mock transport that records every request and answers from a queue of
/// [Reply] entries keyed by `METHOD path`.
class Recorder {
  final List<http.Request> requests = <http.Request>[];
  final Map<String, List<Reply>> _replies = <String, List<Reply>>{};

  late final MockClient client = MockClient((request) async {
    requests.add(request);
    final key = '${request.method} ${request.url.path}';
    final queue = _replies[key];
    if (queue == null || queue.isEmpty) {
      return http.Response('{"error":"unexpected $key"}', 500);
    }
    final reply = queue.length == 1 ? queue.first : queue.removeAt(0);
    return http.Response(reply.body, reply.status, headers: reply.headers);
  });

  void on(
    String method,
    String path, {
    Object? json,
    String? body,
    int status = 200,
    Map<String, String> headers = const {},
  }) {
    _replies.putIfAbsent('$method $path', () => <Reply>[]).add(Reply(
          body ?? jsonEncode(json ?? const <String, Object?>{}),
          status,
          headers,
        ));
  }

  http.Request last(String method, String path) =>
      requests.lastWhere((r) => r.method == method && r.url.path == path);

  Map<String, Object?> bodyOf(String method, String path) =>
      jsonDecode(last(method, path).body) as Map<String, Object?>;

  int count(String method, String path) =>
      requests.where((r) => r.method == method && r.url.path == path).length;
}

class Reply {
  final String body;
  final int status;
  final Map<String, String> headers;

  Reply(this.body, this.status, this.headers);
}
