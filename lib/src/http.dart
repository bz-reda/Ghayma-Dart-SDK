import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'errors.dart';
import 'models/misc.dart';

const _serverKeyHeader = 'X-Ghayma-Server-Key';
const _clientIpHeader = 'X-Ghayma-Client-IP';

// Shape guard, not a validator: the characters an IPv4/IPv6 literal may use,
// plus an optional zone id. Enough to drop a comma-joined x-forwarded-for
// chain, "unknown", or anything carrying control characters.
final _ipLiteral = RegExp(r'^[0-9a-fA-F.:]+(%[0-9a-zA-Z._-]+)?$');

/// Request layer: URL building, headers, JSON, error mapping.
class AuthHttp {
  final String baseUrl;
  final String appSlug;
  final http.Client client;
  final String? serverKey;

  AuthHttp(String baseUrl, this.appSlug, this.client, {this.serverKey})
      : baseUrl = baseUrl.replaceAll(RegExp(r'/+$'), '');

  Uri url(String path) => Uri.parse('$baseUrl/v1/$appSlug$path');

  /// Sends [body] as JSON and decodes the JSON object the service answers
  /// with. A 204 or an empty body decodes as `{}`.
  Future<Map<String, Object?>> send(
    String method,
    String path, {
    Object? body,
    String? accessToken,
    RequestOptions? options,
    Duration timeout = const Duration(seconds: 30),
  }) async {
    final request = http.Request(method, url(path));
    request.headers['Content-Type'] = 'application/json';
    if (accessToken != null) {
      request.headers['Authorization'] = 'Bearer $accessToken';
    }

    // Both headers or neither: the service honours a forwarded IP only from a
    // caller that proves itself with the server key.
    final key = serverKey;
    final clientIp = options?.clientIp?.trim();
    if (key != null &&
        clientIp != null &&
        clientIp.isNotEmpty &&
        _ipLiteral.hasMatch(clientIp)) {
      request.headers[_serverKeyHeader] = key;
      request.headers[_clientIpHeader] = clientIp;
    }

    if (body != null) request.body = jsonEncode(body);

    final http.Response response;
    try {
      response = await _roundTrip(request).timeout(timeout);
    } on TimeoutException {
      throw const GhaymaAuthException(408, 'timeout', 'Request timed out');
    } catch (err) {
      throw GhaymaAuthException(0, 'network_error', err.toString());
    }

    final decoded = _decodeObject(response.body);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw _error(response, decoded);
    }
    return decoded ?? const {};
  }

  Future<http.Response> _roundTrip(http.Request request) async =>
      http.Response.fromStream(await client.send(request));

  /// The body as a JSON object, `{}` when empty, null when it is neither.
  Map<String, Object?>? _decodeObject(String body) {
    if (body.trim().isEmpty) return const {};
    try {
      final value = jsonDecode(body);
      return value is Map<String, Object?> ? value : null;
    } on FormatException {
      return null;
    }
  }

  GhaymaAuthException _error(
      http.Response response, Map<String, Object?>? body) {
    final status = response.statusCode;

    final error = body?['error'];
    final message = error is String && error.isNotEmpty
        ? error
        : 'Request failed with status $status';

    final serviceCode = body?['code'];
    final code = serviceCode is String && serviceCode.isNotEmpty
        ? serviceCode
        : (status == 429 ? 'rate_limited' : 'auth_error');

    return GhaymaAuthException(status, code, message,
        retryAfter: parseRetryAfter(response.headers['retry-after']));
  }
}

/// `Retry-After` is either a delay in seconds or an HTTP-date; both become
/// whole seconds. Null when absent or unparsable.
int? parseRetryAfter(String? value, {DateTime? now}) {
  final raw = value?.trim();
  if (raw == null || raw.isEmpty) return null;

  final seconds = num.tryParse(raw);
  if (seconds != null) return seconds.isFinite ? _atLeastZero(seconds) : null;

  final at = _parseHttpDate(raw);
  if (at == null) return null;
  return _atLeastZero(
      at.difference(now ?? DateTime.now()).inMilliseconds / 1000);
}

int _atLeastZero(num seconds) {
  final rounded = seconds.ceil();
  return rounded < 0 ? 0 : rounded;
}

const _months = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec'
];

// IMF-fixdate, the only HTTP-date form a conforming server sends:
// `Sun, 06 Nov 1994 08:49:37 GMT`.
final _imfFixdate = RegExp(
    r'^[A-Za-z]{3}, (\d{2}) ([A-Za-z]{3}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$');

DateTime? _parseHttpDate(String raw) {
  final match = _imfFixdate.firstMatch(raw);
  if (match == null) return null;
  final month = _months.indexOf(match.group(2)!);
  if (month < 0) return null;
  return DateTime.utc(
    int.parse(match.group(3)!),
    month + 1,
    int.parse(match.group(1)!),
    int.parse(match.group(4)!),
    int.parse(match.group(5)!),
    int.parse(match.group(6)!),
  );
}
