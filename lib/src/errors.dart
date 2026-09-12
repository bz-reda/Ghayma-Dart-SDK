/// Every failure the SDK reports, whether it came from the service or from
/// the transport.
class GhaymaAuthException implements Exception {
  /// HTTP status of the response, or 0 when the request never completed.
  final int status;

  /// Machine-readable reason: the service's `code` field when present, else
  /// `rate_limited` (429), `oauth_error` (a provider `?error=`),
  /// `network_error` / `timeout` for transport failures, `auth_error`
  /// otherwise.
  final String code;

  /// Human-readable message, the service's `error` field when present.
  final String message;

  /// Seconds to wait before retrying, from the `Retry-After` header.
  final int? retryAfter;

  const GhaymaAuthException(this.status, this.code, this.message,
      {this.retryAfter});

  @override
  String toString() => 'GhaymaAuthException($status, $code): $message';
}
