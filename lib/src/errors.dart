import 'models/login_result.dart';

/// Every failure the SDK reports, whether it came from the service or from
/// the transport.
class GhaymaAuthException implements Exception {
  /// HTTP status of the response, or 0 when the request never completed.
  final int status;

  /// Machine-readable reason: the service's `code` field when present, else
  /// `rate_limited` (429), `oauth_error` (a provider `?error=`),
  /// `network_error` / `timeout` for transport failures,
  /// `two_fa_required` / `two_fa_enrollment_required` for a
  /// [TwoFactorRequiredException], `auth_error` otherwise.
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

/// Thrown by the OAuth sign-in methods when the app's 2FA policy applies to
/// the user: no session was created. [result] is a [TwoFaRequired] (finish
/// with the 2FA verify call) or a [TwoFaEnrollmentRequired] (enrol with its
/// token).
class TwoFactorRequiredException extends GhaymaAuthException {
  final LoginResult result;

  TwoFactorRequiredException(this.result)
      : super(
            200,
            result is TwoFaEnrollmentRequired
                ? 'two_fa_enrollment_required'
                : 'two_fa_required',
            result is TwoFaEnrollmentRequired
                ? 'two-factor enrolment required'
                : 'two-factor code required');
}
