import 'json.dart';
import 'session.dart';

/// A TOTP secret waiting to be confirmed. The plaintext secret is returned
/// exactly once.
class TotpEnrollment {
  /// Base32 secret, to type into an authenticator by hand.
  final String secret;

  /// The same secret as an `otpauth://` URI, to render as a QR code.
  final String otpauthUri;

  const TotpEnrollment({required this.secret, required this.otpauthUri});

  factory TotpEnrollment.fromJson(Map<String, Object?> json) => TotpEnrollment(
        secret: requiredString(json['secret']),
        otpauthUri: requiredString(json['otpauth_uri']),
      );
}

/// The answer to confirming TOTP.
class TotpConfirmation {
  final bool enabled;

  /// The recovery codes, shown once. Empty when no new set was minted.
  final List<String> recoveryCodes;

  /// Present only on the enforced-enrolment path, which completes the login
  /// in the same round-trip.
  final Session? session;

  const TotpConfirmation({
    required this.enabled,
    required this.recoveryCodes,
    this.session,
  });

  factory TotpConfirmation.fromJson(Map<String, Object?> json) =>
      TotpConfirmation(
        enabled: boolOf(json['enabled']),
        recoveryCodes: stringList(json['recovery_codes']),
        session:
            json['access_token'] is String && json['refresh_token'] is String
                ? Session.fromJson(json)
                : null,
      );
}
