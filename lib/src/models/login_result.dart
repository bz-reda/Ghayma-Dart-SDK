import 'json.dart';
import 'session.dart';

/// What `login` resolves to: a session, or a pending second-factor step.
sealed class LoginResult {
  const LoginResult();

  /// Picks the variant by the discriminating keys the service sends.
  factory LoginResult.fromJson(Map<String, Object?> json) {
    if (json.containsKey('two_fa_required')) {
      return TwoFaRequired.fromJson(json);
    }
    if (json.containsKey('two_fa_enrollment_required')) {
      return TwoFaEnrollmentRequired.fromJson(json);
    }
    return LoginSuccess(Session.fromJson(json));
  }
}

/// No second factor applies — the session is ready.
class LoginSuccess extends LoginResult {
  final Session session;

  const LoginSuccess(this.session);
}

/// The password verified but the user holds a second factor. Finish at
/// `verify2fa` with [challengeToken].
class TwoFaRequired extends LoginResult {
  final String challengeToken;

  /// `totp` and/or `whatsapp`.
  final List<String> methods;

  /// Masked phone for the WhatsApp factor; empty when there is none.
  final String phoneHint;

  const TwoFaRequired({
    required this.challengeToken,
    required this.methods,
    required this.phoneHint,
  });

  factory TwoFaRequired.fromJson(Map<String, Object?> json) => TwoFaRequired(
        challengeToken: requiredString(json['challenge_token']),
        methods: stringList(json['methods']),
        phoneHint: requiredString(json['phone_hint']),
      );
}

/// The app enforces 2FA and this user is not enrolled. Run TOTP enrolment
/// with [enrollToken]; confirming it also completes the login.
class TwoFaEnrollmentRequired extends LoginResult {
  final String enrollToken;

  /// `totp` and/or `whatsapp`.
  final List<String> methods;

  const TwoFaEnrollmentRequired({
    required this.enrollToken,
    required this.methods,
  });

  factory TwoFaEnrollmentRequired.fromJson(Map<String, Object?> json) =>
      TwoFaEnrollmentRequired(
        enrollToken: requiredString(json['enroll_token']),
        methods: stringList(json['methods']),
      );
}
