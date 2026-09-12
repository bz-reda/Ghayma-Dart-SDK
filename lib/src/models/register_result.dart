import 'json.dart';
import 'session.dart';
import 'user.dart';

/// What `register` resolves to: a session, or a pending email verification.
sealed class RegisterResult {
  const RegisterResult();

  /// Tokens are only issued when the app does not require verification.
  factory RegisterResult.fromJson(Map<String, Object?> json) =>
      json.containsKey('access_token')
          ? RegisterSuccess(Session.fromJson(json))
          : VerificationRequired.fromJson(json);
}

/// Verification is off for this app — the account is signed in already.
class RegisterSuccess extends RegisterResult {
  final Session session;

  const RegisterSuccess(this.session);
}

/// The app requires a verified email; the emailed link must be opened first.
class VerificationRequired extends RegisterResult {
  final User user;
  final String message;

  const VerificationRequired({required this.user, required this.message});

  factory VerificationRequired.fromJson(Map<String, Object?> json) =>
      VerificationRequired(
        user: User.fromJson(optObject(json['user']) ?? const {}),
        message: requiredString(json['message']),
      );
}
