import 'json.dart';
import 'session.dart';

/// Per-call options for the operations the service rate-limits by IP.
class RequestOptions {
  /// The end user's IP, forwarded so the service charges the rate limit to
  /// that address instead of the calling server's. Sent only alongside a
  /// `serverKey`; without one nothing extra goes on the wire. Must be a
  /// single IP literal, not a whole `x-forwarded-for` chain.
  final String? clientIp;

  const RequestOptions({this.clientIp});
}

/// A password-reset token that has not been spent yet.
class ResetTokenInfo {
  final bool valid;

  /// The address the reset link belongs to, for display on a custom page.
  final String email;

  const ResetTokenInfo({required this.valid, required this.email});

  factory ResetTokenInfo.fromJson(Map<String, Object?> json) => ResetTokenInfo(
        valid: boolOf(json['valid']),
        email: requiredString(json['email']),
      );
}

/// A started email change: a confirmation link is on its way to the new
/// address and the change only lands once it is opened.
class EmailChangeRequest {
  final String message;

  /// When the confirmation link stops working, in UTC.
  final DateTime expiresAt;

  const EmailChangeRequest({required this.message, required this.expiresAt});

  factory EmailChangeRequest.fromJson(Map<String, Object?> json) =>
      EmailChangeRequest(
        message: requiredString(json['message']),
        expiresAt: dateOf(json['expires_at']),
      );
}

/// The identity providers the service can start a sign-in with.
enum OAuthProvider { google, github }

/// A prepared PKCE sign-in: send the user to [url] and keep [codeVerifier]
/// until the redirect comes back.
class OAuthStart {
  final String url;
  final String codeVerifier;
  final String codeChallenge;

  const OAuthStart({
    required this.url,
    required this.codeVerifier,
    required this.codeChallenge,
  });
}

/// What changed about the session.
enum AuthEvent { signedIn, signedOut, tokenRefreshed, userUpdated }

/// One notification on `onAuthStateChange`.
class AuthState {
  final AuthEvent event;

  /// The session after the change, null once signed out.
  final Session? session;

  const AuthState(this.event, this.session);
}
