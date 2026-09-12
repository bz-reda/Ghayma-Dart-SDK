import 'json.dart';
import 'user.dart';

/// A freshly rotated access/refresh pair, without the user object.
class TokenPair {
  final String accessToken;
  final String refreshToken;

  /// Access-token lifetime in seconds.
  final int expiresIn;
  final String tokenType;

  const TokenPair({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresIn,
    required this.tokenType,
  });

  factory TokenPair.fromJson(Map<String, Object?> json) => TokenPair(
        accessToken: requiredString(json['access_token']),
        refreshToken: requiredString(json['refresh_token']),
        expiresIn: intOf(json['expires_in']),
        tokenType: requiredString(json['token_type']),
      );

  Map<String, Object?> toJson() => {
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'expires_in': expiresIn,
        'token_type': tokenType,
      };
}

/// A signed-in session: the token pair plus the user it belongs to.
class Session {
  final String accessToken;
  final String refreshToken;

  /// Access-token lifetime in seconds, as the service issued it.
  final int expiresIn;
  final String tokenType;
  final User user;

  /// When the access token stops being valid, in UTC.
  final DateTime expiresAt;

  const Session({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresIn,
    required this.tokenType,
    required this.user,
    required this.expiresAt,
  });

  /// Reads a wire session. `expires_at_ms` is only in the persisted form; a
  /// response from the service has none, so expiry is `now + expires_in`.
  factory Session.fromJson(Map<String, Object?> json) {
    final expiresIn = intOf(json['expires_in']);
    final persisted = json['expires_at_ms'];
    return Session(
      accessToken: requiredString(json['access_token']),
      refreshToken: requiredString(json['refresh_token']),
      expiresIn: expiresIn,
      tokenType: requiredString(json['token_type']),
      user: User.fromJson(optObject(json['user']) ?? const {}),
      expiresAt: persisted is num
          ? DateTime.fromMillisecondsSinceEpoch(persisted.toInt(), isUtc: true)
          : expiryFromNow(expiresIn),
    );
  }

  Map<String, Object?> toJson() => {
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'expires_in': expiresIn,
        'token_type': tokenType,
        'user': user.toJson(),
        'expires_at_ms': expiresAt.millisecondsSinceEpoch,
      };
}

// Millisecond precision, so a persisted session restores to the same instant.
DateTime expiryFromNow(int seconds) => DateTime.fromMillisecondsSinceEpoch(
    DateTime.now().millisecondsSinceEpoch + seconds * 1000,
    isUtc: true);
