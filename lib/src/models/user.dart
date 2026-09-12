import 'json.dart';

/// An end user of the auth app.
class User {
  final String id;
  final String email;

  /// Empty when the account has no name.
  final String name;
  final String? avatarUrl;
  final bool emailVerified;

  /// `email`, `google` or `github`.
  final String provider;

  /// User-owned bag. Written by `updateUser`; carried in the access token as
  /// the `user_metadata` claim rather than rendered here.
  final Map<String, Object?>? metadata;

  /// Developer-owned bag (roles, plan, tenant id), read-only for the client.
  final Map<String, Object?>? appMetadata;
  final bool totpEnabled;

  /// Always false — the WhatsApp factor is not offered.
  final bool whatsappOtpEnabled;

  /// Single-use recovery codes still unspent.
  final int recoveryCodesLeft;
  final DateTime createdAt;

  /// Null until the first successful sign-in.
  final DateTime? lastLoginAt;

  const User({
    required this.id,
    required this.email,
    required this.name,
    this.avatarUrl,
    required this.emailVerified,
    required this.provider,
    this.metadata,
    this.appMetadata,
    required this.totpEnabled,
    required this.whatsappOtpEnabled,
    required this.recoveryCodesLeft,
    required this.createdAt,
    this.lastLoginAt,
  });

  factory User.fromJson(Map<String, Object?> json) => User(
        id: requiredString(json['id']),
        email: requiredString(json['email']),
        name: optString(json['name']) ?? '',
        avatarUrl: optString(json['avatar_url']),
        emailVerified: boolOf(json['email_verified']),
        provider: requiredString(json['provider']),
        metadata: optObject(json['metadata']),
        appMetadata: optObject(json['app_metadata']),
        totpEnabled: boolOf(json['totp_enabled']),
        whatsappOtpEnabled: boolOf(json['whatsapp_otp_enabled']),
        recoveryCodesLeft: intOf(json['recovery_codes_left']),
        createdAt: dateOf(json['created_at']),
        lastLoginAt: optDate(json['last_login_at']),
      );

  Map<String, Object?> toJson() => {
        'id': id,
        'email': email,
        'name': name,
        if (avatarUrl != null) 'avatar_url': avatarUrl,
        'email_verified': emailVerified,
        'provider': provider,
        if (metadata != null) 'metadata': metadata,
        if (appMetadata != null) 'app_metadata': appMetadata,
        'totp_enabled': totpEnabled,
        'whatsapp_otp_enabled': whatsappOtpEnabled,
        'recovery_codes_left': recoveryCodesLeft,
        'created_at': createdAt.toIso8601String(),
        if (lastLoginAt != null)
          'last_login_at': lastLoginAt!.toIso8601String(),
      };
}
