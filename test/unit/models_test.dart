import 'package:ghayma_auth/src/models/login_result.dart';
import 'package:ghayma_auth/src/models/misc.dart';
import 'package:ghayma_auth/src/models/register_result.dart';
import 'package:ghayma_auth/src/models/session.dart';
import 'package:ghayma_auth/src/models/two_factor.dart';
import 'package:ghayma_auth/src/models/user.dart';
import 'package:test/test.dart';

import 'spec_examples.dart';

const _register = '/v1/{appSlug}/register';
const _login = '/v1/{appSlug}/login';
const _me = '/v1/{appSlug}/me';

void main() {
  group('User', () {
    test('parses the /me example, envelope included', () {
      final json = specExample(_me, 'get', '200', 'success');
      final user = User.fromJson(json['user']! as Map<String, Object?>);

      expect(user.id, '3f7c2b90-5e1a-4f2b-9c3d-8a1b2c3d4e5f');
      expect(user.email, 'user@example.com');
      expect(user.name, 'Sample User');
      expect(user.avatarUrl, 'https://cdn.example.com/avatars/sample.png');
      expect(user.emailVerified, isTrue);
      expect(user.provider, 'email');
      expect(user.appMetadata, {'role': 'member'});
      expect(user.metadata, isNull);
      expect(user.totpEnabled, isTrue);
      expect(user.whatsappOtpEnabled, isFalse);
      expect(user.recoveryCodesLeft, 10);
      expect(user.createdAt, DateTime.utc(2026, 9, 1, 10, 15));
      expect(user.lastLoginAt, DateTime.utc(2026, 9, 9, 8, 30));
    });

    test('leaves omitted optional fields null', () {
      final json = specExample(_register, 'post', '201', 'success');
      final user = User.fromJson(json['user']! as Map<String, Object?>);

      expect(user.avatarUrl, isNull);
      expect(user.lastLoginAt, isNull);
      expect(user.appMetadata, isNull);
    });

    test('ignores keys it does not know', () {
      final json = specExample(_me, 'get', '200', 'success');
      final raw =
          Map<String, Object?>.from(json['user']! as Map<String, Object?>)
            ..['future_field'] = 'ignored';

      expect(User.fromJson(raw).email, 'user@example.com');
    });
  });

  group('Session', () {
    test('parses the login example and derives the expiry', () {
      final before = DateTime.now().toUtc();
      final session =
          Session.fromJson(specExample(_login, 'post', '200', 'success'));

      expect(session.accessToken, startsWith('eyJhbGciOiJSUzI1NiIsImtpZCI'));
      expect(session.refreshToken, '9f8e7d6c5b4a...');
      expect(session.expiresIn, 900);
      expect(session.tokenType, 'Bearer');
      expect(session.user.email, 'user@example.com');
      expect(
        session.expiresAt
            .difference(before.add(const Duration(seconds: 900)))
            .inSeconds
            .abs(),
        lessThanOrEqualTo(2),
      );
    });

    test('round-trips through toJson, keeping the exact expiry', () {
      final original =
          Session.fromJson(specExample(_login, 'post', '200', 'success'));
      final restored = Session.fromJson(original.toJson());

      expect(restored.accessToken, original.accessToken);
      expect(restored.refreshToken, original.refreshToken);
      expect(restored.expiresIn, original.expiresIn);
      expect(restored.tokenType, original.tokenType);
      expect(restored.expiresAt, original.expiresAt);
      expect(restored.user.id, original.user.id);
      expect(restored.user.lastLoginAt, original.user.lastLoginAt);
      expect(original.toJson()['expires_at_ms'],
          original.expiresAt.millisecondsSinceEpoch);
    });
  });

  test('TokenPair parses the refresh example', () {
    final pair = TokenPair.fromJson(
        specExample('/v1/{appSlug}/refresh', 'post', '200', 'success'));

    expect(pair.refreshToken, '1a2b3c4d5e6f...');
    expect(pair.expiresIn, 900);
    expect(pair.tokenType, 'Bearer');
    expect(pair.toJson()['access_token'], pair.accessToken);
  });

  group('LoginResult', () {
    test('a plain session is LoginSuccess', () {
      final result =
          LoginResult.fromJson(specExample(_login, 'post', '200', 'success'));

      expect(result, isA<LoginSuccess>());
      expect((result as LoginSuccess).session.user.email, 'user@example.com');
    });

    test('two_fa_required carries the challenge', () {
      final result = LoginResult.fromJson(
          specExample(_login, 'post', '200', 'two_fa_required'));

      expect(result, isA<TwoFaRequired>());
      final pending = result as TwoFaRequired;
      expect(pending.challengeToken, '4c1d8ab2e3f5...');
      expect(pending.methods, ['totp']);
      expect(pending.phoneHint, '');
    });

    test('enrollment_required carries the enrol token', () {
      final result = LoginResult.fromJson(
          specExample(_login, 'post', '200', 'enrollment_required'));

      expect(result, isA<TwoFaEnrollmentRequired>());
      final pending = result as TwoFaEnrollmentRequired;
      expect(pending.enrollToken, '7b2e9c40a1d6...');
      expect(pending.methods, ['totp']);
    });
  });

  group('RegisterResult', () {
    test('tokens present means RegisterSuccess', () {
      final result = RegisterResult.fromJson(
          specExample(_register, 'post', '201', 'success'));

      expect(result, isA<RegisterSuccess>());
      expect((result as RegisterSuccess).session.expiresIn, 900);
    });

    test('no tokens means VerificationRequired', () {
      final result = RegisterResult.fromJson(
          specExample(_register, 'post', '201', 'verification_required'));

      expect(result, isA<VerificationRequired>());
      final pending = result as VerificationRequired;
      expect(pending.message, 'account created, please verify your email');
      expect(pending.user.emailVerified, isFalse);
    });
  });

  group('two-factor', () {
    test('TotpEnrollment parses the enrol example', () {
      final enrollment = TotpEnrollment.fromJson(specExample(
          '/v1/{appSlug}/2fa/totp/enroll', 'post', '200', 'success'));

      expect(enrollment.secret, 'JBSWY3DPEHPK3PXP');
      expect(enrollment.otpauthUri, startsWith('otpauth://totp/'));
    });

    test('TotpConfirmation without tokens has no session', () {
      final confirmation = TotpConfirmation.fromJson(specExample(
          '/v1/{appSlug}/2fa/totp/confirm', 'post', '200', 'success'));

      expect(confirmation.enabled, isTrue);
      expect(confirmation.recoveryCodes,
          ['K7T2M-9BQXR', '4WD8N-YH3ZC', 'R5PJ6-T1XVA']);
      expect(confirmation.session, isNull);
    });

    test('the enforced-enrolment example completes the login', () {
      final confirmation = TotpConfirmation.fromJson(specExample(
          '/v1/{appSlug}/2fa/totp/confirm',
          'post',
          '200',
          'success_forced_enrollment'));

      expect(confirmation.enabled, isTrue);
      expect(confirmation.recoveryCodes, hasLength(3));
      expect(confirmation.session, isNotNull);
      expect(confirmation.session!.user.totpEnabled, isTrue);
    });
  });

  test('ResetTokenInfo parses the verify example', () {
    final info = ResetTokenInfo.fromJson(specExample(
        '/v1/{appSlug}/verify-reset-token', 'post', '200', 'success'));

    expect(info.valid, isTrue);
    expect(info.email, 'user@example.com');
  });

  test('EmailChangeRequest parses the change-request example', () {
    final request = EmailChangeRequest.fromJson(specExample(
        '/v1/{appSlug}/email/change-request', 'post', '200', 'success'));

    expect(request.message, 'check your new email to confirm the change');
    expect(request.expiresAt, DateTime.utc(2026, 9, 9, 9, 30));
  });
}
