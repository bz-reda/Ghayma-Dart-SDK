import 'dart:convert';

import 'package:ghayma_auth/src/models/session.dart';
import 'package:ghayma_auth/src/models/user.dart';
import 'package:ghayma_auth/src/session.dart';
import 'package:test/test.dart';

Session sessionExpiringIn(Duration remaining) => Session(
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresIn: remaining.inSeconds,
      tokenType: 'Bearer',
      user: User(
        id: 'u1',
        email: 'user@example.com',
        name: 'Sample User',
        emailVerified: true,
        provider: 'email',
        totpEnabled: false,
        whatsappOtpEnabled: false,
        recoveryCodesLeft: 0,
        createdAt: DateTime.utc(2026, 9, 1),
      ),
      expiresAt: expiryFromNow(remaining.inSeconds),
    );

class FailingStorage implements TokenStorage {
  @override
  Future<String?> read() async => throw StateError('locked');

  @override
  Future<void> write(String value) async => throw StateError('locked');

  @override
  Future<void> delete() async => throw StateError('locked');
}

void main() {
  group('InMemoryTokenStorage', () {
    test('reads back what it wrote, and forgets on delete', () async {
      final storage = InMemoryTokenStorage();

      expect(await storage.read(), isNull);
      await storage.write('value');
      expect(await storage.read(), 'value');
      await storage.delete();
      expect(await storage.read(), isNull);
    });
  });

  group('SessionStore', () {
    test('persists a session and restores it verbatim', () async {
      final storage = InMemoryTokenStorage();
      final original = sessionExpiringIn(const Duration(minutes: 15));

      await SessionStore(storage).save(original);

      final restored = await SessionStore(storage).load();
      expect(restored, isNotNull);
      expect(restored!.accessToken, 'access');
      expect(restored.refreshToken, 'refresh');
      expect(restored.expiresAt, original.expiresAt);
      expect(restored.user.email, 'user@example.com');
    });

    test('what it writes is the session JSON', () async {
      final storage = InMemoryTokenStorage();
      final session = sessionExpiringIn(const Duration(minutes: 15));

      await SessionStore(storage).save(session);

      final raw = jsonDecode((await storage.read())!) as Map<String, Object?>;
      expect(raw['access_token'], 'access');
      expect(raw['expires_at_ms'], session.expiresAt.millisecondsSinceEpoch);
      expect((raw['user']! as Map<String, Object?>)['id'], 'u1');
    });

    test('load returns null for nothing, blanks and corrupt values', () async {
      final storage = InMemoryTokenStorage();
      expect(await SessionStore(storage).load(), isNull);

      await storage.write('   ');
      expect(await SessionStore(storage).load(), isNull);

      await storage.write('not json');
      expect(await SessionStore(storage).load(), isNull);

      await storage.write('[1,2,3]');
      expect(await SessionStore(storage).load(), isNull);
    });

    test('clear drops the session in memory and in storage', () async {
      final storage = InMemoryTokenStorage();
      final store = SessionStore(storage);
      await store.save(sessionExpiringIn(const Duration(minutes: 15)));

      await store.clear();

      expect(store.session, isNull);
      expect(store.hasSession, isFalse);
      expect(await storage.read(), isNull);
    });

    test('a storage failure never escapes', () async {
      final store = SessionStore(FailingStorage());

      expect(await store.load(), isNull);
      await store.save(sessionExpiringIn(const Duration(minutes: 15)));
      expect(store.hasSession, isTrue);
      await store.clear();
      expect(store.hasSession, isFalse);
    });

    test('isExpiringWithin measures against the window', () {
      final store = SessionStore(InMemoryTokenStorage())
        ..save(sessionExpiringIn(const Duration(seconds: 45)));

      expect(store.isExpiringWithin(const Duration(seconds: 30)), isFalse);
      expect(store.isExpiringWithin(const Duration(seconds: 60)), isTrue);
    });

    test('an expired session is expiring within any window', () {
      final store = SessionStore(InMemoryTokenStorage())
        ..save(sessionExpiringIn(const Duration(seconds: -1)));

      expect(store.isExpiringWithin(Duration.zero), isTrue);
    });

    test('no session counts as expiring and has no refresh delay', () {
      final store = SessionStore(InMemoryTokenStorage());

      expect(store.isExpiringWithin(const Duration(seconds: 30)), isTrue);
      expect(store.refreshDelay(const Duration(seconds: 60)), isNull);
    });

    test('refreshDelay is the lead time before expiry', () {
      final store = SessionStore(InMemoryTokenStorage())
        ..save(sessionExpiringIn(const Duration(minutes: 15)));

      final delay = store.refreshDelay(const Duration(seconds: 60))!;
      expect(delay.inSeconds, closeTo(840, 2));
    });

    test('refreshDelay is zero when the lead has already passed', () {
      final store = SessionStore(InMemoryTokenStorage())
        ..save(sessionExpiringIn(const Duration(seconds: 10)));

      expect(store.refreshDelay(const Duration(seconds: 60)), Duration.zero);
    });
  });
}
