import 'dart:async';
import 'dart:convert';

import 'models/session.dart';

/// Where the session is kept between runs. The default keeps it in memory
/// only; a Flutter app supplies an adapter over secure storage.
abstract class TokenStorage {
  Future<String?> read();
  Future<void> write(String value);
  Future<void> delete();
}

/// Keeps the session for the lifetime of the process and no longer.
class InMemoryTokenStorage implements TokenStorage {
  String? _value;

  @override
  Future<String?> read() async => _value;

  @override
  Future<void> write(String value) async => _value = value;

  @override
  Future<void> delete() async => _value = null;
}

/// Holds the current session and mirrors it into [TokenStorage].
class SessionStore {
  final TokenStorage storage;

  Session? _session;

  SessionStore(this.storage);

  Session? get session => _session;

  bool get hasSession => _session != null;

  /// Restores a persisted session. A corrupt or unreadable value is dropped
  /// rather than thrown — the caller simply starts signed out.
  Future<Session?> load() async {
    String? raw;
    try {
      raw = await storage.read();
    } catch (_) {
      return null;
    }
    if (raw == null || raw.trim().isEmpty) return null;

    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map<String, Object?>) return null;
      return _session = Session.fromJson(decoded);
    } catch (_) {
      return null;
    }
  }

  /// Stores [session] in memory and persists it. A storage failure leaves the
  /// in-memory session in place.
  Future<void> save(Session session) async {
    _session = session;
    try {
      await storage.write(jsonEncode(session.toJson()));
    } catch (_) {
      // Quota, keychain lock or a missing backend — keep going in memory.
    }
  }

  Future<void> clear() async {
    _session = null;
    try {
      await storage.delete();
    } catch (_) {
      // Nothing left to do; the in-memory session is already gone.
    }
  }

  /// Whether the access token expires within [window] (or already has).
  bool isExpiringWithin(Duration window) {
    final session = _session;
    if (session == null) return true;
    return !DateTime.now().toUtc().add(window).isBefore(session.expiresAt);
  }

  /// How long until the access token should be refreshed, [lead] before it
  /// expires. Null when there is no session; [Duration.zero] when it is due.
  Duration? refreshDelay(Duration lead) {
    final session = _session;
    if (session == null) return null;
    final delay = session.expiresAt.difference(DateTime.now().toUtc()) - lead;
    return delay.isNegative ? Duration.zero : delay;
  }
}
