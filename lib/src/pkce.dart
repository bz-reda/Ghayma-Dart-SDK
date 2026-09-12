import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

/// A verifier and the challenge derived from it.
class PkcePair {
  final String codeVerifier;
  final String codeChallenge;

  const PkcePair({required this.codeVerifier, required this.codeChallenge});
}

/// PKCE (RFC 7636) for the one-time-code OAuth flow.
class Pkce {
  Pkce._();

  /// A fresh verifier — 32 random bytes, 43 base64url characters — and its
  /// S256 challenge.
  static Future<PkcePair> generate() async {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    final codeVerifier = _base64url(bytes);
    return PkcePair(
      codeVerifier: codeVerifier,
      codeChallenge: challenge(codeVerifier),
    );
  }

  /// The S256 challenge for [verifier], per RFC 7636 §4.2.
  static String challenge(String verifier) =>
      _base64url(sha256.convert(utf8.encode(verifier)).bytes);
}

String _base64url(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');
