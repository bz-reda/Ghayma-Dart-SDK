import 'package:ghayma_auth/ghayma_auth.dart';
import 'package:test/test.dart';

final _base64url = RegExp(r'^[A-Za-z0-9_-]+$');

void main() {
  group('Pkce.challenge', () {
    test('matches the RFC 7636 appendix B vector', () {
      expect(
        Pkce.challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
        'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      );
    });

    test('is base64url with no padding', () {
      final challenge = Pkce.challenge('another-verifier');

      expect(challenge, hasLength(43));
      expect(challenge, matches(_base64url));
    });
  });

  group('Pkce.generate', () {
    test('mints a 43-character base64url verifier and its challenge', () async {
      final pair = await Pkce.generate();

      expect(pair.codeVerifier, hasLength(43));
      expect(pair.codeVerifier, matches(_base64url));
      expect(pair.codeChallenge, Pkce.challenge(pair.codeVerifier));
    });

    test('the verifier matches the pattern the contract accepts', () async {
      final pair = await Pkce.generate();

      expect(pair.codeVerifier, matches(RegExp(r'^[A-Za-z0-9._~-]{43,128}$')));
      expect(pair.codeChallenge, matches(RegExp(r'^[A-Za-z0-9._~-]{43,128}$')));
    });

    test('never repeats itself', () async {
      final verifiers = <String>{};
      for (var i = 0; i < 20; i++) {
        verifiers.add((await Pkce.generate()).codeVerifier);
      }

      expect(verifiers, hasLength(20));
    });
  });
}
