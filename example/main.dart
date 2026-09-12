// A pure-Dart walkthrough of the client. Run it against your own auth app:
//
//   GHAYMA_APP_SLUG=my-app dart run example/main.dart
//
// Set GHAYMA_AUTH_URL to point at another environment.

import 'dart:io';

import 'package:ghayma_auth/ghayma_auth.dart';

const redirectUri = 'com.example.app://callback';

Future<void> main() async {
  final appSlug = Platform.environment['GHAYMA_APP_SLUG'];
  if (appSlug == null || appSlug.isEmpty) {
    stderr.writeln('set GHAYMA_APP_SLUG to your auth app slug');
    exitCode = 64;
    return;
  }

  final auth = GhaymaAuth(
    appSlug: appSlug,
    baseUrl:
        Platform.environment['GHAYMA_AUTH_URL'] ?? 'https://auth.ghayma.tech',
  );

  final subscription = auth.onAuthStateChange.listen((state) {
    stdout.writeln('[event] ${state.event.name}');
  });

  try {
    // Pick up a session an earlier run persisted. The default storage is
    // in-memory, so this only does something once you plug in your own.
    await auth.init();
    if (auth.isAuthenticated) {
      stdout.writeln('restored a session for ${auth.currentUser?.email}');
    }

    final email = prompt('email');
    final password = prompt('password');

    if (ask('register this address?')) {
      await registerAccount(auth, email, password);
    }

    await signIn(auth, email, password);
    if (!auth.isAuthenticated) return;

    final user = await auth.getUser();
    stdout.writeln('signed in as ${user.email} (verified: '
        '${user.emailVerified}, TOTP: ${user.totpEnabled})');

    if (ask('run the PKCE OAuth flow?')) await oauthFlow(auth);
    if (ask('sign in with a native Google ID token?')) await idTokenFlow(auth);

    await auth.logout();
  } on GhaymaAuthException catch (err) {
    stderr.writeln('${err.code}: ${err.message}');
    if (err.retryAfter != null) {
      stderr.writeln('retry in ${err.retryAfter} s');
    }
    exitCode = 1;
  } finally {
    await subscription.cancel();
    auth.dispose();
  }
}

Future<void> registerAccount(
    GhaymaAuth auth, String email, String password) async {
  final result = await auth.register(
      email: email, password: password, name: prompt('name (optional)'));

  switch (result) {
    case RegisterSuccess(:final session):
      stdout.writeln('registered and signed in as ${session.user.email}');
    case VerificationRequired(:final message):
      stdout.writeln(message);
  }
}

/// Handles all three shapes a login can take.
Future<void> signIn(GhaymaAuth auth, String email, String password) async {
  final result = await auth.login(email: email, password: password);

  switch (result) {
    case LoginSuccess(:final session):
      stdout.writeln('welcome back, ${session.user.name}');

    case TwoFaRequired(:final challengeToken, :final methods):
      stdout.writeln('second factor required (${methods.join(', ')})');
      await auth.verify2fa(
          challengeToken: challengeToken, code: prompt('authenticator code'));

    case TwoFaEnrollmentRequired(:final enrollToken):
      final enrollment = await auth.enrollTotp(enrollToken: enrollToken);
      stdout.writeln('scan this in your authenticator:');
      stdout.writeln('  ${enrollment.otpauthUri}');
      stdout.writeln('  or type the secret: ${enrollment.secret}');

      final confirmation = await auth.confirmTotp(
          code: prompt('code from the authenticator'),
          enrollToken: enrollToken);
      stdout.writeln('store these recovery codes, they are shown once:');
      for (final code in confirmation.recoveryCodes) {
        stdout.writeln('  $code');
      }
  }
}

/// The mobile OAuth flow. A Flutter app opens [OAuthStart.url] with
/// flutter_web_auth_2 and passes the returned URI straight to
/// [GhaymaAuth.handleRedirect]; here the code is pasted by hand.
Future<void> oauthFlow(GhaymaAuth auth) async {
  final start =
      await auth.startOAuth(OAuthProvider.google, redirectUri: redirectUri);
  stdout.writeln('open this URL and finish the sign-in:');
  stdout.writeln('  ${start.url}');

  final code = prompt('the ?code= value from the redirect');
  if (code.isEmpty) return;

  final session =
      await auth.handleRedirect(Uri.parse('$redirectUri?code=$code'));
  stdout.writeln('signed in as ${session.user.email} '
      'via ${session.user.provider}');
}

/// Native sign-in: the platform SDK (google_sign_in on Flutter) hands the app
/// an ID token and no browser is involved.
Future<void> idTokenFlow(GhaymaAuth auth) async {
  final idToken = prompt('Google ID token');
  if (idToken.isEmpty) return;

  final session = await auth.signInWithIdToken(idToken: idToken);
  stdout.writeln('signed in as ${session.user.email}');
}

String prompt(String label) {
  stdout.write('$label: ');
  return stdin.readLineSync()?.trim() ?? '';
}

bool ask(String question) {
  stdout.write('$question [y/N] ');
  return (stdin.readLineSync() ?? '').trim().toLowerCase() == 'y';
}
