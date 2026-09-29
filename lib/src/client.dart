import 'dart:async';

import 'package:http/http.dart' as http;

import 'errors.dart';
import 'http.dart';
import 'models/json.dart';
import 'models/login_result.dart';
import 'models/misc.dart';
import 'models/register_result.dart';
import 'models/session.dart';
import 'models/two_factor.dart';
import 'models/user.dart';
import 'pkce.dart';
import 'session.dart';

const _defaultBaseUrl = 'https://auth.ghayma.tech';

/// Refresh this long before the access token expires.
const _refreshLead = Duration(seconds: 60);

/// `getAccessToken` refreshes rather than hand out a token this close to
/// expiry.
const _staleWindow = Duration(seconds: 30);

/// Client for one Ghayma auth app.
///
/// Create it once, `await init()` at startup to pick up a persisted session,
/// and `dispose()` when the app shuts down.
class GhaymaAuth {
  final String appSlug;
  final String baseUrl;

  final AuthHttp _http;
  final SessionStore _store;
  final bool _autoRefresh;
  final bool _ownsClient;
  final http.Client _client;
  final _events = StreamController<AuthState>.broadcast();

  Timer? _refreshTimer;
  Future<TokenPair>? _inFlightRefresh;
  String? _pendingVerifier;
  bool _disposed = false;

  factory GhaymaAuth({
    required String appSlug,
    String baseUrl = _defaultBaseUrl,
    TokenStorage? storage,
    bool autoRefresh = true,
    String? serverKey,
    http.Client? httpClient,
  }) {
    if (appSlug.isEmpty) {
      throw ArgumentError.value(appSlug, 'appSlug', 'appSlug is required');
    }
    final client = httpClient ?? http.Client();
    return GhaymaAuth._(
      appSlug: appSlug,
      baseUrl: baseUrl.replaceAll(RegExp(r'/+$'), ''),
      storage: storage ?? InMemoryTokenStorage(),
      autoRefresh: autoRefresh,
      serverKey: serverKey,
      client: client,
      ownsClient: httpClient == null,
    );
  }

  GhaymaAuth._({
    required this.appSlug,
    required this.baseUrl,
    required TokenStorage storage,
    required bool autoRefresh,
    required String? serverKey,
    required http.Client client,
    required bool ownsClient,
  })  : _autoRefresh = autoRefresh,
        _ownsClient = ownsClient,
        _client = client,
        _store = SessionStore(storage),
        _http = AuthHttp(baseUrl, appSlug, client, serverKey: serverKey);

  /// Restores a persisted session from storage and arms auto-refresh. Call it
  /// once at startup, before reading [currentSession]. Restoring emits no
  /// event; check [isAuthenticated] once it resolves.
  Future<void> init() async {
    await _store.load();
    _scheduleRefresh();
  }

  /// Cancels the refresh timer, closes the event stream, and closes the HTTP
  /// client when the SDK created it.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _refreshTimer?.cancel();
    _refreshTimer = null;
    _events.close();
    if (_ownsClient) _client.close();
  }

  // ==================== Session state ====================

  /// The session in memory, null when signed out.
  Session? get currentSession => _store.session;

  /// The signed-in user, null when signed out.
  User? get currentUser => _store.session?.user;

  /// Whether a session is held, expired or not.
  bool get isAuthenticated => _store.hasSession;

  /// Sign-in, sign-out, refresh and profile-update notifications.
  Stream<AuthState> get onAuthStateChange => _events.stream;

  /// The current access token, refreshed first when it expires within 30 s.
  ///
  /// Throws [GhaymaAuthException] (401) when there is no session.
  Future<String> getAccessToken() async {
    if (!_store.hasSession) throw _notAuthenticated();
    if (_store.isExpiringWithin(_staleWindow)) await refresh();
    final session = _store.session;
    if (session == null) throw _notAuthenticated();
    return session.accessToken;
  }

  // ==================== Email / password ====================

  /// Creates an account. Apps that require a verified email answer with
  /// [VerificationRequired] and issue no tokens.
  Future<RegisterResult> register({
    required String email,
    required String password,
    String? name,
    RequestOptions? options,
  }) async {
    final json = await _http.send('POST', '/register', options: options, body: {
      'email': email,
      'password': password,
      if (name != null) 'name': name,
    });
    final result = RegisterResult.fromJson(json);
    if (result is RegisterSuccess) {
      await _setSession(result.session, AuthEvent.signedIn);
    }
    return result;
  }

  /// Signs in with email and password. A user with a second factor gets
  /// [TwoFaRequired] or [TwoFaEnrollmentRequired] instead of a session.
  Future<LoginResult> login({
    required String email,
    required String password,
    RequestOptions? options,
  }) async {
    final json = await _http.send('POST', '/login',
        options: options, body: {'email': email, 'password': password});
    final result = LoginResult.fromJson(json);
    if (result is LoginSuccess) {
      await _setSession(result.session, AuthEvent.signedIn);
    }
    return result;
  }

  /// Finishes a login that asked for a second factor, with a TOTP code or one
  /// of the recovery codes.
  Future<Session> verify2fa({
    required String challengeToken,
    required String code,
  }) async {
    final json = await _http.send('POST', '/2fa/verify',
        body: {'challenge_token': challengeToken, 'code': code});
    final session = Session.fromJson(json);
    await _setSession(session, AuthEvent.signedIn);
    return session;
  }

  /// Mints a TOTP secret. Pass [enrollToken] from a
  /// [TwoFaEnrollmentRequired] login; a signed-in user passes nothing.
  Future<TotpEnrollment> enrollTotp({String? enrollToken}) async {
    // The service reads the bearer header first and never falls back to the
    // enrolment token, so the enforced path must send no token.
    final json = await _http.send('POST', '/2fa/totp/enroll',
        accessToken: enrollToken == null ? await getAccessToken() : null,
        body: {if (enrollToken != null) 'enroll_token': enrollToken});
    return TotpEnrollment.fromJson(json);
  }

  /// Turns TOTP on with a code from the authenticator. The recovery codes come
  /// back once and never again. On the enforced path this also completes the
  /// login and stores the session.
  Future<TotpConfirmation> confirmTotp({
    required String code,
    String? enrollToken,
  }) async {
    final json = await _http.send('POST', '/2fa/totp/confirm',
        accessToken: enrollToken == null ? await getAccessToken() : null,
        body: {
          'code': code,
          if (enrollToken != null) 'enroll_token': enrollToken,
        });
    final confirmation = TotpConfirmation.fromJson(json);
    final session = confirmation.session;
    if (session != null) await _setSession(session, AuthEvent.signedIn);
    return confirmation;
  }

  /// Replaces the recovery codes with a fresh set; every previous code stops
  /// working.
  Future<List<String>> regenerateRecoveryCodes({
    required String password,
    required String code,
  }) async {
    final json = await _http.send('POST', '/2fa/recovery/regenerate',
        accessToken: await getAccessToken(),
        body: {'password': password, 'code': code});
    return stringList(json['recovery_codes']);
  }

  /// Turns the second factor off.
  Future<void> disable2fa({
    required String password,
    required String code,
  }) async {
    await _http.send('POST', '/2fa/disable',
        accessToken: await getAccessToken(),
        body: {'password': password, 'code': code});
  }

  /// Rotates the refresh token for a new pair. A rejected token (401, or a 403
  /// for reuse, which revokes every session) clears the session and emits
  /// [AuthEvent.signedOut] before the error is rethrown.
  Future<TokenPair> refresh() {
    // One rotation at a time: a second caller waits for the first rather than
    // spending the refresh token twice.
    return _inFlightRefresh ??= _refresh().whenComplete(() {
      _inFlightRefresh = null;
    });
  }

  Future<TokenPair> _refresh() async {
    final session = _store.session;
    if (session == null) throw _notAuthenticated();

    final Map<String, Object?> json;
    try {
      json = await _http.send('POST', '/refresh',
          body: {'refresh_token': session.refreshToken});
    } on GhaymaAuthException catch (err) {
      if (err.status == 401 || err.status == 403) await _clearSession();
      rethrow;
    }

    final pair = TokenPair.fromJson(json);
    await _setSession(_withTokens(session, pair), AuthEvent.tokenRefreshed);
    return pair;
  }

  /// Revokes the refresh token and clears the local session. The local session
  /// goes even when the service cannot be reached.
  Future<void> logout() async {
    final session = _store.session;
    if (session != null) {
      try {
        await _http.send('POST', '/logout',
            body: {'refresh_token': session.refreshToken});
      } on GhaymaAuthException {
        // Best effort — the local session goes either way.
      }
    }
    await _clearSession();
  }

  /// Sends a password-reset link. Answers the same whether or not the address
  /// is registered.
  Future<void> forgotPassword({
    required String email,
    RequestOptions? options,
  }) async {
    await _http.send('POST', '/forgot-password',
        options: options, body: {'email': email});
  }

  /// Sets a new password with an emailed reset token, revoking every session
  /// of the account.
  Future<void> resetPassword({
    required String token,
    required String password,
    RequestOptions? options,
  }) async {
    await _http.send('POST', '/reset-password',
        options: options, body: {'token': token, 'password': password});
  }

  /// Checks a reset token without spending it, so a custom reset page can say
  /// "link expired" before asking for a new password.
  Future<ResetTokenInfo> verifyResetToken({required String token}) async {
    final json =
        await _http.send('POST', '/verify-reset-token', body: {'token': token});
    return ResetTokenInfo.fromJson(json);
  }

  /// Sends the verification email again. Answers the same whether or not the
  /// address is registered.
  Future<void> resendVerification({
    required String email,
    RequestOptions? options,
  }) async {
    await _http.send('POST', '/resend-verification',
        options: options, body: {'email': email});
  }

  // ==================== Profile ====================

  /// Reads the signed-in user's profile and refreshes [currentUser].
  Future<User> getUser() async {
    final json =
        await _http.send('GET', '/me', accessToken: await getAccessToken());
    final user = _user(json);
    await _storeUser(user);
    return user;
  }

  /// Updates the fields that are given and leaves the rest alone. Emits
  /// [AuthEvent.userUpdated].
  Future<User> updateUser({
    String? name,
    String? avatarUrl,
    Map<String, Object?>? metadata,
  }) async {
    final json = await _http
        .send('PATCH', '/me', accessToken: await getAccessToken(), body: {
      if (name != null) 'name': name,
      if (avatarUrl != null) 'avatar_url': avatarUrl,
      if (metadata != null) 'metadata': metadata,
    });
    final user = _user(json);
    await _storeUser(user);
    _emit(AuthEvent.userUpdated);
    return user;
  }

  /// Deletes the account and clears the session. Email accounts must confirm
  /// with [password]; accounts created through a provider have none.
  Future<void> deleteAccount({String? password}) async {
    await _http.send('DELETE', '/me',
        accessToken: await getAccessToken(),
        body: password == null ? null : {'password': password});
    await _clearSession();
  }

  /// Changes the password. Every session of the account is revoked, this one
  /// included, so the local session is cleared too.
  Future<void> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    await _http.send('POST', '/change-password',
        accessToken: await getAccessToken(),
        body: {
          'current_password': currentPassword,
          'new_password': newPassword,
        });
    await _clearSession();
  }

  /// Starts an email change. The address only moves once the emailed link is
  /// opened, so the current session keeps working meanwhile.
  Future<EmailChangeRequest> changeEmail({
    required String newEmail,
    required String currentPassword,
  }) async {
    final json = await _http.send('POST', '/email/change-request',
        accessToken: await getAccessToken(),
        body: {'new_email': newEmail, 'current_password': currentPassword});
    return EmailChangeRequest.fromJson(json);
  }

  /// Voids any pending email change.
  Future<void> cancelEmailChange() async {
    await _http.send('DELETE', '/email/change-request',
        accessToken: await getAccessToken());
  }

  // ==================== OAuth (PKCE only) ====================

  /// The provider sign-in URL to open in a browser. With [codeChallenge] the
  /// redirect carries a one-time `?code=` instead of tokens.
  ///
  /// [redirectUri] must match one of the app's allowed origins.
  String oauthUrl(
    OAuthProvider provider, {
    required String redirectUri,
    String? codeChallenge,
  }) {
    // Percent-encoding rather than query-parameter encoding: form encoding
    // would change the bytes of a redirect URI holding `~`, `!`, `(`, `)` or
    // a space.
    final buffer = StringBuffer('$baseUrl/v1/$appSlug/auth/${provider.name}'
        '?redirect_uri=${Uri.encodeComponent(redirectUri)}');
    if (codeChallenge != null) {
      buffer.write('&code_challenge=${Uri.encodeComponent(codeChallenge)}'
          '&code_challenge_method=S256');
    }
    return buffer.toString();
  }

  /// Prepares a PKCE sign-in: mints a verifier, remembers it for
  /// [handleRedirect], and returns it alongside the URL to open.
  ///
  /// An app that opens the URL in an external browser can persist
  /// [OAuthStart.codeVerifier] itself and hand it back to [handleRedirect].
  Future<OAuthStart> startOAuth(
    OAuthProvider provider, {
    required String redirectUri,
  }) async {
    final pkce = await Pkce.generate();
    _pendingVerifier = pkce.codeVerifier;
    return OAuthStart(
      url: oauthUrl(provider,
          redirectUri: redirectUri, codeChallenge: pkce.codeChallenge),
      codeVerifier: pkce.codeVerifier,
      codeChallenge: pkce.codeChallenge,
    );
  }

  /// Finishes a sign-in from the URI the provider redirected to.
  ///
  /// Uses [codeVerifier] when given, else the one [startOAuth] remembered,
  /// which it forgets once the exchange succeeds.
  ///
  /// Throws [GhaymaAuthException] 400 `oauth_error` when the redirect carries
  /// `?error=`, `invalid_request` when it carries no code, and `invalid_grant`
  /// when no verifier is available for it.
  Future<Session> handleRedirect(Uri redirect, {String? codeVerifier}) async {
    final error = redirect.queryParameters['error'];
    if (error != null && error.isNotEmpty) {
      throw GhaymaAuthException(400, 'oauth_error', error);
    }

    final code = redirect.queryParameters['code'];
    if (code == null || code.isEmpty) {
      throw const GhaymaAuthException(
          400, 'invalid_request', 'no code in this redirect');
    }

    final verifier = codeVerifier ?? _pendingVerifier;
    if (verifier == null) {
      throw const GhaymaAuthException(
          400, 'invalid_grant', 'no PKCE verifier for this redirect');
    }

    final session = await exchangeCode(code: code, codeVerifier: verifier);
    _pendingVerifier = null;
    return session;
  }

  /// Trades the one-time code from a PKCE redirect for a session.
  ///
  /// Throws [TwoFactorRequiredException] when the app's 2FA policy applies to
  /// the user; nothing is stored.
  Future<Session> exchangeCode({
    required String code,
    required String codeVerifier,
    RequestOptions? options,
  }) async {
    final json = await _http.send('POST', '/oauth/exchange',
        options: options, body: {'code': code, 'code_verifier': codeVerifier});
    return _oauthSignIn(json);
  }

  /// Signs in with a provider ID token obtained natively on iOS or Android,
  /// with no browser involved. [nonce], when given, must match the token's
  /// claim.
  ///
  /// Throws [TwoFactorRequiredException] when the app's 2FA policy applies to
  /// the user; nothing is stored.
  Future<Session> signInWithIdToken({
    OAuthProvider provider = OAuthProvider.google,
    required String idToken,
    String? nonce,
    RequestOptions? options,
  }) async {
    final json =
        await _http.send('POST', '/oauth/id-token', options: options, body: {
      'provider': provider.name,
      'id_token': idToken,
      if (nonce != null) 'nonce': nonce,
    });
    return _oauthSignIn(json);
  }

  // ==================== Internal ====================

  /// OAuth sign-in answers with the bodies of [login]. A pending second
  /// factor is thrown before anything is stored.
  Future<Session> _oauthSignIn(Map<String, Object?> json) async {
    final result = LoginResult.fromJson(json);
    if (result is! LoginSuccess) throw TwoFactorRequiredException(result);
    await _setSession(result.session, AuthEvent.signedIn);
    return result.session;
  }

  User _user(Map<String, Object?> json) {
    final user = json['user'];
    return User.fromJson(user is Map<String, Object?> ? user : const {});
  }

  Future<void> _storeUser(User user) async {
    final session = _store.session;
    if (session != null) await _store.save(_withUser(session, user));
  }

  Future<void> _setSession(Session session, AuthEvent event) async {
    await _store.save(session);
    _scheduleRefresh();
    _emit(event);
  }

  Future<void> _clearSession() async {
    final had = _store.hasSession;
    _refreshTimer?.cancel();
    _refreshTimer = null;
    await _store.clear();
    if (had) _emit(AuthEvent.signedOut);
  }

  void _emit(AuthEvent event) {
    if (_events.isClosed) return;
    _events.add(AuthState(event, _store.session));
  }

  void _scheduleRefresh() {
    _refreshTimer?.cancel();
    _refreshTimer = null;
    if (!_autoRefresh || _disposed) return;

    final delay = _store.refreshDelay(_refreshLead);
    // Already inside the lead window: leave it to getAccessToken rather than
    // fire a refresh the caller did not ask for.
    if (delay == null || delay <= Duration.zero) return;

    // A failure here is silent: the session expires naturally and the next
    // call surfaces the error.
    _refreshTimer = Timer(
        delay, () => unawaited(refresh().then((_) {}, onError: (Object _) {})));
  }
}

GhaymaAuthException _notAuthenticated() =>
    const GhaymaAuthException(401, 'auth_error', 'not authenticated');

Session _withTokens(Session session, TokenPair tokens) => Session(
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn,
      tokenType: tokens.tokenType,
      user: session.user,
      expiresAt: expiryFromNow(tokens.expiresIn),
    );

Session _withUser(Session session, User user) => Session(
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      expiresIn: session.expiresIn,
      tokenType: session.tokenType,
      user: user,
      expiresAt: session.expiresAt,
    );
