import 'package:http/http.dart' as http;

/// Wraps a real client and stamps Prism's `Prefer` header on every request, so
/// a test can pick which documented response it wants back.
class PreferClient extends http.BaseClient {
  final http.Client _inner;

  /// For example `code=401, example=invalid_credentials`. Null sends nothing
  /// and Prism answers with the first documented response.
  String? prefer;

  PreferClient(this._inner, {this.prefer});

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    final value = prefer;
    if (value != null) request.headers['Prefer'] = value;
    return _inner.send(request);
  }

  @override
  void close() => _inner.close();
}
