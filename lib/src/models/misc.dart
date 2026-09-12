/// Per-call options for the operations the service rate-limits by IP.
class RequestOptions {
  /// The end user's IP, forwarded so the service charges the rate limit to
  /// that address instead of the calling server's. Sent only alongside a
  /// `serverKey`; without one nothing extra goes on the wire.
  final String? clientIp;

  const RequestOptions({this.clientIp});
}
