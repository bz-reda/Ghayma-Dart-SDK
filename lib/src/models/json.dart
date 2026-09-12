// Lenient readers: the service may add fields, and optional ones are simply
// omitted rather than sent as null.

String? optString(Object? value) => value is String ? value : null;

String requiredString(Object? value) => value is String ? value : '';

bool boolOf(Object? value) => value is bool ? value : false;

int intOf(Object? value) => value is int
    ? value
    : value is num
        ? value.toInt()
        : 0;

DateTime? optDate(Object? value) {
  if (value is! String || value.isEmpty) return null;
  return DateTime.tryParse(value)?.toUtc();
}

DateTime dateOf(Object? value) =>
    optDate(value) ?? DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

List<String> stringList(Object? value) => value is List
    ? List<String>.unmodifiable(value.whereType<String>())
    : const <String>[];

Map<String, Object?>? optObject(Object? value) =>
    value is Map ? Map<String, Object?>.unmodifiable(value.cast()) : null;
