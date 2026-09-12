import 'dart:io';

import 'package:yaml/yaml.dart';

final YamlMap _spec =
    loadYaml(File('spec/auth.v1.yaml').readAsStringSync()) as YamlMap;

/// The named example of a JSON response, as a plain Dart map.
Map<String, Object?> specExample(
  String path,
  String method,
  String status,
  String example,
) {
  final responses = _spec['paths'][path][method]['responses'] as YamlMap;
  final content = responses[status]['content']['application/json'] as YamlMap;
  final value = (content['examples'] as YamlMap)[example]['value'];
  return plain(value) as Map<String, Object?>;
}

/// YamlMap/YamlList trees become the Map/List shapes `jsonDecode` produces.
Object? plain(Object? node) {
  if (node is YamlMap) {
    return <String, Object?>{
      for (final entry in node.entries)
        entry.key.toString(): plain(entry.value),
    };
  }
  if (node is YamlList) return node.map(plain).toList();
  return node;
}
