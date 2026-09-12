#!/usr/bin/env bash
# Refresh the vendored contract from the live service. CI fails when the
# result differs from what is committed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
curl -fsSL https://auth.ghayma.tech/openapi.yaml -o "$root/spec/auth.v1.yaml"
echo "spec/auth.v1.yaml updated"
