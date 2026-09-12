#!/usr/bin/env bash
# Runs the conformance suite against a Prism mock of the vendored contract.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

port="${PRISM_PORT:-4010}"
log="$(mktemp -t prism-ghayma-auth)"

npx --yes @stoplight/prism-cli@5 mock "$root/spec/auth.v1.yaml" \
  -p "$port" --errors >"$log" 2>&1 &
prism=$!

cleanup() {
  kill "$prism" 2>/dev/null || true
  wait "$prism" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 120); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$port/v1/demo/.well-known/jwks.json"; then
    ready=1
    break
  fi
  kill -0 "$prism" 2>/dev/null || break
  sleep 0.5
done

if [ "${ready:-0}" != "1" ]; then
  echo "prism did not come up on port $port" >&2
  cat "$log" >&2
  exit 1
fi

GHAYMA_AUTH_URL="http://127.0.0.1:$port" \
  dart test --no-color -t conformance --run-skipped
