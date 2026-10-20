#!/bin/sh
# Rebuilds the compiled fixtures the engine tests load:
#   redis.wasm   the example dissector (examples/wasm-dissector)
#   budget.wasm  testdata/budget, built with the same SDK glue
# Run after changing the SDK glue or the ABI. Needs TinyGo or Docker.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE="$HERE/../../../examples/wasm-dissector"

"$EXAMPLE/build.sh" redis
mv "$EXAMPLE/redis.wasm" "$HERE/redis.wasm"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$EXAMPLE/sdk.go" "$EXAMPLE/go.mod" "$EXAMPLE/build.sh" "$HERE/budget/dissector.go" "$WORK/"
"$WORK/build.sh" budget
mv "$WORK/budget.wasm" "$HERE/budget.wasm"
ls -l "$HERE"/*.wasm
