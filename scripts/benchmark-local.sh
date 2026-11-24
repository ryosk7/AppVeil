#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
cp "$ROOT/examples/reverse-engineering/algorithm.js" "$OUT/plain.js"
node -e 'const fs=require("fs"); const s=fs.readFileSync(process.argv[1],"utf8"); fs.writeFileSync(process.argv[2],s.replace(/\/\/.*$/gm,"").replace(/\s+/g," ").trim())' "$OUT/plain.js" "$OUT/minified.js"
clang -O2 -c "$ROOT/examples/reverse-engineering/algorithm.c" -o "$OUT/native.o"
FILES=("$OUT/plain.js" "$OUT/minified.js" "$OUT/native.o")
EXTRA=()
if clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export=polynomial_score "$ROOT/examples/reverse-engineering/algorithm.c" -o "$OUT/module.wasm" 2>"$OUT/wasm.err"; then
  echo "Built Wasm module"
  FILES+=("$OUT/module.wasm")
else
  # Record the omission explicitly; never pretend a Wasm comparison was performed.
  REASON="clang wasm32 build failed: $(head -c 150 "$OUT/wasm.err" | tr '\n:' '  ')"
  echo "Wasm target unavailable; recorded as not-checked" >&2
  EXTRA+=(--not-checked "wasm:${REASON:-unknown}")
fi
if test "${APPVEIL_REQUIRE_WASM:-0}" = 1 && ! test -f "$OUT/module.wasm"; then
  echo "APPVEIL_REQUIRE_WASM=1 but the Wasm artifact was not produced" >&2
  exit 1
fi
node "$ROOT/bin/appveil.mjs" benchmark "${FILES[@]}" --marker polynomialScore ${EXTRA[@]+"${EXTRA[@]}"} > "$ROOT/benchmark-results.json"
echo "Wrote benchmark-results.json (artifact observability only, NOT AI-resistance)"
