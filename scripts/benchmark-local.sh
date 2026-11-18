#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
cp "$ROOT/examples/reverse-engineering/algorithm.js" "$OUT/plain.js"
node -e 'const fs=require("fs"); const s=fs.readFileSync(process.argv[1],"utf8"); fs.writeFileSync(process.argv[2],s.replace(/\/\/.*$/gm,"").replace(/\s+/g," ").trim())' "$OUT/plain.js" "$OUT/minified.js"
clang -O2 -c "$ROOT/examples/reverse-engineering/algorithm.c" -o "$OUT/native.o"
if clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export=polynomial_score "$ROOT/examples/reverse-engineering/algorithm.c" -o "$OUT/module.wasm" 2>/dev/null; then
  echo "Built Wasm module"
else
  echo "Wasm target unavailable; artifact omitted" >&2
  # Do not silently pretend a Wasm comparison was performed.
fi
FILES=("$OUT/plain.js" "$OUT/minified.js" "$OUT/native.o")
if test -f "$OUT/module.wasm"; then FILES+=("$OUT/module.wasm"); fi
node "$ROOT/bin/appveil.mjs" benchmark "${FILES[@]}" --marker polynomialScore > "$ROOT/benchmark-results.json"
echo "Wrote benchmark-results.json (artifact observability only, NOT AI-resistance)"
