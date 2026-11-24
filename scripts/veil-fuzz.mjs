#!/usr/bin/env node
// Long-running local fuzz: node scripts/veil-fuzz.mjs [iterations=20000] [seed=random]
import { fuzzVeil } from '../test/helpers/veil-fuzz.mjs';
const iterations = Number(process.argv[2] ?? 20000);
const seed = process.argv[3] === undefined ? (Date.now() >>> 0) : Number(process.argv[3]);
if (!Number.isSafeInteger(iterations) || iterations < 1 || !Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) {
  console.error('usage: veil-fuzz.mjs [iterations] [uint32 seed]'); process.exit(1);
}
const t = Date.now();
try {
  const stats = fuzzVeil({ seed, iterations });
  console.log(JSON.stringify({ seed, iterations, ms: Date.now() - t, ...stats }));
} catch (e) {
  // The seed is printed so the failure can be reproduced exactly; add it as a regression test.
  console.error(`seed=${seed}\n${e.message}`);
  process.exit(1);
}
