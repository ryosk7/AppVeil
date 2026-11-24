#!/usr/bin/env node
// Regenerate test/golden/build-digests.json. Run ONLY for an intentional compiler change, and say so
// in the PR: a changed golden digest means every downstream build changes.
import { readFileSync, writeFileSync } from 'node:fs';
import { build } from '../src/build-manifest.mjs';
import { GOLDEN_CORPUS } from '../test/golden/corpus.mjs';
const out = {};
for (const c of GOLDEN_CORPUS) {
  const { manifest } = build(readFileSync(new URL(`../${c.file}`, import.meta.url), 'utf8'), c.options);
  out[c.id] = { sourceSha256: manifest.source.sha256, outputs: Object.fromEntries(Object.entries(manifest.outputs).map(([k, v]) => [k, v.sha256])) };
}
writeFileSync(new URL('../test/golden/build-digests.json', import.meta.url), `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${Object.keys(out).length} golden entries`);
