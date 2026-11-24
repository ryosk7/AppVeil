import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Documentation must not point at files that do not exist (issue #28).
const root = fileURLToPath(new URL('..', import.meta.url));
for (const doc of ['README.md', 'docs/SECURITY.md', 'research/ROADMAP.md', 'agent.md', 'AGENTS.md']) {
  test(`relative links in ${doc} resolve`, () => {
    const text = readFileSync(path.join(root, doc), 'utf8');
    const missing = [];
    for (const m of text.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)) {
      const target = m[1];
      if (/^[a-z]+:/i.test(target)) continue; // external URL
      if (!existsSync(path.resolve(path.dirname(path.join(root, doc)), decodeURI(target)))) missing.push(target);
    }
    assert.deepEqual(missing, []);
  });
}
