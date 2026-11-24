import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runBackendMatrix, irToJs, irToC } from '../src/backend-matrix.mjs';
import { generateChallenge } from '../src/red-lab-harness.mjs';

const example = JSON.parse(readFileSync(new URL('../examples/veil-ir-score.json', import.meta.url), 'utf8'));

test('every available backend is correct before it is measured; missing toolchains are not-checked', async () => {
  for (const ir of [example, generateChallenge({ seed: 3, size: 14 })]) {
    const r = await runBackendMatrix(ir, { samples: 300, timingInputs: 2000 });
    const by = Object.fromEntries(r.rows.map(x => [x.backend, x]));
    for (const name of ['plain-js', 'minified-js', 'veil-vm-v1', 'veil-wasm-v1']) {
      assert.equal(by[name].status, 'measured', `${name}: ${JSON.stringify(by[name])}`);
      assert.ok(by[name].nsPerCall > 0 && /^[0-9a-f]{64}$/.test(by[name].sha256));
    }
    for (const row of r.rows) assert.ok(['measured', 'not-checked'].includes(row.status), JSON.stringify(row));
    for (const row of r.rows.filter(x => x.status === 'not-checked')) assert.ok(row.reason, 'not-checked must carry a reason');
    assert.match(r.note, /NOT evidence of confidentiality/);
  }
});

test('generated JS and C use uint32 semantics for every operator', () => {
  const ir = { op: 'shr', left: { op: 'not', arg: { op: 'input' } }, right: { op: 'const', value: 33 } };
  assert.equal(irToJs(ir), '(((~x>>>0)>>(33&31))>>>0)');
  assert.match(irToC(ir), /\(int32_t\)/);
  assert.match(irToC({ op: 'shl', left: { op: 'input' }, right: { op: 'const', value: 1 } }), /& 31u/);
});
