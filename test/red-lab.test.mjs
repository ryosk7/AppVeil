import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { compileVeilIR } from '../src/veil-ir.mjs';
import { recoverInstructionTrace } from '../src/red-lab.mjs';

const ir = JSON.parse(readFileSync(new URL('../examples/veil-ir-score.json', import.meta.url), 'utf8'));
test('static attacker recovers exact operation sequence across diversified opcodes', () => {
  const a = recoverInstructionTrace(compileVeilIR(ir, { seed: 1 }));
  const b = recoverInstructionTrace(compileVeilIR(ir, { seed: 999 }));
  assert.deepEqual(a.recovered.map(x => x.operation), b.recovered.map(x => x.operation));
  assert.ok(a.recovered.some(x => x.operation === 'xor'));
  assert.ok(a.recovered.some(x => x.operation === 'mul'));
  assert.match(a.securityFinding, /no meaningful confidentiality/);
});
test('rejects unsupported artifact', () => {
  assert.throws(() => recoverInstructionTrace({}));
});
