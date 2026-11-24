import test from 'node:test';
import assert from 'node:assert/strict';
import { fuzzVeil, refEvalIR, refRunBytecode, wrapIR } from './helpers/veil-fuzz.mjs';
import { compileVeilIR } from '../src/veil-ir.mjs';

// Pinned seeds and bounded iterations keep CI deterministic. Longer runs: node scripts/veil-fuzz.mjs
for (const seed of [1, 0xc0ffee, 0xdeadbeef]) {
  test(`fuzz invariants hold (seed ${seed}, 400 iterations)`, () => {
    const s = fuzzVeil({ seed, iterations: 400 });
    assert.equal(s.irGenerated, 400);
    assert.ok(s.executions > 400 * 8);
    // Mutation must actually explore both accept and reject paths.
    assert.ok(s.irMutantsAccepted > 0 && s.irMutantsAccepted < s.irMutated, JSON.stringify(s));
    assert.ok(s.bcMutantsAccepted > 0 && s.bcMutantsAccepted < s.bcMutated, JSON.stringify(s));
  });
}

test('fuzz harness detects an injected miscompilation (the harness is not vacuous)', () => {
  const ir = wrapIR({ op: 'sub', left: { op: 'input' }, right: { op: 'const', value: 3 } });
  const bc = compileVeilIR(ir);
  assert.equal(refEvalIR(ir.expression, 10n), 7n);
  assert.equal(refRunBytecode(bc, 10n), 7n);
  // Swap the operands of the sub instruction: still structurally valid, semantically wrong.
  const broken = structuredClone(bc);
  const sub = broken.instructions[2];
  [sub[2], sub[3]] = [sub[3], sub[2]];
  assert.notEqual(refRunBytecode(broken, 10n), refEvalIR(ir.expression, 10n));
});
