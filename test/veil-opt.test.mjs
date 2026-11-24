import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { optimizeVeilIRv2, optimizeOnce, translationValidate, programSize } from '../src/veil-opt.mjs';
import { compileTypeScriptSubset } from '../src/ts-frontend.mjs';
import { compileVeilIRv2, loadVeilBytecodeV2, executeVeilBytecodeV2, evaluateVeilIRv2 } from '../src/veil-ir-v2.mjs';
import { refEvalV2, rngV2, randomV2, randomInputs } from './helpers/veil-v2-ref.mjs';

const v = name => ({ op: 'var', name }), u = value => ({ op: 'const', type: 'u32', value }), b = value => ({ op: 'const', type: 'bool', value });
const prog = (body, outputs = [{ name: 'y', type: 'u32' }]) => ({ schemaVersion: 2, inputs: [{ name: 'x', type: 'u32' }, { name: 'f', type: 'bool' }], outputs, body });

test('folding, identities, CSE, copy propagation and DCE (regression: x - 32 is not x)', () => {
  const doc = prog([
    { let: 'dead', expr: { op: 'mul', left: v('x'), right: u(7) } },
    { let: 'c', expr: { op: 'add', left: u(2), right: u(3) } },                      // folds to 5, propagated
    { let: 'a', expr: { op: 'add', left: v('x'), right: v('c') } },
    { let: 'a2', expr: { op: 'add', left: v('x'), right: u(5) } },                   // CSE -> a
    { let: 'k', expr: { op: 'xor', left: { op: 'mul', left: v('a2'), right: u(1) }, right: u(0) } }, // identities -> a
    { let: 's', expr: { op: 'select', cond: { op: 'or', left: v('f'), right: b(true) }, then: v('k'), else: u(9) } }, // -> k
    { let: 'y', expr: { op: 'sub', left: { op: 'add', left: v('s'), right: v('a') }, right: u(32) } }  // sub by 32 => shift-count rule must NOT apply to sub
  ]);
  const { ir, stats } = optimizeVeilIRv2(doc);
  assert.ok(!ir.body.some(s => s.let === 'dead'), 'dead let removed');
  assert.ok(stats.sizeAfter < stats.sizeBefore, JSON.stringify(stats));
  for (const x of [0, 1, 0xffffffff, 123456789]) for (const f of [true, false]) assert.deepEqual(evaluateVeilIRv2(ir, { x, f }), evaluateVeilIRv2(doc, { x, f }));
});

test('fuzz: optimized programs always pass validation, agree with the reference, and never grow', () => {
  const next = rngV2(0x0b7);
  let shrank = 0;
  for (let p = 0; p < 400; p++) {
    const doc = randomV2(next);
    const { ir, stats } = optimizeVeilIRv2(doc, { samples: 300 });
    assert.ok(stats.sizeAfter <= stats.sizeBefore, `grew: ${JSON.stringify(stats)}`);
    if (stats.sizeAfter < stats.sizeBefore) shrank++;
    const h = loadVeilBytecodeV2(compileVeilIRv2(ir));
    for (let k = 0; k < 5; k++) {
      const inp = randomInputs(doc, next);
      assert.deepEqual(executeVeilBytecodeV2(h, doc.inputs.map(q => inp[q.name])), refEvalV2(doc, inp));
    }
  }
  assert.ok(shrank > 100, `optimizer should shrink many random programs (shrank ${shrank}/400)`);
});

test('translation validation aborts on an injected miscompilation (fail closed)', () => {
  const doc = prog([{ let: 'y', expr: { op: 'sub', left: v('x'), right: u(3) } }]);
  // A buggy pass that swaps sub operands.
  const buggy = d => ({ ...d, body: d.body.map(s => ('let' in s && s.expr.op === 'sub' ? { let: s.let, expr: { ...s.expr, left: s.expr.right, right: s.expr.left } } : s)) });
  // rounds: 1, because applying an operand swap twice would restore the original.
  assert.throws(() => optimizeVeilIRv2(doc, { pass: buggy, rounds: 1 }), /Translation validation failed/);
  // A pass that changes the interface is also rejected.
  assert.throws(() => translationValidate(doc, { ...doc, outputs: [{ name: 'y', type: 'u32' }, { name: 'x', type: 'u32' }] }), /interface changed/);
  // A bug visible only at a boundary value is caught by the edge inputs.
  const edgeBug = d => ({ ...d, body: [{ let: 'y', expr: { op: 'select', cond: { op: 'eq', left: v('x'), right: u(0x80000000) }, then: u(0), else: d.body[0].expr } }] });
  assert.throws(() => optimizeVeilIRv2(doc, { pass: edgeBug, rounds: 1 }), /Translation validation failed/);
});

test('loop variables are never substituted inside their own update', () => {
  const doc = prog([
    { let: 'z', expr: u(0) },
    { loop: { count: 5, vars: { acc: v('x') }, update: { acc: { op: 'add', left: { op: 'add', left: v('acc'), right: v('z') }, right: u(1) } } } },
    { let: 'y', expr: v('acc') }
  ]);
  const { ir } = optimizeVeilIRv2(doc);
  for (const x of [0, 7, 0xffffffff]) assert.equal(evaluateVeilIRv2(ir, { x, f: true }).y, (x + 5) >>> 0);
});

test('optimizing the TypeScript example shrinks it and preserves behavior', () => {
  const { ir } = compileTypeScriptSubset(readFileSync(new URL('../examples/ts/score.ts', import.meta.url), 'utf8'));
  const { ir: opt, stats } = optimizeVeilIRv2(ir);
  assert.ok(stats.sizeAfter <= stats.sizeBefore);
  assert.equal(programSize(opt), stats.sizeAfter);
  assert.equal(stats.validatedInputs, 2000);
});
