import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkEquivalence, equivalenceQuery, solverAvailable } from '../src/veil-smt.mjs';
import { optimizeVeilIRv2 } from '../src/veil-opt.mjs';
import { evaluateVeilIRv2, upgradeV1ToV2 } from '../src/veil-ir-v2.mjs';
import { compileVeilIR } from '../src/veil-ir.mjs';
import { compileVeilIRToWasm } from '../src/veil-wasm.mjs';
import { decompileBytecodeV1 } from '../src/red-lab-attacks.mjs';
import { rngV2, randomV2 } from './helpers/veil-v2-ref.mjs';
import { rng, randomExpr, wrapIR } from './helpers/veil-fuzz.mjs';

const HAVE = !!solverAvailable();
// CI sets APPVEIL_REQUIRE_SMT=1 so that skipped proofs fail the build instead of passing silently.
if (process.env.APPVEIL_REQUIRE_SMT === '1') test('SMT solver is available (required in this environment)', () => assert.ok(HAVE, 'z3 not found but APPVEIL_REQUIRE_SMT=1'));
const smt = { skip: HAVE ? false : 'z3 not available (set APPVEIL_Z3); CI installs it' };
const example = JSON.parse(readFileSync(new URL('../examples/veil-ir-score.json', import.meta.url), 'utf8'));

test('without a solver the result is not-checked, never equivalent', () => {
  const r = checkEquivalence(example, example, { solver: '/nonexistent/z3' });
  assert.equal(r.result, 'not-checked');
  assert.match(r.reason, /not available/);
  // With --prove, a missing solver aborts compilation instead of silently skipping the proof.
  assert.throws(() => optimizeVeilIRv2(upgradeV1ToV2(example), { prove: true, smtSolver: '/nonexistent/z3' }), /Equivalence not proven/);
});

test('query encoding is well formed for v1 and v2', () => {
  const q = equivalenceQuery(example, example);
  assert.match(q, /\(set-logic QF_BV\)/);
  assert.match(q, /bvlshr .* \(bvand #x00000003 #x0000001f\)/);
  assert.throws(() => equivalenceQuery(example, JSON.parse(readFileSync(new URL('../examples/veil-ir-v2-clamp.json', import.meta.url), 'utf8'))), /different interfaces/);
});

test('SMT proves the optimizer correct on 60 random programs (all inputs)', smt, () => {
  const next = rngV2(0x5317);
  for (let p = 0; p < 60; p++) {
    const doc = randomV2(next, { maxStmts: 4 });
    const { ir } = optimizeVeilIRv2(doc, { samples: 100 });
    const r = checkEquivalence(doc, ir, { timeoutSec: 30 });
    assert.notEqual(r.result, 'counterexample', `optimizer bug on program ${p}: ${JSON.stringify(r)}`);
    assert.equal(r.result, 'equivalent', JSON.stringify(r));
  }
});

test('SMT finds a concrete counterexample for injected miscompilations, and the counterexample is real', smt, () => {
  const next = rngV2(0xbad);
  let found = 0;
  for (let p = 0; p < 40; p++) {
    const doc = randomV2(next, { maxStmts: 3 });
    const bad = structuredClone(doc);
    const last = bad.body.findLast(s => 'let' in s);
    if (!last) continue;
    // Mutation: wrap the last let in a select that differs only when the first u32 input == 0x9e3779b9.
    const u32in = bad.inputs.find(i => i.type === 'u32');
    const ty = bad.outputs.find(o => o.name === last.let)?.type;
    if (!u32in || !ty) continue;
    const alt = ty === 'bool' ? { op: 'not', arg: last.expr } : { op: 'add', left: last.expr, right: { op: 'const', type: 'u32', value: 1 } };
    last.expr = { op: 'select', cond: { op: 'eq', left: { op: 'var', name: u32in.name }, right: { op: 'const', type: 'u32', value: 0x9e3779b9 } }, then: alt, else: last.expr };
    const r = checkEquivalence(doc, bad, { timeoutSec: 30 });
    assert.equal(r.result, 'counterexample', JSON.stringify(r));
    assert.equal(r.inputs[u32in.name], 0x9e3779b9);
    const inp = Object.fromEntries(doc.inputs.map(i => [i.name, r.inputs[i.name] ?? (i.type === 'bool' ? false : 0)]));
    assert.notDeepEqual(evaluateVeilIRv2(doc, inp), evaluateVeilIRv2(bad, inp), 'counterexample must reproduce');
    found++;
  }
  assert.ok(found >= 20, `mutations exercised: ${found}`);
});

test('backend translation validation: decompiled bytecode and Wasm are proven equivalent to the source IR', smt, async () => {
  const { wasmStaticDecompile } = await import('../src/red-lab-wasm-attacks.mjs');
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'appveil-smt-'));
  try {
    const next = rng(0x3141);
    for (let p = 0; p < 40; p++) {
      const ir = wrapIR(randomExpr(next, 0, 5));
      const fromBytecode = decompileBytecodeV1(compileVeilIR(ir, { seed: next() }));
      writeFileSync(join(dir, 'artifact.wasm'), compileVeilIRToWasm(ir));
      const fromWasm = wasmStaticDecompile(dir).submission.ir;
      assert.equal(checkEquivalence(ir, fromBytecode, { timeoutSec: 30 }).result, 'equivalent', `bytecode p=${p}`);
      assert.equal(checkEquivalence(ir, fromWasm, { timeoutSec: 30 }).result, 'equivalent', `wasm p=${p}`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('hard instances time out as not-checked, never as equivalent', smt, () => {
  const doc = JSON.parse(readFileSync(new URL('../examples/veil-ir-v2-clamp.json', import.meta.url), 'utf8'));
  const bad = structuredClone(doc);
  bad.body[3].expr.op = 'leu'; // differs only where a 4-round multiplicative hash hits a boundary
  const r = checkEquivalence(doc, bad, { timeoutSec: 1 });
  assert.ok(['not-checked', 'counterexample'].includes(r.result), JSON.stringify(r));
  assert.notEqual(r.result, 'equivalent');
});
