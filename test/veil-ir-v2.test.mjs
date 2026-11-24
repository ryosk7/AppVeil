import test from 'node:test';
import assert from 'node:assert/strict';
import { validateVeilIRv2, evaluateVeilIRv2, compileVeilIRv2, loadVeilBytecodeV2, executeVeilBytecodeV2, upgradeV1ToV2, LIMITS } from '../src/veil-ir-v2.mjs';
import { evaluateVeilIR } from '../src/veil-ir.mjs';
import { refEvalV2, rngV2, randomV2, randomInputs } from './helpers/veil-v2-ref.mjs';
import { rng, randomExpr, wrapIR } from './helpers/veil-fuzz.mjs';

test('v2 interpreter, compiler+VM and independent reference agree on 400 random programs', () => {
  const next = rngV2(0x2222);
  for (let p = 0; p < 400; p++) {
    const doc = randomV2(next);
    const { stepBound } = validateVeilIRv2(doc);
    assert.ok(stepBound <= LIMITS.unrolledInstructions);
    const h = loadVeilBytecodeV2(compileVeilIRv2(doc, { seed: next() }));
    for (let k = 0; k < 10; k++) {
      const inp = randomInputs(doc, next);
      const expected = refEvalV2(doc, inp);
      assert.deepEqual(evaluateVeilIRv2(doc, inp), expected, `interp p=${p}`);
      assert.deepEqual(executeVeilBytecodeV2(h, doc.inputs.map(q => inp[q.name])), expected, `vm p=${p}`);
    }
  }
});

test('v1 programs still work and upgrade to equivalent v2 programs', () => {
  const next = rng(0x11);
  for (let p = 0; p < 100; p++) {
    const v1 = wrapIR(randomExpr(next));
    const v2 = upgradeV1ToV2(v1);
    const h = loadVeilBytecodeV2(compileVeilIRv2(v2));
    for (const x of [0, 1, 0x80000000, 0xffffffff, next()]) {
      assert.equal(evaluateVeilIRv2(v2, { x }).y, evaluateVeilIR(v1, x));
      assert.equal(executeVeilBytecodeV2(h, [x]).y, evaluateVeilIR(v1, x));
    }
  }
});

const base = (body, outputs = [{ name: 'y', type: 'u32' }], inputs = [{ name: 'x', type: 'u32' }]) => ({ schemaVersion: 2, inputs, outputs, body });
const v = name => ({ op: 'var', name }), u = value => ({ op: 'const', type: 'u32', value }), b = value => ({ op: 'const', type: 'bool', value });

test('bounded loop semantics: simultaneous update, constant trip count', () => {
  // Fibonacci-style swap needs simultaneous assignment.
  const doc = base([{ loop: { count: 10, vars: { a: u(0), c: u(1) }, update: { a: v('c'), c: { op: 'add', left: v('a'), right: v('c') } } } }], [{ name: 'a', type: 'u32' }]);
  assert.equal(evaluateVeilIRv2(doc, { x: 0 }).a, 55);
  assert.equal(executeVeilBytecodeV2(loadVeilBytecodeV2(compileVeilIRv2(doc)), [0]).a, 55);
  const sel = base([{ let: 'big', expr: { op: 'ltu', left: u(100), right: v('x') } }, { let: 'y', expr: { op: 'select', cond: v('big'), then: u(1), else: u(2) } }], [{ name: 'y', type: 'u32' }, { name: 'big', type: 'bool' }]);
  assert.deepEqual(evaluateVeilIRv2(sel, { x: 101 }), { y: 1, big: true });
  assert.deepEqual(executeVeilBytecodeV2(loadVeilBytecodeV2(compileVeilIRv2(sel)), [5]), { y: 2, big: false });
});

test('validator rejects unbounded, ill-typed and non-SSA programs', () => {
  const cases = {
    'non-constant loop count': base([{ loop: { count: v('x'), vars: { a: u(0) }, update: { a: v('a') } } }], [{ name: 'a', type: 'u32' }]),
    'loop count too large': base([{ loop: { count: LIMITS.loopCount + 1, vars: { a: u(0) }, update: { a: v('a') } } }], [{ name: 'a', type: 'u32' }]),
    'loop count zero': base([{ loop: { count: 0, vars: { a: u(0) }, update: { a: v('a') } } }], [{ name: 'a', type: 'u32' }]),
    'update missing a variable': base([{ loop: { count: 2, vars: { a: u(0), c: u(0) }, update: { a: v('a') } } }], [{ name: 'a', type: 'u32' }]),
    'update changes type': base([{ loop: { count: 2, vars: { a: u(0) }, update: { a: b(true) } } }], [{ name: 'a', type: 'u32' }]),
    'nested loop': base([{ loop: { count: 2, vars: { a: u(0) }, update: { a: { loop: {} } } } }], [{ name: 'a', type: 'u32' }]),
    'SSA reassignment': base([{ let: 'y', expr: u(1) }, { let: 'y', expr: u(2) }]),
    'reassign input': base([{ let: 'x', expr: u(1) }, { let: 'y', expr: u(2) }]),
    'undefined variable': base([{ let: 'y', expr: v('nope') }]),
    'use before definition': base([{ let: 'y', expr: v('z') }, { let: 'z', expr: u(1) }]),
    'select cond u32': base([{ let: 'y', expr: { op: 'select', cond: v('x'), then: u(1), else: u(2) } }]),
    'select branch mismatch': base([{ let: 'y', expr: { op: 'select', cond: b(true), then: u(1), else: b(false) } }]),
    'add on bool': base([{ let: 'y', expr: { op: 'add', left: b(true), right: b(true) } }]),
    'ltu on bool': base([{ let: 'y', expr: { op: 'ltu', left: b(true), right: b(false) } }], [{ name: 'y', type: 'bool' }]),
    'mixed and': base([{ let: 'y', expr: { op: 'and', left: v('x'), right: b(true) } }]),
    'output type mismatch': base([{ let: 'y', expr: { op: 'eq', left: v('x'), right: u(1) } }]),
    'output undefined': base([{ let: 'z', expr: u(1) }]),
    'unknown field': { ...base([{ let: 'y', expr: u(1) }]), extra: 1 },
    'unknown op': base([{ let: 'y', expr: { op: 'call', name: 'f' } }]),
    'bad name': base([{ let: 'Y-1', expr: u(1) }]),
    'step bound exceeded': base([{ loop: { count: 1024, vars: { a: u(0) }, update: { a: Array.from({ length: 70 }).reduce(acc => ({ op: 'add', left: acc, right: u(1) }), v('a')) } } }], [{ name: 'a', type: 'u32' }])
  };
  for (const [name, doc] of Object.entries(cases)) assert.throws(() => validateVeilIRv2(doc), undefined, name);
  assert.throws(() => evaluateVeilIRv2(base([{ let: 'y', expr: v('x') }]), { x: true }), /must be u32/);
  assert.throws(() => evaluateVeilIRv2(base([{ let: 'y', expr: v('x') }]), { x: 1, z: 2 }), /Unknown input/);
});

test('VM v2 verification rejects kind confusion and malformed bytecode', () => {
  const doc = base([{ let: 'c', expr: { op: 'eq', left: v('x'), right: u(3) } }, { let: 'y', expr: { op: 'select', cond: v('c'), then: u(1), else: u(2) } }]);
  const bc = compileVeilIRv2(doc, { seed: 9 });
  const o = name => bc.opcodes.indexOf(name);
  const mut = f => { const c = structuredClone(bc); f(c); return c; };
  const bad = {
    'select on u32 condition': mut(c => { c.instructions[c.instructions.length - 2] = [o('select'), c.instructions.length - 2, 0, 1, 1]; }),
    'add on bool register': mut(c => { const i = c.instructions.length - 2; c.instructions[i] = [o('add'), i, 2, 2]; }),
    'input index out of range': mut(c => { c.instructions[0] = [o('load-input'), 0, 5]; }),
    'bool const out of range': mut(c => { c.instructions[1] = [o('load-bool'), 1, 2]; }),
    'ret type mismatch': mut(c => { c.outputs[0].type = 'bool'; }),
    'ret count mismatch': mut(c => { c.instructions[c.instructions.length - 1].push(0); }),
    'sparse opcode table': mut(c => { delete c.opcodes[3]; }),
    'unknown field': mut(c => { c.extra = 1; }),
    'forward reference': mut(c => { const i = c.instructions.length - 2; c.instructions[i][2] = i; })
  };
  for (const [name, p] of Object.entries(bad)) assert.throws(() => loadVeilBytecodeV2(p), undefined, name);
  const h = loadVeilBytecodeV2(bc);
  assert.deepEqual(executeVeilBytecodeV2(h, [3]), { y: 1 });
  assert.throws(() => executeVeilBytecodeV2(h, [true]), /must be u32/);
  assert.throws(() => executeVeilBytecodeV2(h, [1], { maxSteps: 2 }), /step limit/);
  assert.throws(() => executeVeilBytecodeV2({ ...h }, [1]), /Not a verified v2 program/);
});

test('code-accepted v2 programs conform to the v2 schema; structural violations are rejected by both', async () => {
  const { readFileSync } = await import('node:fs');
  const { validateSchema } = await import('../src/json-schema-lite.mjs');
  const schema = JSON.parse(readFileSync(new URL('../schemas/veil-ir-v2.schema.json', import.meta.url), 'utf8'));
  const next = rngV2(0x5c4e);
  for (let p = 0; p < 200; p++) {
    const doc = randomV2(next);
    validateVeilIRv2(doc);
    const r = validateSchema(schema, doc);
    assert.equal(r.valid, true, r.errors.join('\n'));
  }
  const good = base([{ let: 'y', expr: u(1) }]);
  for (const bad of [{ ...good, extra: 1 }, { ...good, schemaVersion: 1 }, base([{ let: 'y', expr: { op: 'const', type: 'u32', value: -1 } }]), base([{ let: 'BAD', expr: u(1) }]), base([{ loop: { count: 0, vars: { a: u(0) }, update: { a: u(0) } } }])]) {
    assert.equal(validateSchema(schema, bad).valid, false);
    assert.throws(() => validateVeilIRv2(bad));
  }
});

test('VM-accepted bytecode v2 conforms to the bytecode v2 schema', async () => {
  const { readFileSync } = await import('node:fs');
  const { validateSchema } = await import('../src/json-schema-lite.mjs');
  const { OPERATIONS_V2 } = await import('../src/veil-ir-v2.mjs');
  const schema = JSON.parse(readFileSync(new URL('../schemas/veil-bytecode-v2.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual([...schema.properties.opcodes.items.enum].sort(), [...OPERATIONS_V2].sort());
  assert.equal(schema.properties.opcodes.minItems, OPERATIONS_V2.length);
  const next = rngV2(0xbc2);
  for (let p = 0; p < 150; p++) {
    const bc = compileVeilIRv2(randomV2(next), { seed: next() });
    loadVeilBytecodeV2(bc);
    const r = validateSchema(schema, bc);
    assert.equal(r.valid, true, r.errors.join('\n'));
  }
});
