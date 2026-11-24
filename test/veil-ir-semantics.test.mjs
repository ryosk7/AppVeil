import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateVeilIR, compileVeilIR, runVeilBytecode, opcodePermutation, OPERATIONS, canonicalJson, sha256Canonical } from '../src/veil-ir.mjs';

// Independent ground truth: BigInt arithmetic, sharing no code with src/veil-ir.mjs `apply()`.
const MASK = (1n << 32n) - 1n;
const toSigned = a => (a >= 1n << 31n ? a - (1n << 32n) : a);
const REF = {
  add: (a, b) => (a + b) & MASK,
  sub: (a, b) => (a - b) & MASK,
  xor: (a, b) => a ^ b,
  and: (a, b) => a & b,
  or: (a, b) => a | b,
  mul: (a, b) => (a * b) & MASK,
  shl: (a, b) => (a << (b & 31n)) & MASK,
  // shr = arithmetic shift of the int32 view, result re-read as uint32 (documented in research/VEIL_IR_V1.md).
  shr: (a, b) => toSigned(a) >> (b & 31n) & MASK,
  ushr: (a, b) => a >> (b & 31n)
};
const refNot = a => ~a & MASK;

const EDGE = [0, 1, 2, 3, 30, 31, 32, 33, 63, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe, 0xffffffff, 0xdeadbeef];
function xorshift(seed) { let x = seed >>> 0; return () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>>= 0; }; }
const ir = expression => ({ schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression });
const input = { op: 'input' };
const c = value => ({ op: 'const', value });

function check(program, irDoc, x, expected) {
  assert.equal(evaluateVeilIR(irDoc, x), expected, `IR evaluator x=${x}`);
  assert.equal(runVeilBytecode(program, x), expected, `VM x=${x}`);
}

test('every binary op matches BigInt reference on edge x edge and seeded pairs, evaluator and VM', () => {
  const next = xorshift(0x5eed1234);
  const pairs = [];
  for (const a of EDGE) for (const b of EDGE) pairs.push([a, b]);
  for (let i = 0; i < 500; i++) pairs.push([next(), next()]);
  for (const [op, ref] of Object.entries(REF)) {
    for (const [a, b] of pairs) {
      const doc = ir({ op, left: input, right: c(b) });
      const expected = Number(ref(BigInt(a), BigInt(b)));
      for (const seed of [0, 1, 0xffffffff]) check(compileVeilIR(doc, { seed }), doc, a, expected);
    }
    // Register-register form (both operands from input) exercises operand ordering.
    const doc = ir({ op, left: input, right: { op: 'not', arg: input } });
    const p = compileVeilIR(doc, { seed: 7 });
    for (const [a] of pairs) check(p, doc, a, Number(ref(BigInt(a), refNot(BigInt(a)))));
  }
});

test('not and non-commutative operand order match reference', () => {
  const notDoc = ir({ op: 'not', arg: input });
  const subDoc = ir({ op: 'sub', left: c(5), right: input });
  const shlDoc = ir({ op: 'shl', left: c(1), right: input });
  const pn = compileVeilIR(notDoc, { seed: 3 }), ps = compileVeilIR(subDoc, { seed: 3 }), pl = compileVeilIR(shlDoc, { seed: 3 });
  for (const x of EDGE) {
    check(pn, notDoc, x, Number(refNot(BigInt(x))));
    check(ps, subDoc, x, Number(REF.sub(5n, BigInt(x))));
    check(pl, shlDoc, x, Number(REF.shl(1n, BigInt(x))));
  }
});

test('documented shr semantics: arithmetic int32 shift', () => {
  const doc = ir({ op: 'shr', left: input, right: c(1) });
  assert.equal(evaluateVeilIR(doc, 0x80000000), 0xc0000000);
  assert.equal(evaluateVeilIR(doc, 0x7fffffff), 0x3fffffff);
  assert.equal(evaluateVeilIR(ir({ op: 'ushr', left: input, right: c(1) }), 0x80000000), 0x40000000);
});

test('opcode permutation: valid table for every seed tried, seed 0 is not degenerate', () => {
  const tables = new Set();
  for (const seed of [0, 1, 2, 3, 42, 0x9e3779b9, 0x7fffffff, 0xffffffff]) {
    const t = opcodePermutation(seed);
    assert.deepEqual([...t].sort(), [...OPERATIONS].sort());
    tables.add(t.join(','));
  }
  assert.equal(tables.size, 8, 'distinct seeds produced colliding tables');
  // Previous implementation: xorshift state 0 is a fixed point, giving this rotation for seed 0.
  assert.notEqual(opcodePermutation(0).join(','), [...OPERATIONS.slice(1), OPERATIONS[0]].join(','));
  const displaced = opcodePermutation(0).filter((op, i) => op !== OPERATIONS[i]).length;
  assert.ok(displaced >= OPERATIONS.length / 2, `seed 0 displaced only ${displaced} entries`);
  assert.deepEqual(opcodePermutation(42), opcodePermutation(42), 'permutation must be deterministic');
});

// Build hand-written bytecode for `input + 1` against a given program's opcode table.
function handBytecode(instr) {
  const base = compileVeilIR(ir({ op: 'add', left: input, right: c(1) }), { seed: 11 });
  const o = name => base.opcodes.indexOf(name);
  return { ...base, instructions: instr(o), registers: instr(o).length - 1 };
}

test('VM rejects each malformed instruction class with the intended check', () => {
  const ok = handBytecode(o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('add'), 2, 0, 1], [o('ret'), 2]]);
  assert.equal(runVeilBytecode(ok, 41), 42, 'baseline hand-written program must run');
  const cases = {
    'forward register reference': [o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('add'), 2, 0, 2], [o('ret'), 2]], /Invalid register operand/],
    'negative register': [o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('add'), 2, -1, 1], [o('ret'), 2]], /Invalid register operand/],
    'too many operands': [o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('add'), 2, 0, 1, 1], [o('ret'), 2]], /Invalid register operand/],
    'too few operands': [o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('add'), 2, 0], [o('ret'), 2]], /Invalid register operand/],
    'unary with two operands': [o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('not'), 2, 0, 1], [o('ret'), 2]], /Invalid register operand/],
    'constant above uint32': [o => [[o('load-input'), 0], [o('load-const'), 1, 2 ** 32], [o('add'), 2, 0, 1], [o('ret'), 2]], /Invalid constant/],
    'fractional constant': [o => [[o('load-input'), 0], [o('load-const'), 1, 1.5], [o('add'), 2, 0, 1], [o('ret'), 2]], /Invalid constant/],
    'load-input with operand': [o => [[o('load-input'), 0, 5], [o('load-const'), 1, 1], [o('add'), 2, 0, 1], [o('ret'), 2]], /Invalid input instruction/],
    'non-SSA destination': [o => [[o('load-input'), 0], [o('load-const'), 0, 1], [o('add'), 2, 0, 1], [o('ret'), 2]], /Noncanonical or missing return/],
    'ret not last': [o => [[o('load-input'), 0], [o('ret'), 0], [o('add'), 2, 0, 0], [o('ret'), 2]], /Invalid return instruction/],
    'ret of undefined register': [o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('add'), 2, 0, 1], [o('ret'), 3]], /Invalid return instruction/],
    'ret with extra operand': [o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('add'), 2, 0, 1], [o('ret'), 2, 0]], /Invalid return instruction/],
    'missing ret': [o => [[o('load-input'), 0], [o('load-const'), 1, 1], [o('add'), 2, 0, 1], [o('add'), 3, 0, 1]], /Noncanonical or missing return/],
    'opcode out of range': [o => [[99, 0], [o('load-const'), 1, 1], [o('add'), 2, 0, 1], [o('ret'), 2]], /Invalid instruction/],
    'non-array instruction': [o => [{}, [o('load-const'), 1, 1], [o('add'), 2, 0, 1], [o('ret'), 2]], /Invalid instruction/]
  };
  for (const [name, [instr, pattern]] of Object.entries(cases)) {
    assert.throws(() => runVeilBytecode(handBytecode(instr), 1), pattern, name);
  }
});

test('VM rejects malformed envelopes and opcode tables', () => {
  const p = compileVeilIR(ir({ op: 'add', left: input, right: c(1) }));
  assert.throws(() => runVeilBytecode({ ...p, format: 'x' }, 1), /Invalid bytecode envelope/);
  assert.throws(() => runVeilBytecode({ ...p, version: 2 }, 1), /Invalid bytecode envelope/);
  assert.throws(() => runVeilBytecode({ ...p, opcodes: [...p.opcodes.slice(1), p.opcodes[1]] }, 1), /Invalid opcode table/);
  assert.throws(() => runVeilBytecode({ ...p, opcodes: [...p.opcodes.slice(1), 'eval'] }, 1), /Invalid opcode table/);
  assert.throws(() => runVeilBytecode({ ...p, registers: 0 }, 1), /Invalid register or instruction count/);
  assert.throws(() => runVeilBytecode({ ...p, registers: 257 }, 1), /Invalid register or instruction count/);
  assert.throws(() => runVeilBytecode({ ...p, registers: p.registers + 1 }, 1), /Invalid register or instruction count/);
  for (const bad of [-1, 1.5, 2 ** 32, NaN, '1']) assert.throws(() => runVeilBytecode(p, bad), /Input must be uint32/);
});

test('IR validator enforces shape, depth and node budget', () => {
  assert.throws(() => evaluateVeilIR(ir({ op: 'input', extra: 1 }), 0), /Unexpected input node field/);
  assert.throws(() => evaluateVeilIR(ir({ op: 'const', value: 1, extra: 1 }), 0), /Constant must be uint32/);
  assert.throws(() => evaluateVeilIR(ir({ op: 'not', left: input }), 0), /Invalid unary node/);
  assert.throws(() => evaluateVeilIR(ir({ op: 'add', left: input }), 0), /Invalid binary node/);
  assert.throws(() => evaluateVeilIR(ir([input]), 0), /Expression node must be an object/);
  assert.throws(() => evaluateVeilIR({ ...ir(input), schemaVersion: 2 }, 0), /Expected version 1/);
  let deep = input;
  for (let i = 0; i < 40; i++) deep = { op: 'not', arg: deep };
  assert.throws(() => evaluateVeilIR(ir(deep), 0), /complexity limit/);
  // Balanced tree: depth 8 (under the depth limit) but 2^9 - 1 = 511 nodes (over the 256-node budget).
  const balanced = d => (d === 0 ? input : { op: 'add', left: balanced(d - 1), right: balanced(d - 1) });
  assert.throws(() => evaluateVeilIR(ir(balanced(8)), 0), /complexity limit/);
  // 2^8 - 1 = 255 nodes at depth 7 stays within budget.
  assert.equal(evaluateVeilIR(ir(balanced(7)), 1), 128);
});

test('digests are canonical: independent of object key order', () => {
  const a = ir({ op: 'add', left: input, right: c(1) });
  const b = { expression: { right: { value: 1, op: 'const' }, left: { op: 'input' }, op: 'add' }, outputType: 'uint32', inputType: 'uint32', schemaVersion: 1 };
  assert.notEqual(JSON.stringify(a), JSON.stringify(b));
  assert.equal(canonicalJson(a), canonicalJson(b));
  assert.equal(compileVeilIR(a).irDigest, compileVeilIR(b).irDigest);
  assert.equal(sha256Canonical(a), compileVeilIR(a).irDigest);
  assert.match(compileVeilIR(a).irDigest, /^[0-9a-f]{64}$/);
  assert.notEqual(compileVeilIR(a).irDigest, compileVeilIR(ir({ op: 'add', left: input, right: c(2) })).irDigest);
  assert.throws(() => canonicalJson({ x: Infinity }), /Non-finite/);
  assert.throws(() => canonicalJson({ x: undefined }), /Unsupported value/);
});
