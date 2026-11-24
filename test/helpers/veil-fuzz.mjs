// Deterministic fuzzing for Veil IR v1 / bytecode v1. Ground truth here is BigInt-based and shares
// no code with src/veil-ir.mjs. Used by test/veil-fuzz.test.mjs (bounded) and scripts/veil-fuzz.mjs (long).
import { readFileSync } from 'node:fs';
import { validateVeilIR, evaluateVeilIR, compileVeilIR, loadVeilBytecode, executeVeilBytecode } from '../../src/veil-ir.mjs';
import { validateSchema } from '../../src/json-schema-lite.mjs';

const MASK = (1n << 32n) - 1n;
const toSigned = a => (a >= 1n << 31n ? a - (1n << 32n) : a);
export const REF_BINARY = {
  add: (a, b) => (a + b) & MASK, sub: (a, b) => (a - b) & MASK, xor: (a, b) => a ^ b, and: (a, b) => a & b,
  or: (a, b) => a | b, mul: (a, b) => (a * b) & MASK, shl: (a, b) => (a << (b & 31n)) & MASK,
  shr: (a, b) => toSigned(a) >> (b & 31n) & MASK, ushr: (a, b) => a >> (b & 31n)
};
const refNot = a => ~a & MASK;

/** Independent IR evaluator (BigInt). Assumes the IR was accepted by the validator. */
export function refEvalIR(node, x) {
  if (node.op === 'input') return x;
  if (node.op === 'const') return BigInt(node.value);
  if (node.op === 'not') return refNot(refEvalIR(node.arg, x));
  return REF_BINARY[node.op](refEvalIR(node.left, x), refEvalIR(node.right, x));
}
/** Independent bytecode interpreter (BigInt). Assumes the program was accepted by the VM loader. */
export function refRunBytecode(p, x) {
  const regs = [];
  for (const [opcode, dst, ...args] of p.instructions) {
    const op = p.opcodes[opcode];
    if (op === 'ret') return regs[dst];
    regs.push(op === 'load-input' ? x : op === 'load-const' ? BigInt(args[0]) : op === 'not' ? refNot(regs[args[0]]) : REF_BINARY[op](regs[args[0]], regs[args[1]]));
  }
  throw new Error('reference: no ret');
}

export function rng(seed) {
  let x = seed >>> 0 || 0x9e3779b9;
  const next = () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>>= 0; };
  next.pick = arr => arr[next() % arr.length];
  next.chance = p => next() / 2 ** 32 < p;
  return next;
}
const BIN = Object.keys(REF_BINARY);
const EDGE = [0, 1, 2, 31, 32, 0x7fffffff, 0x80000000, 0xffffffff];
export function randomExpr(next, depth = 0, maxDepth = 7) {
  const r = next() % 10;
  if (depth >= maxDepth || r < 2) return { op: 'input' };
  if (r < 4) return { op: 'const', value: next.chance(0.3) ? next.pick(EDGE) : next() };
  if (r < 5) return { op: 'not', arg: randomExpr(next, depth + 1, maxDepth) };
  return { op: next.pick(BIN), left: randomExpr(next, depth + 1, maxDepth), right: randomExpr(next, depth + 1, maxDepth) };
}
export const wrapIR = expression => ({ schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression });

const WEIRD = [null, undefined, -1, 1.5, 2 ** 32, NaN, Infinity, -0, '1', '', true, [], {}, [1], { op: 'input' }, 2 ** 53, -(2 ** 31)];
const clone = v => structuredClone(v);
function allNodes(v, out = []) {
  if (v && typeof v === 'object') { out.push(v); for (const k of Object.keys(v)) allNodes(v[k], out); }
  return out;
}
/** Apply 1-3 random structural mutations to any JSON-like value. */
export function mutate(value, next) {
  const doc = clone(value);
  const n = 1 + (next() % 3);
  for (let i = 0; i < n; i++) {
    const nodes = allNodes(doc);
    const target = next.pick(nodes);
    const keys = Object.keys(target);
    const key = keys.length ? next.pick(keys) : (Array.isArray(target) ? 0 : 'x');
    switch (next() % 8) {
      case 0: target[key] = clone(next.pick(WEIRD)); break;
      case 1: delete target[key]; break;
      case 2: target[Array.isArray(target) ? target.length : `f${next() % 4}`] = clone(next.pick(WEIRD)); break;
      case 3: if (typeof target[key] === 'number') target[key] = target[key] + (next.chance(0.5) ? 1 : -1); else target[key] = next() % 300; break;
      case 4: if (Array.isArray(target) && target.length > 1) { const j = next() % target.length; [target[key], target[j]] = [target[j], target[key]]; } break;
      case 5: if (Array.isArray(target)) target.splice(next() % (target.length + 1), 0, clone(target[next() % Math.max(target.length, 1)] ?? 0)); break;
      case 6: if (Array.isArray(target) && target.length) target.splice(next() % target.length, 1); break;
      case 7: target[key] = clone(next.pick(nodes)); break;
    }
  }
  return doc;
}

const IR_SCHEMA = JSON.parse(readFileSync(new URL('../../schemas/veil-ir-v1.schema.json', import.meta.url), 'utf8'));
const BC_SCHEMA = JSON.parse(readFileSync(new URL('../../schemas/veil-bytecode-v1.schema.json', import.meta.url), 'utf8'));
const isUint32 = v => Number.isInteger(v) && v >= 0 && v <= 0xffffffff;

/** Throws an Error describing the first invariant violation. Returns counters. */
export function fuzzVeil({ seed = 1, iterations = 1000, inputsPerProgram = 8 } = {}) {
  const next = rng(seed);
  const stats = { irGenerated: 0, irMutated: 0, irMutantsAccepted: 0, bcMutated: 0, bcMutantsAccepted: 0, executions: 0 };
  const fail = (what, ctx) => { const e = new Error(`fuzz invariant violated (seed ${seed}): ${what}\n${JSON.stringify(ctx).slice(0, 2000)}`); e.fuzzContext = ctx; throw e; };
  function guard(fn, ctx) {
    try { return { ok: true, value: fn() }; }
    catch (e) {
      if (!(e instanceof Error)) fail('threw a non-Error value', { ...ctx, thrown: String(e) });
      if (e instanceof RangeError && /call stack/i.test(e.message)) fail('stack overflow', ctx);
      return { ok: false, error: e };
    }
  }
  const inputs = () => Array.from({ length: inputsPerProgram }, (_, i) => (i < 3 ? [0, 0x80000000, 0xffffffff][i] : next()));
  function checkIR(ir, ctx) {
    const accepted = guard(() => validateVeilIR(ir), ctx).ok;
    if (!accepted) return false;
    if (!validateSchema(IR_SCHEMA, ir).valid) fail('code accepted IR that the schema rejects', { ...ctx, ir });
    const bc = guard(() => compileVeilIR(ir, { seed: next() }), ctx);
    if (!bc.ok) fail(`compiler rejected IR the validator accepted: ${bc.error.message}`, { ...ctx, ir });
    const h = loadVeilBytecode(bc.value);
    for (const x of inputs()) {
      const expected = refEvalIR(ir.expression, BigInt(x));
      const ev = evaluateVeilIR(ir, x), vm = executeVeilBytecode(h, x);
      stats.executions++;
      if (!isUint32(ev) || !isUint32(vm)) fail('non-uint32 result', { ...ctx, ir, x, ev, vm });
      if (BigInt(ev) !== expected || BigInt(vm) !== expected) fail('result mismatch', { ...ctx, ir, x, ev, vm, expected: String(expected) });
    }
    return bc.value;
  }
  function checkBytecode(bc, ctx) {
    const loaded = guard(() => loadVeilBytecode(bc), ctx);
    if (!loaded.ok) return false;
    if (!validateSchema(BC_SCHEMA, bc).valid) fail('VM accepted bytecode that the schema rejects', { ...ctx, bc });
    for (const x of inputs()) {
      const vm = guard(() => executeVeilBytecode(loaded.value, x), ctx);
      if (!vm.ok) fail(`verified program failed at runtime: ${vm.error.message}`, { ...ctx, bc, x });
      stats.executions++;
      if (!isUint32(vm.value)) fail('non-uint32 result', { ...ctx, bc, x });
      let expected;
      try { expected = refRunBytecode(bc, BigInt(x)); } catch (e) { fail(`reference interpreter failed on VM-accepted bytecode: ${e.message}`, { ...ctx, bc }); }
      if (BigInt(vm.value) !== expected) fail('bytecode result mismatch', { ...ctx, bc, x, vm: vm.value, expected: String(expected) });
    }
    return true;
  }
  for (let i = 0; i < iterations; i++) {
    const ir = wrapIR(randomExpr(next));
    stats.irGenerated++;
    const bc = checkIR(ir, { i, phase: 'generated-ir' });
    if (!bc) fail('generated valid IR was rejected', { i, ir });
    checkBytecode(bc, { i, phase: 'compiled-bytecode' });
    const irMutant = mutate(ir, next);
    stats.irMutated++;
    if (checkIR(irMutant, { i, phase: 'mutated-ir' })) stats.irMutantsAccepted++;
    const bcMutant = mutate(bc, next);
    stats.bcMutated++;
    if (checkBytecode(bcMutant, { i, phase: 'mutated-bytecode' })) stats.bcMutantsAccepted++;
  }
  return stats;
}
