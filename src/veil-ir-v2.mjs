import { sha256Canonical } from './veil-ir.mjs';

/**
 * Veil IR v2 (research prototype, issue #15). Typed SSA over `u32` and `bool` with multiple named
 * inputs/outputs, comparisons, `select`, and statically bounded loops (constant trip count, no
 * nesting). Every accepted program has a statically known step bound. Normative spec:
 * research/VEIL_IR_V2.md. Not a security mechanism.
 */
export const LIMITS = Object.freeze({ inputs: 16, outputs: 16, statements: 256, nodes: 4096, depth: 32, loopCount: 1024, loopVars: 16, unrolledInstructions: 65536 });
const NAME = /^[a-z_][a-z0-9_]{0,31}$/;
const U32_BIN = new Set(['add', 'sub', 'mul', 'shl', 'shr', 'ushr']);
const LOGIC = new Set(['and', 'or', 'xor']); // u32 x u32 -> u32, or bool x bool -> bool
const CMP = new Set(['eq', 'ne', 'ltu', 'leu']); // u32 x u32 -> bool (eq/ne also bool x bool)
const TYPES = new Set(['u32', 'bool']);
const isWord = n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
const isObj = v => v && typeof v === 'object' && !Array.isArray(v);
function onlyKeys(o, keys, what) { for (const k of Object.keys(o)) if (!keys.includes(k)) throw new Error(`Unknown field in ${what}: ${k}`); }

/** Type-check an expression in `env` (name -> type). Returns its type. */
function typeOf(node, env, ctx, depth = 0) {
  if (++ctx.nodes > LIMITS.nodes || depth > LIMITS.depth) throw new Error('IR complexity limit exceeded');
  if (!isObj(node)) throw new TypeError('Expression node must be an object');
  switch (node.op) {
    case 'var': onlyKeys(node, ['op', 'name'], 'var'); if (!env.has(node.name)) throw new Error(`Undefined variable: ${String(node.name)}`); return env.get(node.name);
    case 'const':
      onlyKeys(node, ['op', 'type', 'value'], 'const');
      if (node.type === 'u32') { if (!isWord(node.value)) throw new TypeError('u32 constant must be an integer in [0, 2^32)'); return 'u32'; }
      if (node.type === 'bool') { if (typeof node.value !== 'boolean') throw new TypeError('bool constant must be true or false'); return 'bool'; }
      throw new TypeError('Constant type must be u32 or bool');
    case 'not': { onlyKeys(node, ['op', 'arg'], 'not'); return typeOf(node.arg, env, ctx, depth + 1); }
    case 'select': {
      onlyKeys(node, ['op', 'cond', 'then', 'else'], 'select');
      if (typeOf(node.cond, env, ctx, depth + 1) !== 'bool') throw new TypeError('select condition must be bool');
      const a = typeOf(node.then, env, ctx, depth + 1), b = typeOf(node.else, env, ctx, depth + 1);
      if (a !== b) throw new TypeError('select branches must have the same type');
      return a;
    }
    default: {
      if (!U32_BIN.has(node.op) && !LOGIC.has(node.op) && !CMP.has(node.op)) throw new Error(`Unsupported IR v2 op: ${String(node.op)}`);
      onlyKeys(node, ['op', 'left', 'right'], node.op);
      if (!('left' in node) || !('right' in node)) throw new Error(`Binary op ${node.op} needs left and right`);
      const a = typeOf(node.left, env, ctx, depth + 1), b = typeOf(node.right, env, ctx, depth + 1);
      if (a !== b) throw new TypeError(`${node.op} operands must have the same type`);
      if (U32_BIN.has(node.op)) { if (a !== 'u32') throw new TypeError(`${node.op} requires u32 operands`); return 'u32'; }
      if (LOGIC.has(node.op)) return a;
      if ((node.op === 'ltu' || node.op === 'leu') && a !== 'u32') throw new TypeError(`${node.op} requires u32 operands`);
      return 'bool';
    }
  }
}

/** Validate and type-check a v2 program. Returns { types: Map, stepBound }. */
export function validateVeilIRv2(doc) {
  if (!isObj(doc)) throw new Error('Expected Veil IR v2 document');
  onlyKeys(doc, ['schemaVersion', 'inputs', 'outputs', 'body'], 'IR v2');
  if (doc.schemaVersion !== 2) throw new Error('Expected schemaVersion 2');
  const ports = (list, what, max) => {
    if (!Array.isArray(list) || list.length < 1 || list.length > max) throw new Error(`${what} must be a non-empty array of at most ${max}`);
    for (let i = 0; i < list.length; i++) {
      if (!(i in list) || !isObj(list[i])) throw new Error(`Invalid ${what} entry`);
      onlyKeys(list[i], ['name', 'type'], what);
      if (!NAME.test(list[i].name ?? '') || !TYPES.has(list[i].type)) throw new Error(`Invalid ${what} entry: names match ${NAME}, types are u32|bool`);
    }
    return list;
  };
  const env = new Map();
  const define = (name, type) => { if (!NAME.test(name ?? '')) throw new Error(`Invalid name: ${String(name)}`); if (env.has(name)) throw new Error(`SSA violation: ${name} assigned twice`); env.set(name, type); };
  for (const p of ports(doc.inputs, 'inputs', LIMITS.inputs)) define(p.name, p.type);
  if (!Array.isArray(doc.body) || doc.body.length > LIMITS.statements) throw new Error(`body must be an array of at most ${LIMITS.statements} statements`);
  const ctx = { nodes: 0 };
  let steps = 0;
  for (let i = 0; i < doc.body.length; i++) {
    const st = doc.body[i];
    if (!(i in doc.body) || !isObj(st)) throw new Error('Invalid statement');
    if ('let' in st) {
      onlyKeys(st, ['let', 'expr'], 'let');
      const before = ctx.nodes;
      const t = typeOf(st.expr, env, ctx);
      steps += ctx.nodes - before;
      define(st.let, t);
    } else if ('loop' in st) {
      onlyKeys(st, ['loop'], 'loop statement');
      const L = st.loop;
      if (!isObj(L)) throw new Error('loop must be an object');
      onlyKeys(L, ['count', 'vars', 'update'], 'loop');
      if (!Number.isInteger(L.count) || L.count < 1 || L.count > LIMITS.loopCount) throw new Error(`loop count must be a constant integer in [1, ${LIMITS.loopCount}]`);
      if (!isObj(L.vars) || !isObj(L.update)) throw new Error('loop needs vars and update objects');
      const names = Object.keys(L.vars);
      if (!names.length || names.length > LIMITS.loopVars) throw new Error(`loop must carry 1..${LIMITS.loopVars} variables`);
      if (Object.keys(L.update).sort().join() !== [...names].sort().join()) throw new Error('loop update must assign exactly the loop variables');
      const inner = new Map(env);
      const varTypes = new Map();
      for (const n of names) {
        if (!NAME.test(n) || env.has(n)) throw new Error(`Invalid or duplicate loop variable: ${n}`);
        const t = typeOf(L.vars[n], env, ctx); varTypes.set(n, t); inner.set(n, t);
      }
      let perIter = 0;
      for (const n of names) {
        const before = ctx.nodes;
        if (typeOf(L.update[n], inner, ctx) !== varTypes.get(n)) throw new TypeError(`loop update for ${n} must keep its type`);
        perIter += ctx.nodes - before;
      }
      steps += perIter * L.count;
      for (const n of names) define(n, varTypes.get(n));
    } else throw new Error('Statement must be { let, expr } or { loop }');
  }
  for (const p of ports(doc.outputs, 'outputs', LIMITS.outputs)) {
    if (!env.has(p.name)) throw new Error(`Output ${p.name} is not defined`);
    if (env.get(p.name) !== p.type) throw new TypeError(`Output ${p.name} has type ${env.get(p.name)}, declared ${p.type}`);
  }
  if (steps > LIMITS.unrolledInstructions) throw new Error(`Static step bound ${steps} exceeds ${LIMITS.unrolledInstructions}`);
  return { types: env, stepBound: steps };
}

const U = v => v >>> 0;
function applyOp(op, a, b) {
  switch (op) {
    case 'add': return U(a + b); case 'sub': return U(a - b); case 'mul': return U(Math.imul(a, b));
    case 'shl': return U(a << (b & 31)); case 'shr': return U(a >> (b & 31)); case 'ushr': return a >>> (b & 31);
    case 'eq': return a === b; case 'ne': return a !== b; case 'ltu': return a < b; case 'leu': return a <= b;
    default: throw new Error(`Unknown op ${op}`);
  }
}
function evalExpr(node, env) {
  switch (node.op) {
    case 'var': return env.get(node.name);
    case 'const': return node.value;
    case 'not': { const v = evalExpr(node.arg, env); return typeof v === 'boolean' ? !v : U(~v); }
    case 'select': return evalExpr(node.cond, env) ? evalExpr(node.then, env) : evalExpr(node.else, env);
    default: {
      const a = evalExpr(node.left, env), b = evalExpr(node.right, env);
      if (LOGIC.has(node.op)) {
        if (typeof a === 'boolean') return node.op === 'and' ? a && b : node.op === 'or' ? a || b : a !== b;
        return U(node.op === 'and' ? a & b : node.op === 'or' ? a | b : a ^ b);
      }
      return applyOp(node.op, a, b);
    }
  }
}
function checkInputs(doc, inputs) {
  if (!isObj(inputs)) throw new TypeError('inputs must be an object');
  for (const k of Object.keys(inputs)) if (!doc.inputs.some(p => p.name === k)) throw new Error(`Unknown input: ${k}`);
  return doc.inputs.map(p => {
    const v = inputs[p.name];
    if (p.type === 'u32' ? !isWord(v) : typeof v !== 'boolean') throw new TypeError(`Input ${p.name} must be ${p.type}`);
    return v;
  });
}

/** Reference interpreter. `inputs` is { name: value }; returns { outputName: value }. */
export function evaluateVeilIRv2(doc, inputs) {
  validateVeilIRv2(doc);
  const values = checkInputs(doc, inputs);
  const env = new Map(doc.inputs.map((p, i) => [p.name, values[i]]));
  for (const st of doc.body) {
    if ('let' in st) env.set(st.let, evalExpr(st.expr, env));
    else {
      const names = Object.keys(st.loop.vars);
      const inner = new Map(env);
      for (const n of names) inner.set(n, evalExpr(st.loop.vars[n], env));
      for (let k = 0; k < st.loop.count; k++) {
        const next = names.map(n => evalExpr(st.loop.update[n], inner)); // simultaneous update
        names.forEach((n, i) => inner.set(n, next[i]));
      }
      for (const n of names) env.set(n, inner.get(n));
    }
  }
  return Object.fromEntries(doc.outputs.map(p => [p.name, env.get(p.name)]));
}

/** Lift a v1 program to v2 (one u32 input `x`, one u32 output `y`). */
export function upgradeV1ToV2(ir) {
  const conv = n => n.op === 'input' ? { op: 'var', name: 'x' } : n.op === 'const' ? { op: 'const', type: 'u32', value: n.value }
    : n.op === 'not' ? { op: 'not', arg: conv(n.arg) } : { op: n.op, left: conv(n.left), right: conv(n.right) };
  return { schemaVersion: 2, inputs: [{ name: 'x', type: 'u32' }], outputs: [{ name: 'y', type: 'u32' }], body: [{ let: 'y', expr: conv(ir.expression) }] };
}

// ---------------- bytecode v2 + VM v2 ----------------
export const OPERATIONS_V2 = Object.freeze(['load-input', 'load-const', 'load-bool', 'add', 'sub', 'xor', 'and', 'or', 'mul', 'shl', 'shr', 'ushr', 'not', 'bnot', 'eq', 'ne', 'ltu', 'leu', 'select', 'ret']);
function fmix32(h) { h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16; return h >>> 0; }
export function opcodePermutationV2(seed) {
  if (!isWord(seed)) throw new TypeError('Seed must be uint32');
  const t = OPERATIONS_V2.slice();
  let x = fmix32((seed ^ 0x9e3779b9) >>> 0) || 0x6d2b79f5;
  for (let i = t.length - 1; i > 0; i--) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0; const j = x % (i + 1); [t[i], t[j]] = [t[j], t[i]]; }
  return t;
}

/** Compile v2 to straight-line bytecode v2 (loops unrolled; bools are 0/1 registers). */
export function compileVeilIRv2(doc, { seed = 0 } = {}) {
  const { types } = validateVeilIRv2(doc);
  const opcodes = opcodePermutationV2(seed);
  const code = name => opcodes.indexOf(name);
  const instructions = [];
  const emit = (op, args) => { const dst = instructions.length; instructions.push([code(op), dst, ...args]); return dst; };
  const typeEnv = new Map(types);
  function lower(node, env) {
    switch (node.op) {
      case 'var': return env.get(node.name);
      case 'const': return node.type === 'bool' ? emit('load-bool', [node.value ? 1 : 0]) : emit('load-const', [node.value]);
      case 'not': { const r = lower(node.arg, env); return emit(exprType(node.arg, env) === 'bool' ? 'bnot' : 'not', [r]); }
      case 'select': { const c = lower(node.cond, env), a = lower(node.then, env), b = lower(node.else, env); return emit('select', [c, a, b]); }
      default: { const a = lower(node.left, env), b = lower(node.right, env); return emit(node.op, [a, b]); }
    }
  }
  // Types of loop-local variables are needed for `not`; track them alongside registers.
  const regType = new Map();
  function exprType(node, env) {
    if (node.op === 'var') return regType.get(env.get(node.name));
    if (node.op === 'const') return node.type;
    if (node.op === 'not') return exprType(node.arg, env);
    if (node.op === 'select') return exprType(node.then, env);
    if (CMP.has(node.op)) return 'bool';
    if (LOGIC.has(node.op)) return exprType(node.left, env);
    return 'u32';
  }
  const env = new Map();
  doc.inputs.forEach((p, i) => { const r = emit('load-input', [i]); env.set(p.name, r); regType.set(r, p.type); });
  for (const st of doc.body) {
    if ('let' in st) { const r = lower(st.expr, env); env.set(st.let, r); regType.set(r, typeEnv.get(st.let)); }
    else {
      const names = Object.keys(st.loop.vars);
      const inner = new Map(env);
      for (const n of names) { const r = lower(st.loop.vars[n], env); inner.set(n, r); regType.set(r, typeEnv.get(n)); }
      for (let k = 0; k < st.loop.count; k++) {
        const next = names.map(n => lower(st.loop.update[n], inner));
        names.forEach((n, i) => { inner.set(n, next[i]); regType.set(next[i], typeEnv.get(n)); });
      }
      for (const n of names) env.set(n, inner.get(n));
    }
  }
  instructions.push([code('ret'), ...doc.outputs.map(p => env.get(p.name))]);
  if (instructions.length > LIMITS.unrolledInstructions + LIMITS.inputs + 1) throw new Error('Unrolled program too large');
  return {
    format: 'appveil-experimental-bytecode', version: 2,
    inputs: doc.inputs.map(p => p.type), outputs: doc.outputs.map(p => ({ name: p.name, type: p.type })),
    opcodes, registers: instructions.length - 1, instructions, seed, irDigest: sha256Canonical(doc),
    disclaimer: 'Opcode permutation is NOT cryptographic secrecy or confidentiality.'
  };
}

const VERIFIED = new WeakMap();
const ARITY = { 'load-input': 1, 'load-const': 1, 'load-bool': 1, not: 1, bnot: 1, select: 3 };
const BOOL_RESULT = new Set(['eq', 'ne', 'ltu', 'leu', 'bnot']);
function dense(v) { if (!Array.isArray(v)) return false; for (let i = 0; i < v.length; i++) if (!(i in v)) return false; return true; }

/** Verify bytecode v2 once (structure, SSA, operand ranges and register kinds); returns an opaque handle. */
export function loadVeilBytecodeV2(p) {
  if (!isObj(p) || p.format !== 'appveil-experimental-bytecode' || p.version !== 2) throw new Error('Invalid bytecode v2 envelope');
  onlyKeys(p, ['format', 'version', 'inputs', 'outputs', 'opcodes', 'registers', 'instructions', 'seed', 'irDigest', 'disclaimer'], 'bytecode v2');
  if (!dense(p.inputs) || p.inputs.length < 1 || p.inputs.length > LIMITS.inputs || p.inputs.some(t => !TYPES.has(t))) throw new Error('Invalid inputs');
  if (!dense(p.outputs) || p.outputs.length < 1 || p.outputs.length > LIMITS.outputs || p.outputs.some(o => !isObj(o) || !NAME.test(o.name ?? '') || !TYPES.has(o.type))) throw new Error('Invalid outputs');
  if (new Set(p.outputs.map(o => o.name)).size !== p.outputs.length) throw new Error('Duplicate output name');
  if (!dense(p.opcodes) || p.opcodes.length !== OPERATIONS_V2.length || new Set(p.opcodes).size !== OPERATIONS_V2.length || p.opcodes.some(o => !OPERATIONS_V2.includes(o))) throw new Error('Invalid opcode table');
  const maxRegs = LIMITS.unrolledInstructions + LIMITS.inputs;
  if (!Number.isInteger(p.registers) || p.registers < 1 || p.registers > maxRegs || !dense(p.instructions) || p.instructions.length !== p.registers + 1) throw new Error('Invalid register or instruction count');
  const n = p.registers;
  const ops = new Array(n), args = new Array(n), isBool = new Uint8Array(n);
  for (let i = 0; i <= n; i++) {
    const inst = p.instructions[i];
    if (!dense(inst) || inst.some(v => !Number.isInteger(v)) || inst[0] < 0 || inst[0] >= p.opcodes.length) throw new Error('Invalid instruction');
    const op = p.opcodes[inst[0]];
    if (op === 'ret') {
      if (i !== n) throw new Error('ret must be the last instruction');
      const regs = inst.slice(1);
      if (regs.length !== p.outputs.length || regs.some(r => r < 0 || r >= n)) throw new Error('Invalid return instruction');
      regs.forEach((r, k) => { if ((p.outputs[k].type === 'bool') !== !!isBool[r]) throw new Error('Return register type mismatch'); });
      const handle = Object.freeze({ kind: 'appveil-verified-bytecode', version: 2, instructions: n + 1 });
      VERIFIED.set(handle, { n, ops, args, ret: regs, inputs: p.inputs.slice(), outputs: p.outputs.map(o => ({ ...o })) });
      return handle;
    }
    if (i === n || inst[1] !== i) throw new Error('Noncanonical or missing return');
    const a = inst.slice(2);
    if (a.length !== (ARITY[op] ?? 2)) throw new Error('Invalid operand count');
    if (op === 'load-input') {
      if (a[0] < 0 || a[0] >= p.inputs.length) throw new Error('Invalid input index');
      isBool[i] = p.inputs[a[0]] === 'bool' ? 1 : 0;
    } else if (op === 'load-const') {
      if (!isWord(a[0])) throw new Error('Invalid constant');
    } else if (op === 'load-bool') {
      if (a[0] !== 0 && a[0] !== 1) throw new Error('Invalid bool constant');
      isBool[i] = 1;
    } else {
      if (a.some(r => r < 0 || r >= i)) throw new Error('Invalid register operand');
      // Register kinds: u32-only ops must not take bools; select needs a bool condition.
      if (['add', 'sub', 'mul', 'shl', 'shr', 'ushr', 'ltu', 'leu', 'not'].includes(op) && a.some(r => isBool[r])) throw new Error(`${op} requires u32 registers`);
      if (op === 'bnot' && !isBool[a[0]]) throw new Error('bnot requires a bool register');
      if (op === 'select') { if (!isBool[a[0]] || isBool[a[1]] !== isBool[a[2]]) throw new Error('select requires a bool condition and same-kind branches'); isBool[i] = isBool[a[1]]; }
      if (['and', 'or', 'xor', 'eq', 'ne'].includes(op) && isBool[a[0]] !== isBool[a[1]]) throw new Error(`${op} operands must have the same kind`);
      if (['and', 'or', 'xor'].includes(op)) isBool[i] = isBool[a[0]];
      if (BOOL_RESULT.has(op)) isBool[i] = 1;
    }
    ops[i] = op; args[i] = a;
  }
  throw new Error('Missing return instruction');
}

export function executeVeilBytecodeV2(handle, inputs, { maxSteps = 1_000_000 } = {}) {
  const p = VERIFIED.get(handle);
  if (!p) throw new TypeError('Not a verified v2 program; call loadVeilBytecodeV2 first');
  if (!Array.isArray(inputs) || inputs.length !== p.inputs.length) throw new TypeError(`Expected ${p.inputs.length} positional inputs`);
  inputs.forEach((v, i) => { if (p.inputs[i] === 'u32' ? !isWord(v) : typeof v !== 'boolean') throw new TypeError(`Input ${i} must be ${p.inputs[i]}`); });
  if (!Number.isSafeInteger(maxSteps) || maxSteps < 1) throw new TypeError('maxSteps must be a positive safe integer');
  if (p.n + 1 > maxSteps) throw new Error('Execution step limit exceeded');
  const r = new Uint32Array(p.n);
  for (let i = 0; i < p.n; i++) {
    const a = p.args[i], x = r[a[0]], y = r[a[1]];
    switch (p.ops[i]) {
      case 'load-input': r[i] = inputs[a[0]] === true ? 1 : inputs[a[0]] === false ? 0 : inputs[a[0]]; break;
      case 'load-const': case 'load-bool': r[i] = a[0]; break;
      case 'add': r[i] = x + y; break; case 'sub': r[i] = x - y; break; case 'mul': r[i] = Math.imul(x, y); break;
      case 'xor': r[i] = x ^ y; break; case 'and': r[i] = x & y; break; case 'or': r[i] = x | y; break;
      case 'shl': r[i] = x << (y & 31); break; case 'shr': r[i] = (x | 0) >> (y & 31); break; case 'ushr': r[i] = x >>> (y & 31); break;
      case 'not': r[i] = ~x; break; case 'bnot': r[i] = x ^ 1; break;
      case 'eq': r[i] = x === y ? 1 : 0; break; case 'ne': r[i] = x !== y ? 1 : 0; break;
      case 'ltu': r[i] = x < y ? 1 : 0; break; case 'leu': r[i] = x <= y ? 1 : 0; break;
      case 'select': r[i] = x ? y : r[a[2]]; break;
      default: throw new Error('Corrupt verified program');
    }
  }
  return Object.fromEntries(p.outputs.map((o, k) => [o.name, o.type === 'bool' ? r[p.ret[k]] === 1 : r[p.ret[k]]]));
}
