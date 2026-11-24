import { spawnSync } from 'node:child_process';
import { validateVeilIR } from './veil-ir.mjs';
import { validateVeilIRv2, upgradeV1ToV2 } from './veil-ir-v2.mjs';

/**
 * Bounded SMT equivalence checking (issue #19). Programs are encoded in SMT-LIB 2 over 32-bit
 * bit-vectors (QF_BV); loops are unrolled (bounded by IR v2's static step limit). Two programs with
 * the same interface are equivalent for ALL inputs iff the solver reports `unsat` for "some output
 * differs". Requires a local solver (`z3`, or APPVEIL_Z3=/path/to/z3). Without it, or on timeout /
 * unknown, the result is `not-checked` — never `equivalent`.
 */
const hex = v => `#x${(v >>> 0).toString(16).padStart(8, '0')}`;
const MASK31 = '#x0000001f';

function encodeExpr(n, sym) {
  switch (n.op) {
    case 'var': return sym(n.name);
    case 'const': return n.type === 'bool' ? (n.value ? 'true' : 'false') : hex(n.value);
    case 'not': return n._ty === 'bool' ? `(not ${encodeExpr(n.arg, sym)})` : `(bvnot ${encodeExpr(n.arg, sym)})`;
    case 'select': return `(ite ${encodeExpr(n.cond, sym)} ${encodeExpr(n.then, sym)} ${encodeExpr(n.else, sym)})`;
  }
  const a = encodeExpr(n.left, sym), b = encodeExpr(n.right, sym);
  switch (n.op) {
    case 'add': return `(bvadd ${a} ${b})`;
    case 'sub': return `(bvsub ${a} ${b})`;
    case 'mul': return `(bvmul ${a} ${b})`;
    case 'shl': return `(bvshl ${a} (bvand ${b} ${MASK31}))`;
    case 'shr': return `(bvashr ${a} (bvand ${b} ${MASK31}))`;
    case 'ushr': return `(bvlshr ${a} (bvand ${b} ${MASK31}))`;
    case 'eq': return `(= ${a} ${b})`;
    case 'ne': return `(not (= ${a} ${b}))`;
    case 'ltu': return `(bvult ${a} ${b})`;
    case 'leu': return `(bvule ${a} ${b})`;
    case 'and': return n._ty === 'bool' ? `(and ${a} ${b})` : `(bvand ${a} ${b})`;
    case 'or': return n._ty === 'bool' ? `(or ${a} ${b})` : `(bvor ${a} ${b})`;
    case 'xor': return n._ty === 'bool' ? `(xor ${a} ${b})` : `(bvxor ${a} ${b})`;
  }
  throw new Error(`Cannot encode op ${n.op}`);
}
// Annotate `not`/`and`/`or`/`xor` nodes with their operand type so bool and bit-vector forms differ.
function annotate(n, typeOfVar) {
  switch (n.op) {
    case 'var': return typeOfVar(n.name);
    case 'const': return n.type;
    case 'not': n._ty = annotate(n.arg, typeOfVar); return n._ty;
    case 'select': annotate(n.cond, typeOfVar); annotate(n.else, typeOfVar); return annotate(n.then, typeOfVar);
    default: { const t = annotate(n.left, typeOfVar); annotate(n.right, typeOfVar); n._ty = t; return ['eq', 'ne', 'ltu', 'leu'].includes(n.op) ? 'bool' : t; }
  }
}
const sort = t => (t === 'bool' ? 'Bool' : '(_ BitVec 32)');

/** Encode one v2 program as define-funs over shared input constants. Returns { lines, outputs }. */
function encodeProgram(doc0, prefix, inputSym) {
  const doc = structuredClone(doc0);
  const { types } = validateVeilIRv2(doc);
  const lines = [];
  const cur = new Map(); // IR name -> SMT symbol
  doc.inputs.forEach(p => cur.set(p.name, inputSym(p.name)));
  let fresh = 0;
  const def = (name, type, body) => { const s = `${prefix}${fresh++}_${name}`; lines.push(`(define-fun ${s} () ${sort(type)} ${body})`); return s; };
  for (const st of doc.body) {
    if ('let' in st) {
      annotate(st.expr, nm => types.get(nm));
      cur.set(st.let, def(st.let, types.get(st.let), encodeExpr(st.expr, nm => cur.get(nm))));
      continue;
    }
    const names = Object.keys(st.loop.vars);
    const inner = new Map(cur);
    for (const nm of names) { annotate(st.loop.vars[nm], x => types.get(x)); inner.set(nm, def(nm, types.get(nm), encodeExpr(st.loop.vars[nm], x => cur.get(x)))); }
    for (const nm of names) annotate(st.loop.update[nm], x => types.get(x));
    for (let k = 0; k < st.loop.count; k++) {
      const next = names.map(nm => def(nm, types.get(nm), encodeExpr(st.loop.update[nm], x => inner.get(x))));
      names.forEach((nm, i) => inner.set(nm, next[i]));
    }
    for (const nm of names) cur.set(nm, inner.get(nm));
  }
  return { lines, outputs: doc.outputs.map(o => cur.get(o.name)) };
}

/** Build the SMT-LIB query "exists inputs such that some output differs". */
export function equivalenceQuery(a, b) {
  const A = a.schemaVersion === 1 ? (validateVeilIR(a), upgradeV1ToV2(a)) : a;
  const B = b.schemaVersion === 1 ? (validateVeilIR(b), upgradeV1ToV2(b)) : b;
  const sig = d => JSON.stringify({ i: d.inputs, o: d.outputs.map(o => o.type) });
  if (sig(A) !== sig(B)) throw new Error('Programs have different interfaces');
  const inputSym = name => `in_${name}`;
  const pa = encodeProgram(A, 'a', inputSym), pb = encodeProgram(B, 'b', inputSym);
  const diff = pa.outputs.map((s, i) => `(not (= ${s} ${pb.outputs[i]}))`);
  return [
    '(set-logic QF_BV)',
    '(set-option :produce-models true)',
    ...A.inputs.map(p => `(declare-const ${inputSym(p.name)} ${sort(p.type)})`),
    ...pa.lines, ...pb.lines,
    `(assert ${diff.length === 1 ? diff[0] : `(or ${diff.join(' ')})`})`,
    '(check-sat)',
    `(get-value (${A.inputs.map(p => inputSym(p.name)).join(' ')}))`,
    ''
  ].join('\n');
}

export function solverAvailable(solver = process.env.APPVEIL_Z3 || 'z3') {
  const p = spawnSync(solver, ['-version'], { encoding: 'utf8' });
  return p.status === 0 ? p.stdout.trim() : null;
}

/**
 * Check equivalence of two IR programs. Returns
 *   { result: 'equivalent' } | { result: 'counterexample', inputs } | { result: 'not-checked', reason }.
 */
export function checkEquivalence(a, b, { solver = process.env.APPVEIL_Z3 || 'z3', timeoutSec = 60 } = {}) {
  const version = solverAvailable(solver);
  if (!version) return { result: 'not-checked', reason: `SMT solver not available (${solver}); install z3 or set APPVEIL_Z3` };
  const query = equivalenceQuery(a, b);
  const p = spawnSync(solver, ['-smt2', '-in', `-T:${timeoutSec}`], { input: query, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const out = (p.stdout || '').trim();
  const first = out.split('\n')[0];
  if (first === 'unsat') return { result: 'equivalent', solver: version, scope: 'all inputs (QF_BV, loops fully unrolled)' };
  if (first === 'sat') {
    const inputs = {};
    for (const m of out.matchAll(/\(in_([a-z_][a-z0-9_]*) (#x[0-9a-f]{8}|true|false)\)/g)) inputs[m[1]] = m[2] === 'true' ? true : m[2] === 'false' ? false : parseInt(m[2].slice(2), 16);
    return { result: 'counterexample', solver: version, inputs };
  }
  return { result: 'not-checked', solver: version, reason: `solver returned ${JSON.stringify(first || p.stderr?.trim() || p.status)} (timeout or unknown)` };
}
