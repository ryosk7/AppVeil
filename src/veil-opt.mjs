import { validateVeilIRv2, evaluateVeilIRv2 } from './veil-ir-v2.mjs';
import { canonicalJson } from './veil-ir.mjs';
import { checkEquivalence } from './veil-smt.mjs';

/**
 * IR v2 optimizer with per-compilation translation validation (issue #17).
 * Passes: constant folding + algebraic identities, common-subexpression elimination against earlier
 * top-level lets, copy propagation, and dead-code elimination. After optimizing, the result is checked
 * against the original on boundary and seeded inputs; any mismatch ABORTS (fail closed).
 * Differential validation is not a proof; bounded SMT equivalence (issue #19) can be layered on top.
 */
const U = v => v >>> 0;
const MAX = 0xffffffff;
const isC = (n, t) => n.op === 'const' && (!t || n.type === t);
const u32 = value => ({ op: 'const', type: 'u32', value: U(value) });
const bool = value => ({ op: 'const', type: 'bool', value });
const same = (a, b) => canonicalJson(a) === canonicalJson(b);
const FOLD = {
  add: (a, b) => U(a + b), sub: (a, b) => U(a - b), mul: (a, b) => U(Math.imul(a, b)),
  shl: (a, b) => U(a << (b & 31)), shr: (a, b) => U(a >> (b & 31)), ushr: (a, b) => a >>> (b & 31),
  eq: (a, b) => a === b, ne: (a, b) => a !== b, ltu: (a, b) => a < b, leu: (a, b) => a <= b
};

/** One bottom-up simplification of an expression. `typeOf(node)` gives 'u32' | 'bool'. */
function simplify(n, typeOf) {
  switch (n.op) {
    case 'var': case 'const': return n;
    case 'not': {
      const a = simplify(n.arg, typeOf);
      if (isC(a)) return a.type === 'bool' ? bool(!a.value) : u32(~a.value);
      if (a.op === 'not') return a.arg;
      return { op: 'not', arg: a };
    }
    case 'select': {
      const c = simplify(n.cond, typeOf), t = simplify(n.then, typeOf), e = simplify(n.else, typeOf);
      if (isC(c)) return c.value ? t : e;
      if (same(t, e)) return t;
      return { op: 'select', cond: c, then: t, else: e };
    }
  }
  const a = simplify(n.left, typeOf), b = simplify(n.right, typeOf);
  const out = { op: n.op, left: a, right: b };
  if (isC(a) && isC(b)) {
    if (FOLD[n.op]) { const v = FOLD[n.op](a.value, b.value); return typeof v === 'boolean' ? bool(v) : u32(v); }
    if (a.type === 'bool') return bool(n.op === 'and' ? a.value && b.value : n.op === 'or' ? a.value || b.value : a.value !== b.value);
    return u32(n.op === 'and' ? a.value & b.value : n.op === 'or' ? a.value | b.value : a.value ^ b.value);
  }
  const ty = typeOf(a);
  // Algebraic identities (each is exact for uint32 / bool semantics).
  if (ty === 'u32') {
    if ((n.op === 'add' || n.op === 'or' || n.op === 'xor') && isC(b, 'u32') && b.value === 0) return a;
    if ((n.op === 'add' || n.op === 'or' || n.op === 'xor') && isC(a, 'u32') && a.value === 0) return b;
    if (n.op === 'sub' && isC(b, 'u32') && b.value === 0) return a;
    // Shift counts are taken mod 32, so any multiple of 32 is an identity (but NOT for sub).
    if ((n.op === 'shl' || n.op === 'shr' || n.op === 'ushr') && isC(b, 'u32') && (b.value & 31) === 0) return a;
    if (n.op === 'mul' && isC(b, 'u32') && b.value === 1) return a;
    if (n.op === 'mul' && isC(a, 'u32') && a.value === 1) return b;
    if ((n.op === 'mul' || n.op === 'and') && ((isC(b, 'u32') && b.value === 0) || (isC(a, 'u32') && a.value === 0))) return u32(0);
    if (n.op === 'and' && isC(b, 'u32') && b.value === MAX) return a;
    if (n.op === 'and' && isC(a, 'u32') && a.value === MAX) return b;
    if ((n.op === 'sub' || n.op === 'xor') && same(a, b)) return u32(0);
    if ((n.op === 'and' || n.op === 'or') && same(a, b)) return a;
  } else if (ty === 'bool') {
    if (n.op === 'and' && isC(b, 'bool')) return b.value ? a : bool(false);
    if (n.op === 'and' && isC(a, 'bool')) return a.value ? b : bool(false);
    if (n.op === 'or' && isC(b, 'bool')) return b.value ? bool(true) : a;
    if (n.op === 'or' && isC(a, 'bool')) return a.value ? bool(true) : b;
    if ((n.op === 'and' || n.op === 'or') && same(a, b)) return a;
  }
  if ((n.op === 'eq' || n.op === 'leu') && same(a, b)) return bool(true);
  if ((n.op === 'ne' || n.op === 'ltu') && same(a, b)) return bool(false);
  return out;
}

function exprTypeFactory(types) {
  const t = n => {
    switch (n.op) {
      case 'var': return types.get(n.name);
      case 'const': return n.type;
      case 'not': return t(n.arg);
      case 'select': return t(n.then);
      case 'eq': case 'ne': case 'ltu': case 'leu': return 'bool';
      case 'and': case 'or': case 'xor': return t(n.left);
      default: return 'u32';
    }
  };
  return t;
}
const mapExpr = (n, f) => {
  const m = n.op === 'not' ? { ...n, arg: mapExpr(n.arg, f) } : n.op === 'select' ? { ...n, cond: mapExpr(n.cond, f), then: mapExpr(n.then, f), else: mapExpr(n.else, f) }
    : 'left' in n ? { ...n, left: mapExpr(n.left, f), right: mapExpr(n.right, f) } : n;
  return f(m);
};
const countNodes = n => 1 + (n.op === 'not' ? countNodes(n.arg) : n.op === 'select' ? countNodes(n.cond) + countNodes(n.then) + countNodes(n.else) : 'left' in n ? countNodes(n.left) + countNodes(n.right) : 0);
const varsIn = (n, out = new Set()) => { mapExpr(n, m => { if (m.op === 'var') out.add(m.name); return m; }); return out; };
export function programSize(doc) {
  let s = 0;
  for (const st of doc.body) s += 'let' in st ? countNodes(st.expr) : st.loop.count * Object.values(st.loop.update).reduce((a, e) => a + countNodes(e), 0) + Object.values(st.loop.vars).reduce((a, e) => a + countNodes(e), 0);
  return s;
}

/** Apply passes once. Pure function of the input document. */
export function optimizeOnce(doc) {
  const { types } = validateVeilIRv2(doc);
  const typeOf = exprTypeFactory(types);
  const outputs = new Set(doc.outputs.map(o => o.name));
  // 1. fold + copy/constant propagation + CSE against earlier top-level lets.
  const subst = new Map();      // name -> replacement expression (var or const)
  const available = new Map();  // canonical expr -> defining let name
  const replace = n => mapExpr(n, m => (m.op === 'var' && subst.has(m.name) ? subst.get(m.name) : m));
  const cse = n => mapExpr(n, m => { if (m.op === 'var' || m.op === 'const') return m; const hit = available.get(canonicalJson(m)); return hit ? { op: 'var', name: hit } : m; });
  const body = [];
  for (const st of doc.body) {
    if ('let' in st) {
      const e = cse(simplify(replace(st.expr), typeOf));
      if ((e.op === 'var' || e.op === 'const') && !outputs.has(st.let)) { subst.set(st.let, e); continue; }
      if (e.op !== 'var' && e.op !== 'const' && !available.has(canonicalJson(e))) available.set(canonicalJson(e), st.let);
      body.push({ let: st.let, expr: e });
    } else {
      const names = new Set(Object.keys(st.loop.vars));
      const vars = {}, update = {};
      for (const [k, e] of Object.entries(st.loop.vars)) vars[k] = cse(simplify(replace(e), typeOf));
      // Inside the update, loop variables denote per-iteration values: never substitute them away.
      const replaceInner = n => mapExpr(n, m => (m.op === 'var' && !names.has(m.name) && subst.has(m.name) ? subst.get(m.name) : m));
      for (const [k, e] of Object.entries(st.loop.update)) update[k] = simplify(replaceInner(e), typeOf);
      body.push({ loop: { count: st.loop.count, vars, update } });
    }
  }
  // 2. dead-code elimination, walking backwards from the outputs.
  const live = new Set(doc.outputs.map(o => o.name));
  const kept = [];
  for (let i = body.length - 1; i >= 0; i--) {
    const st = body[i];
    if ('let' in st) {
      if (!live.has(st.let)) continue;
      varsIn(st.expr, live);
      kept.unshift(st);
    } else {
      const names = Object.keys(st.loop.vars);
      if (!names.some(n => live.has(n))) continue;
      // Keep every variable of a live loop (updates may depend on each other); trimming is future work.
      for (const n of names) { varsIn(st.loop.vars[n], live); varsIn(st.loop.update[n], live); }
      kept.unshift(st);
    }
  }
  return { ...doc, body: kept };
}

function* validationInputs(doc, samples, seed) {
  let s = seed >>> 0 || 1;
  const r = () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>>= 0; };
  const EDGE = [0, 1, 2, 31, 32, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff];
  for (let k = 0; k < samples; k++) {
    yield Object.fromEntries(doc.inputs.map((p, i) => [p.name, p.type === 'bool' ? !!((r() >>> (i % 31)) & 1) : (k < EDGE.length * doc.inputs.length ? EDGE[(k + i) % EDGE.length] : r())]));
  }
}

/** Check `optimized` against `original` on samples; throws on the first mismatch. */
export function translationValidate(original, optimized, { samples = 2000, seed = 0x7a11d } = {}) {
  validateVeilIRv2(optimized);
  if (canonicalJson(original.inputs) !== canonicalJson(optimized.inputs) || canonicalJson(original.outputs) !== canonicalJson(optimized.outputs)) throw new Error('Translation validation failed: interface changed');
  let checked = 0;
  for (const inp of validationInputs(original, samples, seed)) {
    const a = evaluateVeilIRv2(original, inp), b = evaluateVeilIRv2(optimized, inp);
    if (canonicalJson(a) !== canonicalJson(b)) throw new Error(`Translation validation failed on input ${JSON.stringify(inp)}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
    checked++;
  }
  return { checked };
}

/**
 * Optimize to a fixpoint (at most `rounds`), then translation-validate. Returns { ir, stats }.
 * `passes` may be overridden for testing the validator itself.
 */
export function optimizeVeilIRv2(doc, { rounds = 8, samples = 2000, pass = optimizeOnce, prove = false, smtTimeoutSec = 60, smtSolver } = {}) {
  validateVeilIRv2(doc);
  let cur = doc;
  for (let i = 0; i < rounds; i++) {
    const next = pass(cur);
    if (canonicalJson(next) === canonicalJson(cur)) break;
    cur = next;
  }
  const { checked } = translationValidate(doc, cur, { samples });
  // Optional SMT proof. A counterexample always aborts; with prove=true anything short of a proof aborts.
  let smt = null;
  if (prove) {
    smt = checkEquivalence(doc, cur, { timeoutSec: smtTimeoutSec, ...(smtSolver ? { solver: smtSolver } : {}) });
    if (smt.result === 'counterexample') throw new Error(`Translation validation failed (SMT counterexample ${JSON.stringify(smt.inputs)})`);
    if (smt.result !== 'equivalent') throw new Error(`Equivalence not proven: ${smt.reason}`);
  }
  return { ir: cur, stats: { sizeBefore: programSize(doc), sizeAfter: programSize(cur), statementsBefore: doc.body.length, statementsAfter: cur.body.length, validatedInputs: checked, validation: smt ? 'differential + SMT proof (all inputs)' : 'differential (boundary + seeded); not a proof', ...(smt ? { smt: smt.result } : {}) } };
}
