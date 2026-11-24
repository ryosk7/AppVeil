/**
 * Non-AI black-box imitation baseline (issue #14). The attacker sees ONLY a query-limited oracle.
 * Bottom-up enumerative synthesis over Veil IR v1 with observational-equivalence pruning, plus
 * algebraic solving of one top-level 32-bit constant (`t op c`). Bounded by query, time and term
 * budgets. Success is judged by the Red Lab judge on hidden holdout inputs, so overfitting to the
 * queried examples shows up as accuracy < 1.
 */
const U = v => v >>> 0;
const BIN = {
  add: (a, b) => U(a + b), sub: (a, b) => U(a - b), xor: (a, b) => U(a ^ b), and: (a, b) => U(a & b), or: (a, b) => U(a | b),
  mul: (a, b) => U(Math.imul(a, b)), shl: (a, b) => U(a << (b & 31)), shr: (a, b) => U(a >> (b & 31)), ushr: (a, b) => a >>> (b & 31)
};
const SEED_CONSTS = [0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 24, 31, 0xff, 0xffff, 0x80000000, 0xffffffff];

// Modular inverse of an odd uint32 (Newton iteration).
function inverseOdd(a) { let x = a; for (let i = 0; i < 5; i++) x = U(Math.imul(x, U(2 - Math.imul(a, x)))); return x; }

/** Try to find c with Y = t op c (or c op t) for every example. Returns { op, c, constLeft } or null. */
export function solveConstant(t, Y) {
  const n = Y.length, all = f => { for (let i = 0; i < n; i++) if (!f(i)) return false; return true; };
  let c = U(Y[0] - t[0]); if (all(i => U(t[i] + c) === Y[i])) return { op: 'add', c };
  c = U(Y[0] ^ t[0]); if (all(i => U(t[i] ^ c) === Y[i])) return { op: 'xor', c };
  c = U(t[0] - Y[0]); if (all(i => U(t[i] - c) === Y[i])) return { op: 'sub', c };
  c = U(Y[0] + t[0]); if (all(i => U(c - t[i]) === Y[i])) return { op: 'sub', c, constLeft: true };
  for (let k = 0; k < n; k++) if (t[k] & 1) { c = U(Math.imul(Y[k], inverseOdd(t[k]))); if (all(i => U(Math.imul(t[i], c)) === Y[i])) return { op: 'mul', c }; break; }
  let andC = 0; for (let i = 0; i < n; i++) andC = U(andC | Y[i]);
  if (all(i => U(t[i] & andC) === Y[i])) return { op: 'and', c: andC };
  let orC = 0xffffffff; for (let i = 0; i < n; i++) orC = U(orC & Y[i]);
  if (all(i => U(t[i] | orC) === Y[i])) return { op: 'or', c: orC };
  return null;
}

/**
 * Synthesize from an oracle. Returns { submission, used }. Never executes attacker-generated code:
 * candidate terms are evaluated by the fixed interpreter above.
 */
export function blackBoxImitationAttack(oracle, { queries, timeMs = 1000, maxTerms = 20000, seed = 0xb1ac } = {}) {
  const t0 = Date.now();
  let s = seed >>> 0;
  const rand = () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>>= 0; };
  const edge = [0, 1, 2, 3, 0x7fffffff, 0x80000000, 0xffffffff];
  const X = Array.from({ length: queries }, (_, i) => (i < edge.length ? edge[i] : rand()));
  const Y = X.map(x => oracle(x));
  const key = v => v.join(',');
  const target = key(Y);
  const seen = new Map();
  const terms = [];
  const add = (expr, vals) => {
    const k = key(vals);
    if (seen.has(k)) return null;
    const term = { expr, vals };
    seen.set(k, term); terms.push(term);
    return term;
  };
  const done = expr => ({ submission: { kind: 'ir', ir: { schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression: expr } }, used: { queries, timeMs: Date.now() - t0 } });
  const check = term => {
    if (!term) return null;
    if (key(term.vals) === target) return done(term.expr);
    const sol = solveConstant(term.vals, Y);
    if (sol) {
      const c = { op: 'const', value: sol.c };
      return done(sol.constLeft ? { op: sol.op, left: c, right: term.expr } : { op: sol.op, left: term.expr, right: c });
    }
    return null;
  };
  let r = check(add({ op: 'input' }, X.slice()));
  if (r) return r;
  for (const v of SEED_CONSTS) add({ op: 'const', value: v }, X.map(() => v));
  // Bottom-up: each round combines all existing terms; stop on success or budget.
  for (let round = 0; round < 6; round++) {
    const snapshot = terms.length;
    for (let i = 0; i < snapshot; i++) {
      if (Date.now() - t0 > timeMs || terms.length >= maxTerms) return { submission: { kind: 'none', reason: 'budget exhausted' }, used: { queries, timeMs: Date.now() - t0 } };
      const a = terms[i];
      if ((r = check(add({ op: 'not', arg: a.expr }, a.vals.map(v => U(~v)))))) return r;
      for (let j = 0; j < snapshot; j++) {
        const b = terms[j];
        for (const [op, f] of Object.entries(BIN)) {
          if ((op === 'add' || op === 'xor' || op === 'and' || op === 'or' || op === 'mul') && j < i) continue; // commutative
          if ((r = check(add({ op, left: a.expr, right: b.expr }, a.vals.map((v, k) => f(v, b.vals[k])))))) return r;
        }
      }
    }
  }
  return { submission: { kind: 'none', reason: 'search space exhausted' }, used: { queries, timeMs: Date.now() - t0 } };
}
