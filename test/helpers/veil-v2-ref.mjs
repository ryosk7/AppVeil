// Independent reference semantics and random generator for Veil IR v2 (shares no code with src/).
const M = (1n << 32n) - 1n;
const sgn = a => (a >= 1n << 31n ? a - (1n << 32n) : a);
const U32 = { add: (a, b) => (a + b) & M, sub: (a, b) => (a - b) & M, mul: (a, b) => (a * b) & M, shl: (a, b) => (a << (b & 31n)) & M, shr: (a, b) => sgn(a) >> (b & 31n) & M, ushr: (a, b) => a >> (b & 31n) };
function ev(n, env) {
  switch (n.op) {
    case 'var': return env[n.name];
    case 'const': return n.type === 'bool' ? n.value : BigInt(n.value);
    case 'not': { const v = ev(n.arg, env); return typeof v === 'boolean' ? !v : ~v & M; }
    case 'select': return ev(n.cond, env) === true ? ev(n.then, env) : ev(n.else, env);
    default: {
      const a = ev(n.left, env), b = ev(n.right, env);
      if (n.op in U32) return U32[n.op](a, b);
      if (n.op === 'eq') return a === b;
      if (n.op === 'ne') return a !== b;
      if (n.op === 'ltu') return a < b;
      if (n.op === 'leu') return a <= b;
      if (typeof a === 'boolean') return n.op === 'and' ? a && b : n.op === 'or' ? a || b : a !== b;
      return n.op === 'and' ? a & b : n.op === 'or' ? a | b : a ^ b;
    }
  }
}
/** Reference evaluation: inputs { name: number|boolean } -> outputs { name: number|boolean }. */
export function refEvalV2(doc, inputs) {
  const env = {};
  for (const p of doc.inputs) env[p.name] = p.type === 'bool' ? inputs[p.name] : BigInt(inputs[p.name]);
  for (const st of doc.body) {
    if ('let' in st) { env[st.let] = ev(st.expr, env); continue; }
    const names = Object.keys(st.loop.vars);
    const inner = { ...env };
    for (const k of names) inner[k] = ev(st.loop.vars[k], env);
    for (let i = 0; i < st.loop.count; i++) { const nx = names.map(k => ev(st.loop.update[k], inner)); names.forEach((k, j) => { inner[k] = nx[j]; }); }
    for (const k of names) env[k] = inner[k];
  }
  return Object.fromEntries(doc.outputs.map(p => [p.name, typeof env[p.name] === 'bigint' ? Number(env[p.name]) : env[p.name]]));
}

export function rngV2(seed) {
  let x = seed >>> 0 || 7;
  const n = () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>>= 0; };
  n.pick = a => a[n() % a.length];
  return n;
}
/** Random well-typed v2 program with lets, loops, selects, comparisons and bool logic. */
export function randomV2(next, { maxStmts = 6 } = {}) {
  const inputs = [];
  const nIn = 1 + next() % 3;
  for (let i = 0; i < nIn; i++) inputs.push({ name: `i${i}`, type: next() % 4 === 0 ? 'bool' : 'u32' });
  if (!inputs.some(p => p.type === 'u32')) inputs[0].type = 'u32';
  const scope = inputs.map(p => [p.name, p.type]);
  const ofType = t => scope.filter(([, ty]) => ty === t).map(([n]) => n);
  function expr(type, depth) {
    const vars = ofType(type);
    const r = next() % 10;
    if (depth > 3 || r < 3) {
      if (vars.length && next() % 3) return { op: 'var', name: next.pick(vars) };
      return type === 'u32' ? { op: 'const', type, value: next() % 3 ? next() % 64 : next() } : { op: 'const', type, value: !!(next() & 1) };
    }
    if (r === 3) return { op: 'not', arg: expr(type, depth + 1) };
    if (r === 4) return { op: 'select', cond: expr('bool', depth + 1), then: expr(type, depth + 1), else: expr(type, depth + 1) };
    if (type === 'bool') {
      if (next() % 2) return { op: next.pick(['eq', 'ne', 'ltu', 'leu']), left: expr('u32', depth + 1), right: expr('u32', depth + 1) };
      return { op: next.pick(['and', 'or', 'xor', 'eq', 'ne']), left: expr('bool', depth + 1), right: expr('bool', depth + 1) };
    }
    return { op: next.pick(['add', 'sub', 'mul', 'shl', 'shr', 'ushr', 'and', 'or', 'xor']), left: expr('u32', depth + 1), right: expr('u32', depth + 1) };
  }
  const body = [];
  const nSt = 1 + next() % maxStmts;
  for (let s = 0; s < nSt; s++) {
    if (next() % 3 === 0) {
      const vars = {}, update = {}, names = [];
      const k = 1 + next() % 2;
      for (let j = 0; j < k; j++) { const nm = `l${s}_${j}`; names.push([nm, j === 0 || next() % 2 ? 'u32' : 'bool']); }
      for (const [nm, t] of names) vars[nm] = expr(t, 2);
      scope.push(...names);
      for (const [nm, t] of names) update[nm] = expr(t, 1);
      body.push({ loop: { count: 1 + next() % 12, vars, update } });
    } else {
      const t = next() % 4 === 0 ? 'bool' : 'u32';
      const nm = `v${s}`;
      body.push({ let: nm, expr: expr(t, 0) });
      scope.push([nm, t]);
    }
  }
  const defined = body.flatMap(st => ('let' in st ? [st.let] : Object.keys(st.loop.vars)));
  const typeOf = nm => scope.find(([n]) => n === nm)[1];
  const outs = [...new Set([defined[defined.length - 1], next.pick(defined)])];
  return { schemaVersion: 2, inputs, outputs: outs.map(nm => ({ name: nm, type: typeOf(nm) })), body };
}
export function randomInputs(doc, next) {
  return Object.fromEntries(doc.inputs.map(p => [p.name, p.type === 'bool' ? !!(next() & 1) : (next() % 4 === 0 ? next.pick([0, 1, 0x7fffffff, 0x80000000, 0xffffffff]) : next())]));
}
