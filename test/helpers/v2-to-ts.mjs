// Print a Veil IR v2 program as restricted TypeScript (test helper for round-trip checks).
function ex(n) {
  switch (n.op) {
    case 'var': return n.name;
    case 'const': return String(n.value);
    case 'not': return n.ty === 'bool' ? `(!${ex(n.arg)})` : `((~${ex(n.arg)}) >>> 0)`;
    case 'select': return `(${ex(n.cond)} ? ${ex(n.then)} : ${ex(n.else)})`;
    case 'mul': return `(Math.imul(${ex(n.left)}, ${ex(n.right)}) >>> 0)`;
    case 'ushr': return `(${ex(n.left)} >>> ${ex(n.right)})`;
    case 'eq': return `(${ex(n.left)} === ${ex(n.right)})`;
    case 'ne': return `(${ex(n.left)} !== ${ex(n.right)})`;
    case 'ltu': return `(${ex(n.left)} < ${ex(n.right)})`;
    case 'leu': return `(${ex(n.left)} <= ${ex(n.right)})`;
    default: {
      if (n.ty === 'bool') return n.op === 'and' ? `(${ex(n.left)} && ${ex(n.right)})` : n.op === 'or' ? `(${ex(n.left)} || ${ex(n.right)})` : `(${ex(n.left)} !== ${ex(n.right)})`;
      const sym = { add: '+', sub: '-', shl: '<<', shr: '>>', and: '&', or: '|', xor: '^' }[n.op];
      return `((${ex(n.left)} ${sym} ${ex(n.right)}) >>> 0)`;
    }
  }
}
// Annotate nodes with their type so `not`/logic print correctly.
function annotate(n, env) {
  switch (n.op) {
    case 'var': return env.get(n.name);
    case 'const': return n.type;
    case 'not': n.ty = annotate(n.arg, env); return n.ty;
    case 'select': annotate(n.cond, env); annotate(n.else, env); return annotate(n.then, env);
    default: { const t = annotate(n.left, env); annotate(n.right, env); n.ty = t; return ['eq', 'ne', 'ltu', 'leu'].includes(n.op) ? 'bool' : t; }
  }
}
export function v2ToTs(doc0) {
  const doc = structuredClone(doc0);
  const env = new Map(doc.inputs.map(p => [p.name, p.type]));
  const T = t => (t === 'u32' ? 'number' : 'boolean');
  const lines = [];
  let tmp = 0;
  for (const st of doc.body) {
    if ('let' in st) { env.set(st.let, annotate(st.expr, env)); lines.push(`  const ${st.let} = ${ex(st.expr)};`); continue; }
    const names = Object.keys(st.loop.vars);
    for (const nm of names) { const t = annotate(st.loop.vars[nm], env); lines.push(`  let ${nm} = ${ex(st.loop.vars[nm])};`); env.set(nm, t); }
    const temps = names.map(nm => { const t = `tmp${tmp++}`; lines.push(`  let ${t} = ${env.get(nm) === 'u32' ? '0' : 'false'};`); return t; });
    const idx = `k${tmp++}`;
    lines.push(`  for (let ${idx} = 0; ${idx} < ${st.loop.count}; ${idx}++) {`);
    // Simultaneous update via temporaries assigned first, then copied.
    names.forEach((nm, i) => { annotate(st.loop.update[nm], env); lines.push(`    ${temps[i]} = ${ex(st.loop.update[nm])};`); });
    names.forEach((nm, i) => lines.push(`    ${nm} = ${temps[i]};`));
    lines.push('  }');
  }
  const ret = doc.outputs.map(o => `${o.name}: ${T(o.type)}`).join('; ');
  const fields = doc.outputs.map(o => `${o.name}: ${o.name}`).join(', ');
  return `export function f(${doc.inputs.map(p => `${p.name}: ${T(p.type)}`).join(', ')}): { ${ret} } {\n${lines.join('\n')}\n  return { ${fields} };\n}\n`;
}
