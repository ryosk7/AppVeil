import { validateVeilIRv2 } from './veil-ir-v2.mjs';

/**
 * Restricted TypeScript subset -> Veil IR v2 (research prototype, issue #16).
 *
 * The accepted subset is chosen so that executing the TypeScript under normal JS semantics gives
 * exactly the IR semantics: every int32-producing operation must be explicitly wrapped in `>>> 0`
 * (`(a + b) >>> 0`, `Math.imul(a, b) >>> 0`, `(a & b) >>> 0`, `(~a) >>> 0`, ...). Anything outside
 * the subset is rejected with a source-located diagnostic. The source is parsed, never executed.
 * Spec: research/TS_FRONTEND.md.
 */
export class TsSubsetError extends Error {
  constructor(message, loc) { super(loc ? `${loc.line}:${loc.col}: ${message}` : message); this.loc = loc; }
}
const MAX_SOURCE = 256 * 1024;

// ---------------- tokenizer ----------------
const PUNCT = ['>>>=', '>>>', '===', '!==', '<<=', '>>=', '**', '&&', '||', '<<', '>>', '<=', '>=', '==', '!=', '++', '--', '+=', '-=', '*=', '&=', '|=', '^=', '=>', '...',
  '{', '}', '(', ')', '[', ']', ';', ',', ':', '?', '.', '=', '+', '-', '*', '/', '%', '&', '|', '^', '~', '!', '<', '>', '@', '#', '`'];
function tokenize(src) {
  if (typeof src !== 'string') throw new TsSubsetError('Source must be a string');
  if (src.length > MAX_SOURCE) throw new TsSubsetError(`Source larger than ${MAX_SOURCE} bytes`);
  const toks = [];
  let i = 0, line = 1, col = 1;
  const adv = n => { for (let k = 0; k < n; k++) { if (src[i] === '\n') { line++; col = 1; } else col++; i++; } };
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { adv(1); continue; }
    if (src.startsWith('//', i)) { while (i < src.length && src[i] !== '\n') adv(1); continue; }
    if (src.startsWith('/*', i)) { const e = src.indexOf('*/', i + 2); if (e < 0) throw new TsSubsetError('Unterminated comment', { line, col }); adv(e + 2 - i); continue; }
    const loc = { line, col };
    if (/[A-Za-z_$]/.test(c)) { let j = i; while (j < src.length && /[A-Za-z0-9_$]/.test(src[j])) j++; toks.push({ t: 'id', v: src.slice(i, j), loc }); adv(j - i); continue; }
    if (/[0-9]/.test(c)) {
      const m = /^(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|[0-9][0-9_]*)(?![A-Za-z0-9_.$])/.exec(src.slice(i));
      if (!m) throw new TsSubsetError('Only integer literals are supported (no floats, exponents or BigInt)', loc);
      toks.push({ t: 'num', v: m[0], loc }); adv(m[0].length); continue;
    }
    if (c === '"' || c === "'") throw new TsSubsetError('String literals are not supported', loc);
    const p = PUNCT.find(q => src.startsWith(q, i));
    if (!p) throw new TsSubsetError(`Unexpected character ${JSON.stringify(c)}`, loc);
    toks.push({ t: 'p', v: p, loc }); adv(p.length);
  }
  toks.push({ t: 'eof', v: '<eof>', loc: { line, col } });
  return toks;
}

// ---------------- parser (subset AST) ----------------
const RESERVED_REJECT = new Set(['var', 'while', 'do', 'switch', 'class', 'new', 'this', 'function', 'async', 'await', 'yield', 'import', 'typeof', 'delete', 'void', 'in', 'instanceof', 'try', 'throw', 'with', 'debugger', 'eval', 'arguments', 'any', 'unknown', 'break', 'continue']);
function parse(src) {
  const toks = tokenize(src);
  let k = 0;
  const peek = (o = 0) => toks[k + o];
  const is = (v, o = 0) => (peek(o).t === 'p' || peek(o).t === 'id') && peek(o).v === v;
  const fail = (msg, tok = peek()) => { throw new TsSubsetError(msg, tok.loc); };
  const eat = v => { if (!is(v)) fail(`Expected '${v}' but found '${peek().v}'`); return toks[k++]; };
  const ident = () => {
    const t = peek();
    if (t.t !== 'id') fail(`Expected identifier but found '${t.v}'`);
    if (RESERVED_REJECT.has(t.v)) fail(`'${t.v}' is not supported in the restricted subset`);
    k++; return t;
  };
  function type() {
    const t = peek();
    if (is('number') || is('boolean')) { k++; return t.v === 'number' ? 'u32' : 'bool'; }
    fail(`Only 'number' (uint32) and 'boolean' types are supported, found '${t.v}'`);
  }
  // Expressions, by precedence: ternary > || > && > | > ^ > & > equality > relational > shift > additive > multiplicative > unary > primary
  function expr() { return ternary(); }
  function ternary() {
    const cond = binary(0);
    if (is('?')) { const loc = eat('?').loc; const a = expr(); eat(':'); const b = expr(); return { k: 'cond', cond, a, b, loc }; }
    return cond;
  }
  const LEVELS = [['||'], ['&&'], ['|'], ['^'], ['&'], ['===', '!==', '==', '!='], ['<', '<=', '>', '>='], ['<<', '>>', '>>>'], ['+', '-'], ['*', '/', '%', '**']];
  function binary(level) {
    if (level === LEVELS.length) return unary();
    let left = binary(level + 1);
    while (peek().t === 'p' && LEVELS[level].includes(peek().v)) {
      const op = toks[k++];
      if (op.v === '==' || op.v === '!=') fail(`Use '${op.v}=' (strict equality)`, op);
      if (op.v === '/' || op.v === '%' || op.v === '**') fail(`Operator '${op.v}' is not supported (no division, remainder or exponent in the uint32 subset)`, op);
      const right = binary(level + 1);
      left = { k: 'bin', op: op.v, left, right, loc: op.loc };
    }
    return left;
  }
  function unary() {
    if (is('!') || is('~')) { const op = toks[k++]; return { k: 'un', op: op.v, arg: unary(), loc: op.loc }; }
    if (is('-') || is('+')) fail(`Unary '${peek().v}' is not supported; write the uint32 value explicitly`);
    if (is('++') || is('--')) fail(`'${peek().v}' is only allowed as the for-loop increment`);
    return primary();
  }
  function primary() {
    const t = peek();
    if (is('(')) { eat('('); const e = expr(); eat(')'); return { ...e, paren: true }; }
    if (t.t === 'num') {
      k++;
      const v = Number(t.v.replace(/_/g, ''));
      if (!Number.isSafeInteger(v) || v < 0 || v > 0xffffffff) fail('Integer literal must be in [0, 2^32)', t);
      return { k: 'num', v, loc: t.loc };
    }
    if (is('true') || is('false')) { k++; return { k: 'bool', v: t.v === 'true', loc: t.loc }; }
    if (is('Math') && is('.', 1)) {
      k += 2;
      const m = ident();
      if (m.v !== 'imul') fail(`Only Math.imul is supported, found Math.${m.v}`, m);
      eat('('); const a = expr(); eat(','); const b = expr(); eat(')');
      return { k: 'imul', a, b, loc: t.loc };
    }
    const id = ident();
    if (is('(')) fail(`Calls are not supported (only Math.imul): ${id.v}(...)`, id);
    if (is('.') || is('[')) fail(`Property access is not supported: ${id.v}${peek().v}...`, id);
    return { k: 'id', name: id.v, loc: id.loc };
  }
  function block() {
    eat('{');
    const body = [];
    while (!is('}')) body.push(statement());
    eat('}');
    return body;
  }
  function statement() {
    const t = peek();
    if (t.t === 'id' && RESERVED_REJECT.has(t.v)) fail(`'${t.v}' is not supported in the restricted subset`);
    if (is('const') || is('let')) {
      const kind = toks[k++].v;
      const name = ident();
      let ty = null;
      if (is(':')) { eat(':'); ty = type(); }
      eat('='); const init = expr(); eat(';');
      return { k: 'decl', kind, name: name.v, ty, init, loc: name.loc };
    }
    if (is('if')) {
      eat('if'); eat('('); const cond = expr(); eat(')');
      const then = block();
      let els = [];
      if (is('else')) { eat('else'); els = is('if') ? [statement()] : block(); }
      return { k: 'if', cond, then, els, loc: t.loc };
    }
    if (is('for')) {
      eat('for'); eat('('); eat('let');
      const iv = ident(); if (is(':')) { eat(':'); if (type() !== 'u32') fail('Loop index must be a number', iv); }
      eat('=');
      const start = peek(); if (start.t !== 'num' || Number(start.v) !== 0) fail('Loop index must start at literal 0'); k++;
      eat(';');
      const iv2 = ident(); if (iv2.v !== iv.v) fail('Loop condition must test the loop index', iv2);
      eat('<');
      const bound = peek(); if (bound.t !== 'num') fail('Loop bound must be an integer literal (statically bounded loops only)'); k++;
      eat(';');
      const iv3 = ident(); if (iv3.v !== iv.v) fail('Loop increment must be <index>++', iv3);
      eat('++'); eat(')');
      const body = block();
      return { k: 'for', index: iv.v, count: Number(bound.v.replace(/_/g, '')), body, loc: t.loc };
    }
    if (is('return')) {
      eat('return');
      if (is('{')) {
        eat('{');
        const fields = [];
        while (!is('}')) { const n = ident(); eat(':'); fields.push({ name: n.v, e: expr(), loc: n.loc }); if (!is('}')) eat(','); }
        eat('}'); eat(';');
        return { k: 'return', fields, loc: t.loc };
      }
      const e = expr(); eat(';');
      return { k: 'return', e, loc: t.loc };
    }
    if (peek().t === 'id' && is('=', 1)) {
      const name = ident(); eat('='); const e = expr(); eat(';');
      return { k: 'assign', name: name.v, e, loc: name.loc };
    }
    if (peek().t === 'id' && peek(1).t === 'p' && /^(?:\+|-|\*|&|\||\^|<<|>>|>>>)=$/.test(peek(1).v)) fail(`Compound assignment '${peek(1).v}' is not supported; write x = (x op y) >>> 0`, peek(1));
    fail(`Unsupported statement starting with '${t.v}'`);
  }
  // Program: exactly one exported function.
  eat('export');
  if (!is('function')) fail("Expected 'function' after 'export'");
  k++;
  const fname = ident();
  eat('(');
  const params = [];
  while (!is(')')) { const n = ident(); eat(':'); params.push({ name: n.v, type: type(), loc: n.loc }); if (!is(')')) eat(','); }
  eat(')');
  eat(':');
  let ret;
  if (is('{')) {
    eat('{'); ret = [];
    while (!is('}')) { const n = ident(); eat(':'); ret.push({ name: n.v, type: type() }); if (is(';') || is(',')) k++; }
    eat('}');
  } else ret = type();
  const body = block();
  if (peek().t !== 'eof') fail('Only one exported function is allowed per module');
  return { name: fname.v, params, ret, body };
}

// ---------------- lowering to IR v2 ----------------
const INT32_OPS = { '+': 'add', '-': 'sub', '<<': 'shl', '>>': 'shr', '&': 'and', '|': 'or', '^': 'xor' };
const CMP = { '===': 'eq', '!==': 'ne', '<': 'ltu', '<=': 'leu' };
function lowerFunction(ast) {
  const scope = new Map(); // source name -> { ir: current SSA name, type, mutable }
  const used = new Set();
  const fresh = base => { let n = base, i = 1; while (used.has(n)) n = `${base}_${i++}`; used.add(n); return n; };
  const v = name => ({ op: 'var', name });
  const err = (msg, loc) => { throw new TsSubsetError(msg, loc); };
  const SAFE_NAME = /^[a-z_][a-z0-9_]{0,24}$/;
  const irName = (src, loc) => { if (!SAFE_NAME.test(src)) err(`Identifier '${src}' must match ${SAFE_NAME} (lowercase, digits, underscore)`, loc); return src; };

  // Expression lowering. `env` maps source names to IR expressions (vars or substituted expressions).
  function lowerExpr(e, env) {
    switch (e.k) {
      case 'num': return { ir: { op: 'const', type: 'u32', value: e.v }, ty: 'u32' };
      case 'bool': return { ir: { op: 'const', type: 'bool', value: e.v }, ty: 'bool' };
      case 'id': {
        if (!env.has(e.name)) err(`Unknown identifier '${e.name}' (no globals, closures or ambient APIs)`, e.loc);
        return env.get(e.name);
      }
      case 'imul': err('Math.imul(a, b) must be wrapped as Math.imul(a, b) >>> 0', e.loc); break;
      case 'un': {
        const a = lowerExpr(e.arg, env);
        if (e.op === '!') { if (a.ty !== 'bool') err("'!' requires a boolean", e.loc); return { ir: { op: 'not', arg: a.ir }, ty: 'bool' }; }
        err("'~x' produces int32; write (~x) >>> 0", e.loc); break;
      }
      case 'cond': {
        const c = lowerExpr(e.cond, env), a = lowerExpr(e.a, env), b = lowerExpr(e.b, env);
        if (c.ty !== 'bool') err('Conditional test must be boolean', e.loc);
        if (a.ty !== b.ty) err('Both branches of ?: must have the same type', e.loc);
        return { ir: { op: 'select', cond: c.ir, then: a.ir, else: b.ir }, ty: a.ty };
      }
      case 'bin': {
        if (e.op === '>>>') {
          const r = lowerExpr(e.right, env);
          if (r.ty !== 'u32') err("'>>>' requires numbers", e.loc);
          // `X >>> 0` is the uint32 wrapper of an int32-producing operation.
          if (e.right.k === 'num' && e.right.v === 0) {
            const inner = e.left;
            if (inner.k === 'imul') { const a = lowerExpr(inner.a, env), b = lowerExpr(inner.b, env); need(a, b, 'Math.imul', inner.loc); return { ir: { op: 'mul', left: a.ir, right: b.ir }, ty: 'u32' }; }
            if (inner.k === 'un' && inner.op === '~') { const a = lowerExpr(inner.arg, env); if (a.ty !== 'u32') err("'~' requires a number", inner.loc); return { ir: { op: 'not', arg: a.ir }, ty: 'u32' }; }
            if (inner.k === 'bin' && INT32_OPS[inner.op]) { const a = lowerExpr(inner.left, env), b = lowerExpr(inner.right, env); need(a, b, inner.op, inner.loc); return { ir: { op: INT32_OPS[inner.op], left: a.ir, right: b.ir }, ty: 'u32' }; }
          }
          const l = lowerExpr(e.left, env);
          if (l.ty !== 'u32') err("'>>>' requires numbers", e.loc);
          return { ir: { op: 'ushr', left: l.ir, right: r.ir }, ty: 'u32' };
        }
        if (INT32_OPS[e.op] || e.op === '*') {
          if (e.op === '*') err("'*' loses precision above 2^53; write Math.imul(a, b) >>> 0", e.loc);
          // Bool logic with & | ^ is not allowed either (it yields numbers in JS).
          err(`'${e.op}' produces int32 or an unbounded number in JS; wrap it as (a ${e.op} b) >>> 0`, e.loc);
        }
        const a = lowerExpr(e.left, env), b = lowerExpr(e.right, env);
        if (e.op === '&&' || e.op === '||') { if (a.ty !== 'bool' || b.ty !== 'bool') err(`'${e.op}' requires booleans`, e.loc); return { ir: { op: e.op === '&&' ? 'and' : 'or', left: a.ir, right: b.ir }, ty: 'bool' }; }
        if (e.op === '===' || e.op === '!==') { if (a.ty !== b.ty) err(`'${e.op}' operands must have the same type`, e.loc); return { ir: { op: CMP[e.op], left: a.ir, right: b.ir }, ty: 'bool' }; }
        if (a.ty !== 'u32' || b.ty !== 'u32') err(`'${e.op}' requires numbers`, e.loc);
        if (e.op === '>') return { ir: { op: 'ltu', left: b.ir, right: a.ir }, ty: 'bool' };
        if (e.op === '>=') return { ir: { op: 'leu', left: b.ir, right: a.ir }, ty: 'bool' };
        return { ir: { op: CMP[e.op], left: a.ir, right: b.ir }, ty: 'bool' };
      }
    }
    err(`Unsupported expression`, e.loc);
  }
  function need(a, b, op, loc) {
    if (a.ty !== 'u32' || b.ty !== 'u32') err(`'${op}' requires numbers (for booleans use && || !)`, loc);
  }

  const body = [];
  const env = new Map(); // source name -> lowered value { ir: var node, ty }
  for (const p of ast.params) {
    irName(p.name, p.loc);
    if (env.has(p.name)) err(`Duplicate parameter '${p.name}'`, p.loc);
    used.add(p.name);
    env.set(p.name, { ir: v(p.name), ty: p.type });
    scope.set(p.name, { mutable: false, ty: p.type });
  }
  let result = null;
  // Statements at function level: each assignment creates a fresh SSA name.
  function bind(srcName, value, loc) {
    const name = fresh(irName(srcName, loc));
    body.push({ let: name, expr: value.ir });
    env.set(srcName, { ir: v(name), ty: value.ty });
  }
  // Within a branch or loop body: track assignments symbolically (substitution) without emitting.
  function symbolic(stmts, envIn, mutableSet, ctx) {
    const local = new Map(envIn);
    for (const s of stmts) {
      if (s.k === 'assign') {
        if (!mutableSet.has(s.name)) err(scope.has(s.name) ? `'${s.name}' is const or not assignable here` : `Unknown variable '${s.name}'`, s.loc);
        const val = lowerExpr(s.e, local);
        if (val.ty !== local.get(s.name).ty) err(`Assignment changes the type of '${s.name}'`, s.loc);
        local.set(s.name, val);
      } else if (s.k === 'if') {
        const c = lowerExpr(s.cond, local);
        if (c.ty !== 'bool') err('if condition must be boolean', s.loc);
        const t = symbolic(s.then, local, mutableSet, ctx), f = symbolic(s.els, local, mutableSet, ctx);
        for (const name of mutableSet) {
          const a = t.get(name), b = f.get(name);
          if (a !== b) local.set(name, { ir: { op: 'select', cond: c.ir, then: a.ir, else: b.ir }, ty: a.ty });
        }
      } else err(`Only assignments and if statements are allowed inside ${ctx}`, s.loc);
    }
    return local;
  }
  const mutables = new Set();
  for (const s of ast.body) {
    if (result) err('Statements after return are not allowed', s.loc);
    if (s.k === 'decl') {
      if (env.has(s.name)) err(`'${s.name}' is already declared (no shadowing)`, s.loc);
      const val = lowerExpr(s.init, env);
      if (s.ty && s.ty !== val.ty) err(`Declared type ${s.ty === 'u32' ? 'number' : 'boolean'} does not match initializer`, s.loc);
      bind(s.name, val, s.loc);
      scope.set(s.name, { mutable: s.kind === 'let', ty: val.ty });
      if (s.kind === 'let') mutables.add(s.name);
    } else if (s.k === 'assign') {
      if (!mutables.has(s.name)) err(scope.has(s.name) ? `Cannot assign to const or parameter '${s.name}'` : `Unknown variable '${s.name}'`, s.loc);
      const val = lowerExpr(s.e, env);
      if (val.ty !== env.get(s.name).ty) err(`Assignment changes the type of '${s.name}'`, s.loc);
      bind(s.name, val, s.loc);
    } else if (s.k === 'if') {
      const out = symbolic([s], env, mutables, 'if statements');
      for (const name of mutables) if (out.get(name) !== env.get(name)) bind(name, out.get(name), s.loc);
    } else if (s.k === 'for') {
      if (!Number.isSafeInteger(s.count) || s.count < 1 || s.count > 1024) err('Loop bound must be in [1, 1024]', s.loc);
      if (env.has(s.index)) err(`Loop index '${s.index}' shadows an existing name`, s.loc);
      // Loop-carried variables: the index plus every outer `let` assigned in the body.
      const assigned = new Set();
      (function collect(stmts) { for (const st of stmts) { if (st.k === 'assign') assigned.add(st.name); else if (st.k === 'if') { collect(st.then); collect(st.els); } } })(s.body);
      for (const n of assigned) if (!mutables.has(n)) err(n === s.index ? 'The loop index must not be assigned in the body' : `'${n}' must be an outer 'let' to be assigned in a loop`, s.loc);
      const carried = [...assigned];
      const names = new Map();
      const vars = {}, inner = new Map(env);
      const idx = fresh(irName(s.index, s.loc));
      names.set(s.index, idx); vars[idx] = { op: 'const', type: 'u32', value: 0 }; inner.set(s.index, { ir: v(idx), ty: 'u32' });
      for (const n of carried) { const ln = fresh(n); names.set(n, ln); vars[ln] = env.get(n).ir; inner.set(n, { ir: v(ln), ty: env.get(n).ty }); }
      // JS runs the body sequentially; substitution turns it into the IR's simultaneous update.
      const after = symbolic(s.body, inner, new Set(carried), 'for loops');
      const update = { [idx]: { op: 'add', left: v(idx), right: { op: 'const', type: 'u32', value: 1 } } };
      for (const n of carried) update[names.get(n)] = after.get(n).ir;
      body.push({ loop: { count: s.count, vars, update } });
      for (const n of carried) env.set(n, { ir: v(names.get(n)), ty: env.get(n).ty });
    } else if (s.k === 'return') {
      result = s;
    } else err('Unsupported statement', s.loc);
  }
  if (!result) err('Function must end with a return statement', ast.body.at(-1)?.loc ?? { line: 1, col: 1 });
  const outputs = [];
  const emitOut = (name, e, ty, loc) => {
    const val = lowerExpr(e, env);
    if (val.ty !== ty) err(`Return value '${name}' must be ${ty === 'u32' ? 'number' : 'boolean'}`, loc);
    const outName = fresh(`out_${name}`);
    body.push({ let: outName, expr: val.ir });
    outputs.push({ name: outName, type: ty, source: name });
  };
  if (Array.isArray(ast.ret)) {
    if (!result.fields) err('Return type is an object; return an object literal with the same fields', result.loc);
    const want = ast.ret.map(f => f.name).join(), got = result.fields.map(f => f.name).join();
    if (want !== got) err(`Returned fields (${got}) must match the declared return type (${want}) in order`, result.loc);
    ast.ret.forEach((f, i) => emitOut(irName(f.name, result.fields[i].loc), result.fields[i].e, f.type, result.fields[i].loc));
  } else {
    if (result.fields) err('Return type is not an object', result.loc);
    emitOut('result', result.e, ast.ret, result.loc);
  }
  return {
    ir: { schemaVersion: 2, inputs: ast.params.map(p => ({ name: p.name, type: p.type })), outputs: outputs.map(({ name, type }) => ({ name, type })), body },
    outputMap: Object.fromEntries(outputs.map(o => [o.name, o.source]))
  };
}

/** Compile a restricted-TypeScript module. Returns { ir, outputMap, functionName }. Throws TsSubsetError. */
export function compileTypeScriptSubset(source) {
  const ast = parse(source);
  const { ir, outputMap } = lowerFunction(ast);
  try { validateVeilIRv2(ir); } catch (e) { throw new TsSubsetError(`Program exceeds IR v2 limits: ${e.message}`); }
  return { ir, outputMap, functionName: ast.name };
}

/**
 * Strip the subset's type annotations to plain JavaScript (for differential testing only). The
 * input must already have been accepted by compileTypeScriptSubset.
 */
export function stripTypesForTesting(source) {
  compileTypeScriptSubset(source);
  return source
    .replace(/\)\s*:\s*\{[^}]*\}\s*\{/, ') {')
    .replace(/\)\s*:\s*(?:number|boolean)\s*\{/, ') {')
    .replace(/([A-Za-z_$][\w$]*)\s*:\s*(?:number|boolean)\b/g, '$1');
}
