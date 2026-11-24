import { readFileSync } from 'node:fs';
import path from 'node:path';

/**
 * Red Lab baseline attackers (research). Each attacker gets only what its attack class allows and
 * returns a DATA submission for the judge: { kind: 'ir', ir } or { kind: 'none', reason }.
 * They are written from the attacker's point of view: no defender compiler, loader or source is used.
 * Success means the defense FAILED against a trivial attacker; that is the expected result for v1.
 */

const BINARY = new Set(['add', 'sub', 'xor', 'and', 'or', 'mul', 'shl', 'shr', 'ushr']);

/**
 * Static attack (issue #12): decompile bytecode v1 to an expression tree. The artifact ships its own
 * opcode table, so every instruction's meaning is read directly; SSA registers are inlined back into a
 * tree. Works for every seed because the permutation is not secret.
 */
export function decompileBytecodeV1(artifact, { maxNodes = 4096 } = {}) {
  if (artifact?.format !== 'appveil-experimental-bytecode' || artifact.version !== 1) throw new Error('Not a bytecode v1 artifact');
  const { opcodes, instructions } = artifact;
  if (!Array.isArray(opcodes) || !Array.isArray(instructions)) throw new Error('Malformed artifact');
  const regs = [];
  let nodes = 0;
  const count = n => { if (++nodes > maxNodes) throw new Error('Decompiled tree too large'); return n; };
  const reg = r => { if (!Number.isInteger(r) || !(r in regs)) throw new Error(`Undefined register ${r}`); return structuredClone(regs[r]); };
  for (const inst of instructions) {
    if (!Array.isArray(inst)) throw new Error('Malformed instruction');
    const [code, dst, ...args] = inst;
    const op = opcodes[code];
    if (op === 'ret') return { schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression: reg(dst) };
    let node;
    if (op === 'load-input') node = { op: 'input' };
    else if (op === 'load-const') node = { op: 'const', value: args[0] };
    else if (op === 'not') node = { op: 'not', arg: reg(args[0]) };
    else if (BINARY.has(op)) node = { op, left: reg(args[0]), right: reg(args[1]) };
    else throw new Error(`Unknown operation ${String(op)}`);
    regs[dst] = count(node);
  }
  throw new Error('No ret instruction');
}

/** Static attacker over a trial workspace: reads only attackerDir/artifact.json. */
export function staticDecompileAttack(attackerDir) {
  const t0 = process.hrtime.bigint();
  try {
    const artifact = JSON.parse(readFileSync(path.join(attackerDir, 'artifact.json'), 'utf8'));
    const ir = decompileBytecodeV1(artifact);
    return { submission: { kind: 'ir', ir }, used: { timeMs: Number(process.hrtime.bigint() - t0) / 1e6 } };
  } catch (e) {
    return { submission: { kind: 'none', reason: e.message }, used: { timeMs: Number(process.hrtime.bigint() - t0) / 1e6 } };
  }
}

/**
 * Dynamic attack (issue #13): run the shipped VM runtime under the V8 inspector, as a host-root
 * debugger would, and record each executed step's operand registers, operand values and result.
 * Each step's operation is inferred ONLY from observed input/output values across many runs. The
 * opcode table and the bytecode format are never consulted. The defender's source is not modified.
 */
export async function dynamicTraceAttack(attackerDir, { runs = 24, seed = 0x7ace } = {}) {
  const t0 = process.hrtime.bigint();
  const { Session } = await import('node:inspector');
  const { pathToFileURL, fileURLToPath } = await import('node:url');
  const runtimeUrl = new URL('./veil-ir.mjs', import.meta.url);
  const runtime = await import(runtimeUrl.href);
  const lines = readFileSync(fileURLToPath(runtimeUrl), 'utf8').split('\n');
  // The attacker reads the (shipped, readable) runtime to choose breakpoint locations.
  const stepLine = lines.findIndex(l => l.includes('switch (kind[i])'));
  const retLine = lines.findIndex(l => l.includes('return r[ret];'));
  if (stepLine < 0 || retLine < 0) return { submission: { kind: 'none', reason: 'breakpoint locations not found in runtime' }, used: {} };
  const handle = runtime.loadVeilBytecode(JSON.parse(readFileSync(path.join(attackerDir, 'artifact.json'), 'utf8')));
  const session = new Session();
  session.connect();
  const post = (method, params) => { let out, err; session.post(method, params, (e, r) => { err = e; out = r; }); if (err) throw err; return out; };
  let current = null;
  session.on('Debugger.paused', ({ params }) => {
    const frame = params.callFrames[0];
    const ev = expression => post('Debugger.evaluateOnCallFrame', { callFrameId: frame.callFrameId, expression, returnByValue: true }).result.value;
    try {
      if (frame.location.lineNumber === stepLine) current.steps.push(ev('[i, a[i], b[i]]'));
      else if (frame.location.lineNumber === retLine) { current.regs = ev('Array.from(r)'); current.ret = ev('ret'); }
    } finally { post('Debugger.resume'); }
  });
  const traces = [];
  try {
    post('Debugger.enable');
    const url = pathToFileURL(fileURLToPath(runtimeUrl)).href;
    post('Debugger.setBreakpointByUrl', { url, lineNumber: stepLine });
    post('Debugger.setBreakpointByUrl', { url, lineNumber: retLine });
    let s = seed >>> 0;
    const rand = () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>>= 0; };
    for (let k = 0; k < runs; k++) {
      const input = k < 6 ? [0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff][k] : rand();
      current = { input, steps: [], regs: null, ret: null };
      const output = runtime.executeVeilBytecode(handle, input);
      traces.push({ ...current, output });
    }
  } finally {
    try { post('Debugger.disable'); } catch { /* ignore */ }
    session.disconnect();
  }
  const used = { queries: runs, timeMs: Number(process.hrtime.bigint() - t0) / 1e6 };
  try {
    return { submission: { kind: 'ir', ir: reconstructFromTraces(traces) }, used };
  } catch (e) {
    return { submission: { kind: 'none', reason: e.message }, used };
  }
}

const U = v => v >>> 0;
const OBSERVED_BINARY = {
  add: (x, y) => U(x + y), sub: (x, y) => U(x - y), xor: (x, y) => U(x ^ y), and: (x, y) => U(x & y), or: (x, y) => U(x | y),
  mul: (x, y) => U(Math.imul(x, y)), shl: (x, y) => U(x << (y & 31)), shr: (x, y) => U(x >> (y & 31)), ushr: (x, y) => x >>> (y & 31)
};

/** Infer each step's operation from (operand values -> result) observations, then rebuild the tree. */
export function reconstructFromTraces(traces) {
  if (!traces.length || !traces.every(t => t.regs && t.steps.length === traces[0].steps.length)) throw new Error('Inconsistent traces');
  const n = traces[0].steps.length;
  const inferred = [];
  for (let i = 0; i < n; i++) {
    const [, ai, bi] = traces[0].steps[i];
    const obs = traces.map(t => ({ input: t.input, out: t.regs[i], x: t.regs[ai], y: t.regs[bi] }));
    let node;
    if (obs.every(o => o.out === o.input)) node = { kind: 'input' };
    else if (obs.every(o => o.out === obs[0].out)) node = { kind: 'const', value: obs[0].out };
    else if (ai < i && obs.every(o => o.out === U(~o.x))) node = { kind: 'not', a: ai };
    else {
      const op = Object.keys(OBSERVED_BINARY).find(k => ai < i && bi < i && obs.every(o => o.out === OBSERVED_BINARY[k](o.x, o.y)));
      if (!op) throw new Error(`Could not infer operation at step ${i}`);
      node = { kind: op, a: ai, b: bi };
    }
    inferred.push(node);
  }
  const ret = traces[0].ret;
  const build = i => {
    const s = inferred[i];
    if (s.kind === 'input') return { op: 'input' };
    if (s.kind === 'const') return { op: 'const', value: s.value };
    if (s.kind === 'not') return { op: 'not', arg: build(s.a) };
    return { op: s.kind, left: build(s.a), right: build(s.b) };
  };
  return { schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression: build(ret) };
}
