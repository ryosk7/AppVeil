import { readFileSync } from 'node:fs';
import path from 'node:path';

/**
 * Red Lab attackers against the Wasm defender (`veil-wasm-v1`), written from the attacker's side:
 * they use only the public WebAssembly binary format, never the defender's compiler.
 *  - wasmStaticDecompile: parse the code section and rebuild the expression (static attack).
 *  - wasmInstrumentationAttack: rewrite the binary to call an imported trace hook after every
 *    value-producing instruction, run it, and infer each operation from observed VALUES only. The
 *    stack discipline (how many operands an instruction pops) gives the dataflow (dynamic attack).
 */

function readUleb(buf, pos) {
  let result = 0, shift = 0, b;
  do { if (pos.i >= buf.length) throw new Error('Truncated LEB128'); b = buf[pos.i++]; result |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80 && shift < 35);
  return result >>> 0;
}
function readSleb32(buf, pos) {
  let result = 0, shift = 0, b;
  do { if (pos.i >= buf.length) throw new Error('Truncated LEB128'); b = buf[pos.i++]; result |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80 && shift < 35);
  if (shift < 32 && (b & 0x40)) result |= -1 << shift;
  return result | 0;
}
const uleb = n => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };

/** Split a module into sections: [{ id, bytes }]. */
export function parseSections(buf) {
  if (buf.length < 8 || buf.readUInt32LE(0) !== 0x6d736100 || buf.readUInt32LE(4) !== 1) throw new Error('Not a Wasm v1 module');
  const out = [], pos = { i: 8 };
  while (pos.i < buf.length) {
    const id = buf[pos.i++];
    const size = readUleb(buf, pos);
    if (pos.i + size > buf.length) throw new Error('Truncated section');
    out.push({ id, bytes: buf.subarray(pos.i, pos.i + size) });
    pos.i += size;
  }
  return out;
}

const BINOPS = { 0x6a: 'add', 0x6b: 'sub', 0x6c: 'mul', 0x71: 'and', 0x72: 'or', 0x73: 'xor', 0x74: 'shl', 0x75: 'shr', 0x76: 'ushr' };

/** Decode the single function body into instructions [{ kind, arg?, start, end }]. */
export function decodeSingleFunction(buf) {
  const sections = parseSections(buf);
  const code = sections.find(s => s.id === 10);
  if (!code) throw new Error('No code section');
  const pos = { i: 0 };
  if (readUleb(code.bytes, pos) !== 1) throw new Error('Expected exactly one function body');
  const size = readUleb(code.bytes, pos);
  const bodyEnd = pos.i + size;
  const localGroups = readUleb(code.bytes, pos);
  for (let g = 0; g < localGroups; g++) { readUleb(code.bytes, pos); pos.i++; }
  const instructions = [];
  while (pos.i < bodyEnd) {
    const start = pos.i, op = code.bytes[pos.i++];
    if (op === 0x0b) { instructions.push({ kind: 'end', start, end: pos.i }); break; }
    if (op === 0x20) instructions.push({ kind: 'local.get', arg: readUleb(code.bytes, pos), start, end: pos.i });
    else if (op === 0x41) instructions.push({ kind: 'i32.const', arg: readSleb32(code.bytes, pos), start, end: pos.i });
    else if (BINOPS[op]) instructions.push({ kind: 'binop', op: BINOPS[op], start, end: pos.i });
    else throw new Error(`Unsupported Wasm opcode 0x${op.toString(16)} (attacker decoder covers the observed subset only)`);
  }
  return { sections, code, instructions };
}

const asIR = expression => ({ schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression });

/** Static attack: simulate the operand stack symbolically. */
export function wasmStaticDecompile(attackerDir) {
  const t0 = Date.now();
  try {
    const { instructions } = decodeSingleFunction(readFileSync(path.join(attackerDir, 'artifact.wasm')));
    const stack = [];
    for (const ins of instructions) {
      if (ins.kind === 'local.get') stack.push({ op: 'input' });
      else if (ins.kind === 'i32.const') stack.push({ op: 'const', value: ins.arg >>> 0 });
      else if (ins.kind === 'binop') { const right = stack.pop(), left = stack.pop(); if (!left || !right) throw new Error('Stack underflow'); stack.push({ op: ins.op, left, right }); }
    }
    if (stack.length !== 1) throw new Error('Unexpected final stack');
    return { submission: { kind: 'ir', ir: asIR(stack[0]) }, used: { timeMs: Date.now() - t0 } };
  } catch (e) { return { submission: { kind: 'none', reason: e.message }, used: { timeMs: Date.now() - t0 } }; }
}

/**
 * Rewrite the module: add an import `t.trace : (i32) -> i32` (identity hook) as function 0, shift the
 * original function to index 1, and insert `call 0` after every value-producing instruction.
 */
export function instrumentForTracing(buf) {
  const { sections, code, instructions } = decodeSingleFunction(buf);
  const typeSec = sections.find(s => s.id === 1);
  // Reuse type 0 if it is (i32)->i32; the defender module has exactly that type.
  if (!typeSec || Buffer.compare(Buffer.from(typeSec.bytes), Buffer.from([1, 0x60, 1, 0x7f, 1, 0x7f])) !== 0) throw new Error('Unexpected type section');
  const body = [0x00];
  for (const ins of instructions) {
    body.push(...code.bytes.subarray(ins.start, ins.end));
    if (ins.kind !== 'end') body.push(0x10, 0x00); // call $trace
  }
  const sec = (id, bytes) => [id, ...uleb(bytes.length), ...bytes];
  const importSec = [1, 1, 0x74 /* "t" */, 5, ...Buffer.from('trace'), 0x00, 0x00];
  const out = [0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...sec(1, [...typeSec.bytes]), ...sec(2, importSec), ...sec(3, [1, 0]),
    ...sec(7, [1, 1, 0x66, 0x00, 1]), ...sec(10, [1, ...uleb(body.length), ...body])];
  return { bytes: Uint8Array.from(out), instructions: instructions.filter(i => i.kind !== 'end') };
}

const U = v => v >>> 0;
const VALUE_OPS = {
  add: (x, y) => U(x + y), sub: (x, y) => U(x - y), xor: (x, y) => U(x ^ y), and: (x, y) => U(x & y), or: (x, y) => U(x | y),
  mul: (x, y) => U(Math.imul(x, y)), shl: (x, y) => U(x << (y & 31)), shr: (x, y) => U(x >> (y & 31)), ushr: (x, y) => x >>> (y & 31)
};

/** Dynamic attack: run the instrumented binary over many inputs and infer operations from values. */
export function wasmInstrumentationAttack(attackerDir, { runs = 24, seed = 0x7ace } = {}) {
  const t0 = Date.now();
  try {
    const { bytes, instructions } = instrumentForTracing(readFileSync(path.join(attackerDir, 'artifact.wasm')));
    let log = [];
    const { f } = new WebAssembly.Instance(new WebAssembly.Module(bytes), { t: { trace: v => { log.push(v >>> 0); return v; } } }).exports;
    let s = seed >>> 0;
    const rand = () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>>= 0; };
    const traces = [];
    for (let k = 0; k < runs; k++) {
      const input = k < 6 ? [0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff][k] : rand();
      log = [];
      f(input | 0);
      if (log.length !== instructions.length) throw new Error('Trace length mismatch');
      traces.push({ input, values: log });
    }
    // Dataflow from stack discipline: value-producing instruction j pops `arity` earlier values.
    const operands = [], stack = [];
    instructions.forEach((ins, j) => {
      const arity = ins.kind === 'binop' ? 2 : 0;
      const args = stack.splice(stack.length - arity, arity);
      if (args.length !== arity) throw new Error('Stack underflow');
      operands.push(args); stack.push(j);
    });
    // Operation identity from values only (opcode bytes are used solely for arity).
    const nodes = instructions.map((ins, j) => {
      const obs = traces.map(t => ({ input: t.input, out: t.values[j], args: operands[j].map(a => t.values[a]) }));
      if (operands[j].length === 0) {
        if (obs.every(o => o.out === o.input)) return { kind: 'input' };
        if (obs.every(o => o.out === obs[0].out)) return { kind: 'const', value: obs[0].out };
        throw new Error(`Leaf ${j} is neither input nor constant`);
      }
      const op = Object.keys(VALUE_OPS).find(k => obs.every(o => o.out === VALUE_OPS[k](o.args[0], o.args[1])));
      if (!op) throw new Error(`Could not infer operation at ${j}`);
      return { kind: op, args: operands[j] };
    });
    const build = j => {
      const n = nodes[j];
      if (n.kind === 'input') return { op: 'input' };
      if (n.kind === 'const') return { op: 'const', value: n.value };
      return { op: n.kind, left: build(n.args[0]), right: build(n.args[1]) };
    };
    return { submission: { kind: 'ir', ir: asIR(build(stack[stack.length - 1])) }, used: { queries: runs, timeMs: Date.now() - t0 } };
  } catch (e) { return { submission: { kind: 'none', reason: e.message }, used: { queries: runs, timeMs: Date.now() - t0 } }; }
}
