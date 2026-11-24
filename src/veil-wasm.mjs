import { createHash } from 'node:crypto';
import { validateVeilIR } from './veil-ir.mjs';

/**
 * Independent backend: Veil IR v1 -> WebAssembly binary, emitted directly (no toolchain). The module
 * exports one function `f(i32) -> i32` and has NO imports, so it gets no ambient capabilities.
 * Wasm masks shift counts to 5 bits, matching Veil semantics; `shr` maps to i32.shr_s.
 * Wasm is decompilable: this backend is a correctness cross-check and benchmark target, NOT a
 * confidentiality mechanism.
 */
const OP = { add: 0x6a, sub: 0x6b, mul: 0x6c, and: 0x71, or: 0x72, xor: 0x73, shl: 0x74, shr: 0x75, ushr: 0x76 };
const I32_CONST = 0x41, LOCAL_GET = 0x20, END = 0x0b;

function uleb(n) { const out = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n); return out; }
function sleb32(v) {
  let n = v | 0; const out = [];
  for (;;) {
    const b = n & 0x7f; n >>= 7;
    if ((n === 0 && (b & 0x40) === 0) || (n === -1 && (b & 0x40) !== 0)) { out.push(b); return out; }
    out.push(b | 0x80);
  }
}
const section = (id, bytes) => [id, ...uleb(bytes.length), ...bytes];
const vec = items => [...uleb(items.length), ...items.flat()];

export function compileVeilIRToWasm(ir) {
  validateVeilIR(ir);
  const code = [];
  (function emit(node) {
    if (node.op === 'input') code.push(LOCAL_GET, 0);
    else if (node.op === 'const') code.push(I32_CONST, ...sleb32(node.value));
    else if (node.op === 'not') { emit(node.arg); code.push(I32_CONST, ...sleb32(-1), OP.xor); }
    else { emit(node.left); emit(node.right); code.push(OP[node.op]); }
  })(ir.expression);
  code.push(END);
  const body = [0x00 /* no locals */, ...code];
  const bytes = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, vec([[0x60, 1, 0x7f, 1, 0x7f]])),          // type: (i32) -> i32
    ...section(3, vec([[0]])),                              // function 0 uses type 0
    ...section(7, vec([[1, 0x66 /* "f" */, 0x00, 0]])),     // export "f" = func 0
    ...section(10, vec([[...uleb(body.length), ...body]]))  // code
  ];
  return Uint8Array.from(bytes);
}

/** Instantiate with an empty import object. Returns a uint32 -> uint32 function. */
export function instantiateVeilWasm(bytes) {
  const module = new WebAssembly.Module(bytes);
  const imports = WebAssembly.Module.imports(module);
  if (imports.length) throw new Error('Veil Wasm modules must not import anything');
  const { f } = new WebAssembly.Instance(module, {}).exports;
  if (typeof f !== 'function') throw new Error('Missing export f');
  return x => {
    if (!Number.isInteger(x) || x < 0 || x > 0xffffffff) throw new TypeError('Input must be uint32');
    return f(x | 0) >>> 0;
  };
}

export const wasmDigest = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
