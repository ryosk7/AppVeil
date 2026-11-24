import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { validateVeilIR, compileVeilIR, loadVeilBytecode, executeVeilBytecode } from './veil-ir.mjs';
import { compileVeilIRToWasm, instantiateVeilWasm } from './veil-wasm.mjs';

/**
 * Backend matrix (issue #10): compile ONE Veil IR program to every backend, verify each against an
 * independent BigInt reference, and only then measure cost and mechanical observability. Missing
 * toolchains are recorded as `not-checked`, never as passed. Measures cost only, not AI resistance.
 */
const MASK = (1n << 32n) - 1n;
const S = a => (a >= 1n << 31n ? a - (1n << 32n) : a);
const REF = { add: (a, b) => (a + b) & MASK, sub: (a, b) => (a - b) & MASK, xor: (a, b) => a ^ b, and: (a, b) => a & b, or: (a, b) => a | b, mul: (a, b) => (a * b) & MASK, shl: (a, b) => (a << (b & 31n)) & MASK, shr: (a, b) => S(a) >> (b & 31n) & MASK, ushr: (a, b) => a >> (b & 31n) };
function refEval(n, x) {
  if (n.op === 'input') return x;
  if (n.op === 'const') return BigInt(n.value);
  if (n.op === 'not') return ~refEval(n.arg, x) & MASK;
  return REF[n.op](refEval(n.left, x), refEval(n.right, x));
}

/** IR -> JS expression (all intermediate values kept as uint32). */
export function irToJs(n) {
  if (n.op === 'input') return 'x';
  if (n.op === 'const') return String(n.value);
  if (n.op === 'not') return `(~${irToJs(n.arg)}>>>0)`;
  const a = irToJs(n.left), b = irToJs(n.right);
  switch (n.op) {
    case 'mul': return `(Math.imul(${a},${b})>>>0)`;
    case 'ushr': return `(${a}>>>(${b}&31))`;
    case 'shr': return `((${a}>>(${b}&31))>>>0)`;
    case 'shl': return `((${a}<<(${b}&31))>>>0)`;
    default: return `((${a}${{ add: '+', sub: '-', xor: '^', and: '&', or: '|' }[n.op]}${b})>>>0)`;
  }
}
/** IR -> C expression over uint32_t (shift counts masked; shr via int32 arithmetic shift). */
export function irToC(n) {
  if (n.op === 'input') return 'x';
  if (n.op === 'const') return `UINT32_C(${n.value})`;
  if (n.op === 'not') return `((uint32_t)~${irToC(n.arg)})`;
  const a = irToC(n.left), b = irToC(n.right);
  switch (n.op) {
    case 'shl': return `((uint32_t)(${a} << (${b} & 31u)))`;
    case 'ushr': return `((uint32_t)(${a} >> (${b} & 31u)))`;
    case 'shr': return `((uint32_t)((int32_t)${a} >> (${b} & 31u)))`;
    default: return `((uint32_t)(${a} ${{ add: '+', sub: '-', xor: '^', and: '&', or: '|', mul: '*' }[n.op]} ${b}))`;
  }
}

const sha = b => createHash('sha256').update(b).digest('hex');
function inputs(n, seed = 0x51ab) {
  let s = seed;
  const r = () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>>= 0; };
  return Uint32Array.from({ length: n }, (_, i) => (i < 6 ? [0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff][i] : r()));
}
const CHILD = new URL('./backend-timer-child.mjs', import.meta.url);
/** Time one backend in a fresh Node process (median of 7 after warm-up). */
function timeInChild(kind, artifactPath, inputsPath) {
  const p = spawnSync(process.execPath, [CHILD.pathname, kind, artifactPath, inputsPath], { encoding: 'utf8' });
  if (p.status !== 0) throw new Error(`timer child failed for ${kind}: ${p.stderr.split('\n')[0]}`);
  return +JSON.parse(p.stdout).nsPerCall.toFixed(2);
}
/** Constants of the IR that are visible in the artifact (decimal text, or LE32 / signed LEB128 bytes). */
function visibleConstants(ir, bytes) {
  const consts = [];
  (function walk(n) { if (n.op === 'const') consts.push(n.value); for (const k of ['arg', 'left', 'right']) if (n[k]) walk(n[k]); })(ir.expression);
  const text = Buffer.from(bytes).toString('latin1');
  const leb = v => { const o = []; let n = v | 0; for (;;) { const b = n & 0x7f; n >>= 7; if ((n === 0 && !(b & 0x40)) || (n === -1 && (b & 0x40))) { o.push(b); break; } o.push(b | 0x80); } return Buffer.from([0x41, ...o]); };
  const le = v => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b; };
  const big = consts.filter(v => v > 255); // small constants are indistinguishable from noise
  const seen = big.filter(v => text.includes(String(v)) || Buffer.from(bytes).includes(le(v)) || Buffer.from(bytes).includes(leb(v)));
  return { constantsAbove255: big.length, visible: seen.length };
}
const toolVersion = (cmd, args) => { const p = spawnSync(cmd, args, { encoding: 'utf8' }); return p.status === 0 ? p.stdout.split('\n')[0].trim() : null; };

export async function runBackendMatrix(ir, { samples = 1000, timingInputs = 100000 } = {}) {
  validateVeilIR(ir);
  const check = inputs(samples, 0xc0de);
  const timed = inputs(timingInputs);
  const expected = Array.from(check, x => Number(refEval(ir.expression, BigInt(x))));
  const dir = mkdtempSync(path.join(tmpdir(), 'appveil-matrix-'));
  const rows = [];
  const timedFile = path.join(dir, 'timed.bin');
  writeFileSync(timedFile, Buffer.from(timed.buffer));
  // `timing` is { native } or [kind, artifactPath] for a child-process timer.
  const record = (name, artifactBytes, fn, timing, extra = {}) => {
    const bad = Array.from(check).findIndex((x, i) => fn(x) !== expected[i]);
    if (bad >= 0) { rows.push({ backend: name, status: 'incorrect', firstMismatchInput: check[bad] }); return; }
    const t = timing.native ?? { nsPerCall: timeInChild(timing[0], timing[1], timedFile), timing: 'fresh Node process per backend, median of 7' };
    rows.push({ backend: name, status: 'measured', bytes: artifactBytes.length, sha256: sha(artifactBytes), ...visibleConstants(ir, artifactBytes), ...t, ...extra });
  };
  try {
    // Plain and minified JS: generated from validated IR, written to a file and imported (no eval of strings).
    const expr = irToJs(ir.expression);
    const plain = `// generated from Veil IR\nexport function f(x) {\n  return ${expr};\n}\n`;
    const minified = `export function f(x){return ${expr}}`;
    for (const [name, src] of [['plain-js', plain], ['minified-js', minified]]) {
      const file = path.join(dir, `${name}.mjs`);
      writeFileSync(file, src);
      const { f } = await import(pathToFileURL(file).href);
      record(name, Buffer.from(src), f, ['js', file]);
    }
    const bc = compileVeilIR(ir, { seed: 42 });
    const h = loadVeilBytecode(bc);
    const bcFile = path.join(dir, 'bc.json');
    writeFileSync(bcFile, JSON.stringify(bc));
    record('veil-vm-v1', Buffer.from(JSON.stringify(bc)), x => executeVeilBytecode(h, x), ['veil-vm', bcFile]);
    const vw = compileVeilIRToWasm(ir);
    const vwFile = path.join(dir, 'veil.wasm');
    writeFileSync(vwFile, vw);
    record('veil-wasm-v1', vw, instantiateVeilWasm(vw), ['wasm', vwFile]);
    // C toolchain backends.
    const cBody = `#include <stdint.h>\nuint32_t f(uint32_t x) { return ${irToC(ir.expression)}; }\n`;
    writeFileSync(path.join(dir, 'f.c'), cBody);
    const clang = toolVersion('clang', ['--version']);
    if (!clang) rows.push({ backend: 'native-clang-O2', status: 'not-checked', reason: 'clang not found' }, { backend: 'clang-wasm32', status: 'not-checked', reason: 'clang not found' });
    else {
      // Native: a harness verifies outputs and times the loop itself; the binary is the measured artifact's host.
      const harness = `#include <stdio.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <time.h>\nuint32_t f(uint32_t);\nint main(int c,char**v){FILE*in=fopen(v[1],"rb");long n=atol(v[2]);uint32_t*xs=malloc(4*n);if(fread(xs,4,n,in)!=(size_t)n)return 3;fclose(in);\nif(c>3){for(long i=0;i<n;i++)printf("%u\\n",f(xs[i]));return 0;}\nvolatile uint32_t sink=0;struct timespec a,b;double best=1e18;for(int r=0;r<5;r++){clock_gettime(CLOCK_MONOTONIC,&a);for(long i=0;i<n;i++)sink^=f(xs[i]);clock_gettime(CLOCK_MONOTONIC,&b);double ns=((b.tv_sec-a.tv_sec)*1e9+(b.tv_nsec-a.tv_nsec))/n;if(ns<best)best=ns;}printf("%f\\n",best);return 0;}\n`;
      writeFileSync(path.join(dir, 'h.c'), harness);
      const obj = path.join(dir, 'f.o'), exe = path.join(dir, 'h');
      const okObj = spawnSync('clang', ['-O2', '-c', path.join(dir, 'f.c'), '-o', obj]).status === 0;
      // f lives in a separate object, so it stays an out-of-line call (no cross-TU inlining without LTO).
      const okExe = okObj && spawnSync('clang', ['-O2', path.join(dir, 'h.c'), obj, '-o', exe]).status === 0;
      if (!okExe) rows.push({ backend: 'native-clang-O2', status: 'not-checked', reason: 'native build failed' });
      else {
        const inFile = path.join(dir, 'in.bin');
        writeFileSync(inFile, Buffer.from(check.buffer));
        const outs = spawnSync(exe, [inFile, String(samples), 'print'], { encoding: 'utf8' }).stdout.trim().split('\n').map(Number);
        writeFileSync(inFile, Buffer.from(timed.buffer));
        const ns = Number(spawnSync(exe, [inFile, String(timingInputs)], { encoding: 'utf8' }).stdout.trim());
        const fn = x => outs[Array.prototype.indexOf.call(check, x)];
        record('native-clang-O2', readFileSync(obj), fn, { native: { nsPerCall: +ns.toFixed(2), timing: 'native harness loop (min of 5); excludes JS call overhead' } }, { toolchain: clang });
      }
      const wasmOut = path.join(dir, 'c.wasm');
      const w = spawnSync('clang', ['--target=wasm32', '-O2', '-nostdlib', '-Wl,--no-entry', '-Wl,--export=f', path.join(dir, 'f.c'), '-o', wasmOut], { encoding: 'utf8' });
      if (w.status !== 0 || !existsSync(wasmOut)) rows.push({ backend: 'clang-wasm32', status: 'not-checked', reason: (w.stderr || 'build failed').split('\n')[0].slice(0, 160) });
      else {
        const bytes = readFileSync(wasmOut);
        const { f } = new WebAssembly.Instance(new WebAssembly.Module(bytes), {}).exports;
        record('clang-wasm32', bytes, x => f(x | 0) >>> 0, ['wasm', wasmOut], { toolchain: clang });
      }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
  return {
    schemaVersion: 1,
    note: 'Cost and mechanical observability only. NOT evidence of confidentiality or reverse-engineering resistance; see research/RED_LAB_BASELINE.md (all encodings are fully recovered).',
    node: process.version,
    samplesChecked: samples, timingInputs,
    rows
  };
}
