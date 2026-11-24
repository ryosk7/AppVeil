import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { compileVeilIRToWasm, instantiateVeilWasm, wasmDigest } from '../src/veil-wasm.mjs';
import { compileVeilIR, loadVeilBytecode, executeVeilBytecode } from '../src/veil-ir.mjs';
import { rng, randomExpr, wrapIR, refEvalIR, REF_BINARY } from './helpers/veil-fuzz.mjs';

test('Wasm backend matches the BigInt reference and the VM on 500 generated programs', () => {
  const next = rng(0x3a5);
  for (let p = 0; p < 500; p++) {
    const ir = wrapIR(randomExpr(next));
    const f = instantiateVeilWasm(compileVeilIRToWasm(ir));
    const vm = loadVeilBytecode(compileVeilIR(ir, { seed: next() }));
    for (let k = 0; k < 20; k++) {
      const x = k < 5 ? [0, 1, 0x7fffffff, 0x80000000, 0xffffffff][k] : next();
      const expected = Number(refEvalIR(ir.expression, BigInt(x)));
      assert.equal(f(x), expected, `wasm p=${p} x=${x}`);
      assert.equal(executeVeilBytecode(vm, x), expected, `vm p=${p} x=${x}`);
    }
  }
});

test('every op and edge constant (incl. negative-as-signed LEB128) round-trips', () => {
  const edges = [0, 1, 63, 64, 127, 128, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff, 0x3fffffff, 0x40000000];
  for (const op of Object.keys(REF_BINARY)) for (const c of edges) {
    const ir = wrapIR({ op, left: { op: 'input' }, right: { op: 'const', value: c } });
    const f = instantiateVeilWasm(compileVeilIRToWasm(ir));
    for (const x of edges) assert.equal(f(x), Number(REF_BINARY[op](BigInt(x), BigInt(c))), `${op} ${x} ${c}`);
  }
  const notF = instantiateVeilWasm(compileVeilIRToWasm(wrapIR({ op: 'not', arg: { op: 'input' } })));
  assert.equal(notF(0), 0xffffffff); assert.equal(notF(0xffffffff), 0);
});

test('module bytes are deterministic, import-free and validated', () => {
  const ir = JSON.parse(readFileSync(new URL('../examples/veil-ir-score.json', import.meta.url), 'utf8'));
  const a = compileVeilIRToWasm(ir), b = compileVeilIRToWasm(structuredClone(ir));
  assert.equal(wasmDigest(a), wasmDigest(b));
  assert.ok(WebAssembly.validate(a));
  assert.deepEqual(WebAssembly.Module.imports(new WebAssembly.Module(a)), []);
  assert.throws(() => compileVeilIRToWasm({ ...ir, expression: { op: 'eval' } }), /Unsupported IR opcode/);
  assert.throws(() => instantiateVeilWasm(a)(-1), /uint32/);
  // A module that imports something is refused.
  const withImport = Uint8Array.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 2, 7, 1, 1, 0x6d, 1, 0x66, 0, 0]);
  assert.ok(WebAssembly.validate(withImport));
  assert.throws(() => instantiateVeilWasm(withImport), /must not import/);
});
