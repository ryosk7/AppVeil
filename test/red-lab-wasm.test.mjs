import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { runRedLab } from '../src/red-lab-run.mjs';
import { createTrial, destroyTrial, assertAttackerIsolation, createOracle } from '../src/red-lab-harness.mjs';
import { instrumentForTracing, parseSections } from '../src/red-lab-wasm-attacks.mjs';
import { compileVeilIRToWasm, instantiateVeilWasm } from '../src/veil-wasm.mjs';

test('Wasm defender trial ships only artifact.wasm and task.json, and stays isolated', () => {
  const t = createTrial({ challengeSeed: 12, size: 8, defender: 'veil-wasm-v1', holdoutCount: 100, budget: { queries: 4 } });
  try {
    assert.deepEqual(readdirSync(t.attackerDir).sort(), ['artifact.wasm', 'task.json']);
    assert.ok(WebAssembly.validate(readFileSync(path.join(t.attackerDir, 'artifact.wasm'))));
    assert.equal(assertAttackerIsolation(t), true);
    const o = createOracle(t);
    o(1); o(2); o(3); o(4);
    assert.throws(() => o(5), /budget exhausted/);
  } finally { destroyTrial(t); }
});

for (const attack of ['static-decompile', 'dynamic-trace']) {
  test(`${attack} recovers every Wasm challenge (expected defense failure)`, async () => {
    const r = await runRedLab({ attack, defender: 'veil-wasm-v1', trials: 20, size: 10, seed: 5, holdoutCount: 300 });
    assert.equal(r.summary.exactRecoveries, 20, JSON.stringify(r.results.find(x => !x.exactOnHoldout)));
    assert.equal(r.defender, 'veil-wasm-v1');
  });
}

test('instrumented module preserves behavior and adds exactly one trace import', () => {
  const ir = { schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression: { op: 'xor', left: { op: 'mul', left: { op: 'input' }, right: { op: 'const', value: 0x9e3779b9 } }, right: { op: 'const', value: 7 } } };
  const original = compileVeilIRToWasm(ir);
  const { bytes, instructions } = instrumentForTracing(Buffer.from(original));
  const mod = new WebAssembly.Module(bytes);
  assert.deepEqual(WebAssembly.Module.imports(mod), [{ module: 't', name: 'trace', kind: 'function' }]);
  const seen = [];
  const { f } = new WebAssembly.Instance(mod, { t: { trace: v => { seen.push(v >>> 0); return v; } } }).exports;
  const ref = instantiateVeilWasm(original);
  for (const x of [0, 1, 12345, 0xffffffff]) { seen.length = 0; assert.equal(f(x | 0) >>> 0, ref(x)); assert.equal(seen.length, instructions.length); }
  assert.throws(() => parseSections(Buffer.from('not wasm!')), /Not a Wasm v1 module/);
});

test('black-box results are identical across encodings (VM vs Wasm) for the same challenges', async () => {
  const vm = await runRedLab({ attack: 'blackbox-enum', defender: 'veil-vm-v1', trials: 10, size: 3, seed: 2, holdoutCount: 200, queries: 16 });
  const wasm = await runRedLab({ attack: 'blackbox-enum', defender: 'veil-wasm-v1', trials: 10, size: 3, seed: 2, holdoutCount: 200, queries: 16 });
  assert.deepEqual(vm.results.map(r => r.correct), wasm.results.map(r => r.correct));
});
