#!/usr/bin/env node
// Veil IR v1 resource-cost measurement: compile time, interpreter slowdown vs. plain JS, heap delta.
// Measures COST ONLY. It says nothing about confidentiality or reverse-engineering resistance.
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import os from 'node:os';
import { compileVeilIR, runVeilBytecode, evaluateVeilIR, loadVeilBytecode, executeVeilBytecode, sha256Canonical } from '../src/veil-ir.mjs';
import { oracle } from '../src/reconstruction-eval.mjs';

const N = Number(process.argv[2] ?? 200000);
if (!Number.isSafeInteger(N) || N < 1000 || N > 10_000_000) throw new Error('iterations must be an integer in [1000, 10000000]');
const ir = JSON.parse(readFileSync(new URL('../examples/veil-ir-score.json', import.meta.url), 'utf8'));
const inputs = new Uint32Array(N);
let x = 0x12345678;
for (let i = 0; i < N; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; inputs[i] = x >>> 0; }

function time(fn) {
  for (let i = 0; i < 3; i++) fn(); // warm-up
  const samples = [];
  for (let r = 0; r < 7; r++) { const t = process.hrtime.bigint(); fn(); samples.push(Number(process.hrtime.bigint() - t) / 1e6); }
  samples.sort((a, b) => a - b);
  return samples[3]; // median ms
}
let sink = 0;
const program = compileVeilIR(ir, { seed: 42 });
const compileMs = time(() => { for (let i = 0; i < 1000; i++) compileVeilIR(ir, { seed: i }); }) / 1000;
const jsMs = time(() => { for (let i = 0; i < N; i++) sink ^= oracle(inputs[i]); });
const irMs = time(() => { for (let i = 0; i < N; i++) sink ^= evaluateVeilIR(ir, inputs[i]); });
const vmMs = time(() => { for (let i = 0; i < N; i++) sink ^= runVeilBytecode(program, inputs[i]); });
const loaded = loadVeilBytecode(program);
const loadMs = time(() => { for (let i = 0; i < 1000; i++) loadVeilBytecode(program); }) / 1000;
const vmLoadedMs = time(() => { for (let i = 0; i < N; i++) sink ^= executeVeilBytecode(loaded, inputs[i]); });
for (let i = 0; i < 1000; i++) if (executeVeilBytecode(loaded, inputs[i]) !== oracle(inputs[i])) throw new Error('VM mismatch; refusing to report timings');
global.gc?.();
const before = process.memoryUsage().heapUsed;
for (let i = 0; i < N; i++) sink ^= executeVeilBytecode(loaded, inputs[i]);
const heapDeltaKiB = Math.round((process.memoryUsage().heapUsed - before) / 1024);

let commit = 'unknown';
try { commit = execSync('git rev-parse HEAD', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch {}
console.log(JSON.stringify({
  schemaVersion: 1,
  note: 'Resource cost only. NOT evidence of confidentiality or AI/reverse-engineering resistance.',
  commit, node: process.version, platform: `${os.platform()} ${os.release()} ${os.arch()}`, cpu: os.cpus()[0]?.model,
  irDigest: sha256Canonical(ir), bytecodeDigest: sha256Canonical(program), bytecodeBytes: JSON.stringify(program).length,
  iterations: N,
  compileMsPerProgram: +compileMs.toFixed(4),
  loadMsPerProgram: +loadMs.toFixed(4),
  medianMs: { plainJs: +jsMs.toFixed(2), irEvaluator: +irMs.toFixed(2), vmVerifyEachCall: +vmMs.toFixed(2), vmLoadOnce: +vmLoadedMs.toFixed(2) },
  nsPerCall: { plainJs: +(jsMs * 1e6 / N).toFixed(1), irEvaluator: +(irMs * 1e6 / N).toFixed(1), vmVerifyEachCall: +(vmMs * 1e6 / N).toFixed(1), vmLoadOnce: +(vmLoadedMs * 1e6 / N).toFixed(1) },
  slowdownVsPlainJs: { irEvaluator: +(irMs / jsMs).toFixed(1), vmVerifyEachCall: +(vmMs / jsMs).toFixed(1), vmLoadOnce: +(vmLoadedMs / jsMs).toFixed(1) },
  heapDeltaKiBAfterLoadOnceVmRun: heapDeltaKiB, gcExposed: typeof global.gc === 'function',
  sink: sink >>> 0
}, null, 2));
