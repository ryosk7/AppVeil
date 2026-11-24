import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runRedLab } from '../src/red-lab-run.mjs';
import { reconstructFromTraces } from '../src/red-lab-attacks.mjs';

test('dynamic tracing via the V8 inspector recovers every challenge (expected defense failure)', async () => {
  const r = await runRedLab({ attack: 'dynamic-trace', trials: 20, size: 10, seed: 3, holdoutCount: 300 });
  assert.equal(r.summary.exactRecoveries, 20, JSON.stringify(r.results.find(x => !x.exactOnHoldout)));
  for (const res of r.results) { assert.equal(res.attackClass, 'dynamic'); assert.ok(res.used.queries > 0); }
});

test('dynamic attacker infers operations from values only and never reads the opcode table', () => {
  const src = readFileSync(new URL('../src/red-lab-attacks.mjs', import.meta.url), 'utf8');
  const body = src.slice(src.indexOf('export async function dynamicTraceAttack'));
  assert.ok(!/\.opcodes\b|instructions/.test(body), 'dynamic attack must not consult the bytecode format');
  // Synthetic trace: step0 = input, step1 = const 5, step2 = sub(step0, step1); ret = 2.
  const traces = [3, 10, 0xffffffff, 0].map(input => ({ input, steps: [[0, 0, 0], [1, 5, 0], [2, 0, 1]], regs: [input, 5, (input - 5) >>> 0], ret: 2 }));
  assert.deepEqual(reconstructFromTraces(traces).expression, { op: 'sub', left: { op: 'input' }, right: { op: 'const', value: 5 } });
  assert.throws(() => reconstructFromTraces([]), /Inconsistent/);
  const nonsense = [1, 2, 3].map(input => ({ input, steps: [[0, 0, 0], [1, 0, 0]], regs: [input, (input * 7919 + 13) % 1000], ret: 1 }));
  assert.throws(() => reconstructFromTraces(nonsense), /Could not infer/);
});
