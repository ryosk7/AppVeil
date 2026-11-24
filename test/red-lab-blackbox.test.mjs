import test from 'node:test';
import assert from 'node:assert/strict';
import { solveConstant, blackBoxImitationAttack } from '../src/red-lab-blackbox.mjs';
import { runRedLab } from '../src/red-lab-run.mjs';
import { createTrial, createOracle, destroyTrial } from '../src/red-lab-harness.mjs';

test('constant solver recovers t op c for random 32-bit constants', () => {
  const t = [3, 10, 0x80000000, 0xffffffff, 12345678];
  const c = 0x9e3779b9;
  const cases = { add: v => (v + c) >>> 0, xor: v => (v ^ c) >>> 0, sub: v => (v - c) >>> 0, mul: v => Math.imul(v, c) >>> 0 };
  const apply = (sol, v) => {
    const f = { add: (a, b) => a + b, sub: (a, b) => a - b, xor: (a, b) => a ^ b, mul: Math.imul, and: (a, b) => a & b, or: (a, b) => a | b }[sol.op];
    return (sol.constLeft ? f(sol.c, v) : f(v, sol.c)) >>> 0;
  };
  for (const [op, f] of Object.entries(cases)) {
    const Y = t.map(f);
    const sol = solveConstant(t, Y);
    assert.ok(sol, op);
    // Any semantically equivalent solution is acceptable (e.g. t - c == t + (-c)).
    assert.deepEqual(t.map(v => apply(sol, v)), Y, op);
  }
  const rev = t.map(v => (c - v) >>> 0);
  assert.deepEqual(t.map(v => apply(solveConstant(t, rev), v)), rev);
  assert.equal(solveConstant([1, 2, 3], [7, 7, 9]), null);
});

test('black-box attacker uses only the oracle and respects the query budget', () => {
  const trial = createTrial({ challengeSeed: 5, size: 2, holdoutCount: 50, budget: { queries: 16 } });
  try {
    const oracle = createOracle(trial);
    const { used } = blackBoxImitationAttack(oracle, { queries: 16, timeMs: 500 });
    assert.equal(oracle.used, 16);
    assert.equal(used.queries, 16);
    assert.throws(() => blackBoxImitationAttack(createOracle(trial, { maxQueries: 4 }), { queries: 16 }), /budget exhausted/);
  } finally { destroyTrial(trial); }
});

test('small challenges are imitated; results are judged on hidden holdout inputs', async () => {
  const r = await runRedLab({ attack: 'blackbox-enum', trials: 10, size: 1, seed: 1, holdoutCount: 300, queries: 16 });
  assert.ok(r.summary.exactRecoveries >= 8, JSON.stringify(r.summary));
  for (const res of r.results) assert.equal(res.attackClass, 'black-box');
});
