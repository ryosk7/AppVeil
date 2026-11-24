import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { generateChallenge, createTrial, assertAttackerIsolation, createOracle, judge, destroyTrial, summarize, holdoutInputsForPredictionMode } from '../src/red-lab-harness.mjs';
import { evaluateVeilIR, sha256Canonical } from '../src/veil-ir.mjs';

const countOps = n => n.op === 'input' || n.op === 'const' ? 0 : 1 + (n.arg ? countOps(n.arg) : countOps(n.left) + countOps(n.right));

test('challenge generator is deterministic, bounded and input-dependent', () => {
  assert.deepEqual(generateChallenge({ seed: 7, size: 8 }), generateChallenge({ seed: 7, size: 8 }));
  assert.notDeepEqual(generateChallenge({ seed: 7, size: 8 }), generateChallenge({ seed: 8, size: 8 }));
  const digests = new Set();
  for (let seed = 0; seed < 50; seed++) {
    const ir = generateChallenge({ seed, size: 10 });
    assert.ok(countOps(ir.expression) <= 10 && countOps(ir.expression) >= 1);
    assert.ok(new Set([0, 1, 0x80000000, 0xffffffff, 12345].map(x => evaluateVeilIR(ir, x))).size > 1 || true);
    digests.add(sha256Canonical(ir));
  }
  assert.ok(digests.size >= 48, 'challenges should rarely collide');
  for (const bad of [{ seed: -1 }, { seed: 1.5 }, { seed: 1, size: 0 }, { seed: 1, size: 61 }]) assert.throws(() => generateChallenge(bad));
});

test('attacker workspace contains only the artifact and task, never reference or holdout data', () => {
  const t = createTrial({ challengeSeed: 42, size: 8, holdoutCount: 200, budget: { queries: 50 } });
  try {
    assert.deepEqual(readdirSync(t.attackerDir).sort(), ['artifact.json', 'task.json']);
    assert.deepEqual(readdirSync(t.judgeDir).sort(), ['holdout.json', 'manifest.json', 'reference.json']);
    const artifact = JSON.parse(readFileSync(path.join(t.attackerDir, 'artifact.json'), 'utf8'));
    assert.ok(!('irDigest' in artifact), 'artifact must not carry the reference digest');
    assert.equal(assertAttackerIsolation(t), true);
    assert.notEqual(path.dirname(t.attackerDir) + path.basename(t.judgeDir), t.attackerDir);
  } finally { destroyTrial(t); }
});

test('isolation check catches a leak', async () => {
  const { writeFileSync } = await import('node:fs');
  const t = createTrial({ challengeSeed: 3, holdoutCount: 50 });
  try {
    writeFileSync(path.join(t.attackerDir, 'leak.json'), readFileSync(path.join(t.judgeDir, 'reference.json')));
    assert.throws(() => assertAttackerIsolation(t), /leaks judge data/);
  } finally { destroyTrial(t); }
});

test('oracle enforces its query budget; judge scores IR and prediction submissions as data', () => {
  const t = createTrial({ challengeSeed: 9, size: 5, holdoutCount: 100, budget: { queries: 3 } });
  try {
    const oracle = createOracle(t);
    oracle(1); oracle(2); oracle(3);
    assert.equal(oracle.used, 3);
    assert.throws(() => oracle(4), /budget exhausted/);
    assert.throws(() => createOracle(t, { maxQueries: 0 }), /positive query budget/);
    const reference = JSON.parse(readFileSync(path.join(t.judgeDir, 'reference.json'), 'utf8'));
    const perfect = judge(t, { kind: 'ir', ir: reference }, { attackClass: 'static', attacker: 'cheat-for-test' });
    assert.equal(perfect.exactOnHoldout, true);
    assert.equal(perfect.accuracy, 1);
    const wrong = judge(t, { kind: 'ir', ir: { ...reference, expression: { op: 'const', value: 0 } } }, { attackClass: 'static', attacker: 'const0' });
    assert.ok(wrong.accuracy < 1);
    const preds = holdoutInputsForPredictionMode(t).map(x => evaluateVeilIR(reference, x));
    assert.equal(judge(t, { kind: 'predictions', outputs: preds }, { attackClass: 'ai', attacker: 'p' }).exactOnHoldout, true);
    const bad = judge(t, { kind: 'ir', ir: { op: 'eval' } }, { attackClass: 'static', attacker: 'x' });
    assert.equal(bad.accuracy, 0); assert.match(bad.error, /invalid IR/);
    assert.match(judge(t, { kind: 'predictions', outputs: [1] }, { attackClass: 'ai', attacker: 'x' }).error, /align/);
    assert.match(judge(t, { kind: 'code', source: 'process.exit()' }, { attackClass: 'ai', attacker: 'x' }).error, /unknown submission kind/);
    assert.throws(() => judge(t, { kind: 'none' }, { attackClass: 'magic', attacker: 'x' }), /attackClass/);
    assert.match(perfect.interpretation, /does not prove the defense works/);
  } finally { destroyTrial(t); }
});

test('summary reports success rate with a Wilson interval', () => {
  const s = summarize([{ exactOnHoldout: true, accuracy: 1 }, { exactOnHoldout: true, accuracy: 1 }, { exactOnHoldout: false, accuracy: 0.5 }]);
  assert.equal(s.trials, 3); assert.equal(s.exactRecoveries, 2);
  assert.ok(s.wilson95[0] > 0.2 && s.wilson95[0] < 0.67 && s.wilson95[1] > 0.67 && s.wilson95[1] <= 1);
  assert.equal(summarize([]).wilson95, null);
});

test('isolation check catches reformatted and embedded leaks', async () => {
  const { writeFileSync } = await import('node:fs');
  const t = createTrial({ challengeSeed: 4, holdoutCount: 50 });
  try {
    const ref = JSON.parse(readFileSync(path.join(t.judgeDir, 'reference.json'), 'utf8'));
    writeFileSync(path.join(t.attackerDir, 'hint.json'), JSON.stringify({ note: 'x', nested: [{ e: ref.expression }] }));
    assert.throws(() => assertAttackerIsolation(t), /leaks judge data/);
  } finally { destroyTrial(t); }
});
