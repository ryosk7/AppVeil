import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { runRedLab } from '../src/red-lab-run.mjs';
import { localAiAttack, buildPrompt, parseIrReply } from '../src/red-lab-ai.mjs';
import { createTrial, destroyTrial } from '../src/red-lab-harness.mjs';
import { decompileBytecodeV1 } from '../src/red-lab-attacks.mjs';

// Fake local model: answers with the decompiled IR (a "perfect" model) or with a fixed reply.
function fakeModel({ reply, capture = [] } = {}) {
  return async (url, init) => {
    if (url.endsWith('/api/tags')) return { ok: true, json: async () => ({ models: [{ name: 'fake:1b', digest: 'sha256:fake', details: { quantization_level: 'Q4_K_M', parameter_size: '1B', family: 'fake' } }] }) };
    const body = JSON.parse(init.body);
    capture.push(body.prompt);
    let response = reply;
    if (!response) { const p = body.prompt, i = p.indexOf('\n', p.indexOf('Artifact format:')); const art = p.slice(i + 1); response = '```json\n' + JSON.stringify(decompileBytecodeV1(JSON.parse(art))) + '\n```'; }
    return { ok: true, json: async () => ({ response, eval_count: 100, prompt_eval_count: 400 }) };
  };
}

test('pipeline: a perfect fake model is judged exact; model metadata and token use are recorded', async () => {
  const r = await runRedLab({ attack: 'local-ai', trials: 5, size: 8, seed: 4, holdoutCount: 200, attackOptions: { model: 'fake:1b', fetchImpl: fakeModel() } });
  assert.equal(r.status, 'completed');
  assert.equal(r.summary.exactRecoveries, 5);
  assert.deepEqual(r.results[0].model, { model: 'fake:1b', digest: 'sha256:fake', quantization: 'Q4_K_M', parameterSize: '1B', family: 'fake' });
  assert.equal(r.results[0].used.tokens, 500);
  assert.match(r.results[0].trustAssumption, /not verified/);
});

test('the prompt contains only the attacker artifact, never reference or holdout data', async () => {
  const t = createTrial({ challengeSeed: 77, size: 8, holdoutCount: 100 });
  try {
    const capture = [];
    await localAiAttack(t.attackerDir, { model: 'fake:1b', fetchImpl: fakeModel({ capture }) });
    const ref = JSON.parse(readFileSync(path.join(t.judgeDir, 'reference.json'), 'utf8'));
    const holdout = JSON.parse(readFileSync(path.join(t.judgeDir, 'holdout.json'), 'utf8'));
    assert.equal(capture.length, 1);
    assert.ok(!capture[0].includes(JSON.stringify(ref.expression)), 'reference expression leaked into prompt');
    assert.ok(!capture[0].includes(t.manifest.challenge.referenceDigest));
    assert.ok(!capture[0].includes(holdout.slice(6, 12).join(',')));
    assert.equal(buildPrompt(t.attackerDir), capture[0]);
  } finally { destroyTrial(t); }
});

test('unavailable model => not-checked (never a failed attack); garbage replies score 0; endpoint is loopback-only', async () => {
  const down = async () => { throw new Error('ECONNREFUSED'); };
  const r = await runRedLab({ attack: 'local-ai', trials: 2, holdoutCount: 50, attackOptions: { model: 'fake:1b', fetchImpl: down } });
  assert.equal(r.status, 'not-checked'); assert.match(r.reason, /unreachable/); assert.equal(r.results, undefined);
  const missing = await runRedLab({ attack: 'local-ai', trials: 1, holdoutCount: 50, attackOptions: { model: 'other:7b', fetchImpl: fakeModel() } });
  assert.equal(missing.status, 'not-checked'); assert.match(missing.reason, /not installed/);
  const garbage = await runRedLab({ attack: 'local-ai', trials: 2, holdoutCount: 50, attackOptions: { model: 'fake:1b', fetchImpl: fakeModel({ reply: 'function f(x){return x}' }) } });
  assert.equal(garbage.summary.exactRecoveries, 0);
  assert.match(garbage.results[0].error, /unparseable model reply|no submission/);
  const code = await runRedLab({ attack: 'local-ai', trials: 1, holdoutCount: 50, attackOptions: { model: 'fake:1b', fetchImpl: fakeModel({ reply: '{"kind":"code","source":"process.exit(1)"}' }) } });
  assert.equal(code.summary.exactRecoveries, 0, 'a non-IR reply is never executed and scores 0');
  await assert.rejects(() => localAiAttack('/tmp', { model: 'fake:1b', endpoint: 'http://example.com:11434' }), /loopback/);
  assert.deepEqual(parseIrReply('Sure! ```json\n{"a":1}\n``` done'), { a: 1 });
});
