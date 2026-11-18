import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseModelPredictions, runLocalAiTrial } from '../src/local-ai-trial.mjs';
import { oracle } from '../src/reconstruction-eval.mjs';

test('parses only bounded uint32 numeric predictions', () => {
  assert.deepEqual(parseModelPredictions('```json\n[0, 1]\n```', 2), [0, 1]);
  assert.throws(() => parseModelPredictions('[1, -1]', 2));
  assert.throws(() => parseModelPredictions('[1]', 2));
});
test('scores mocked local AI outputs, without external HTTP', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'appveil-ai-'));
  try {
    const file = path.join(dir, 'synthetic.js');
    writeFileSync(file, 'export function synthetic(x) {return x;}');
    const inputs = [0,1,17];
    const result = await runLocalAiTrial({
      artifactPath: file,
      model: 'test-synthetic',
      inputs,
      fetchImpl: async (url, request) => {
        assert.equal(url, 'http://127.0.0.1:11434/api/generate');
        assert.equal(JSON.parse(request.body).stream, false);
        return { ok: true, json: async () => ({response: JSON.stringify(inputs.map(oracle)), eval_count: 33}) };
      }
    });
    assert.equal(result.accuracy, 1);
    assert.equal(result.evaluatedTokens, 33);
    assert.ok(!('predictions' in result));
  } finally {rmSync(dir,{recursive:true,force:true});}
});
test('refuses non-loopback endpoints', async () => {
  await assert.rejects(runLocalAiTrial({artifactPath:'/not-used',model:'test',endpoint:'https://external.example'}), /Only local Ollama/);
});
