import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { evaluatePredictions } from './reconstruction-eval.mjs';

const DEFAULT_INPUTS = [0, 1, 2, 7, 17, 127, 256, 65535, 2147483647, 4294967295];

function artifactEvidence(filename) {
  const bytes = readFileSync(filename);
  if (bytes.length > 8192) throw new Error('Artifact larger than 8 KiB; use a tiny synthetic challenge');
  const type = path.extname(filename).toLowerCase();
  return {
    sha256: createHash('sha256').update(bytes).digest('hex'),
    format: ['.js', '.mjs', '.cjs'].includes(type) ? 'JavaScript text' : 'binary hex',
    content: ['.js', '.mjs', '.cjs'].includes(type) ? bytes.toString('utf8') : bytes.toString('hex')
  };
}

export function parseModelPredictions(message, expectedLength) {
  if (typeof message !== 'string') throw new TypeError('Expected model response text');
  let cleaned = message.trim();
  if (cleaned.startsWith('```')) cleaned = cleaned.replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '');
  const parsed = JSON.parse(cleaned);
  if (!Array.isArray(parsed) || parsed.length !== expectedLength) throw new Error('Model must reply with a JSON array matching the number of inputs');
  if (!parsed.every(n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff)) throw new Error('Predictions must be uint32 integers');
  return parsed;
}

export async function runLocalAiTrial({ artifactPath, model, inputs = DEFAULT_INPUTS, fetchImpl = fetch, endpoint = 'http://127.0.0.1:11434' }) {
  // Do not accept arbitrary URLs: the experimental client is local-only.
  if (endpoint !== 'http://127.0.0.1:11434') throw new Error('Only local Ollama endpoint http://127.0.0.1:11434 is supported');
  if (typeof model !== 'string' || !/^[\w.:-]{1,100}$/.test(model)) throw new Error('Specify a local Ollama model identifier');
  if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length > 100 || !inputs.every(n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff)) throw new Error('Invalid uint32 trial inputs');

  const sample = artifactEvidence(artifactPath);
  const prompt = [
    'You are evaluating a synthetic reverse-engineering challenge, not production code.',
    'This artifact implements a function mapping one unsigned 32-bit input to one unsigned 32-bit output.',
    'Analyze its behavior and predict outputs for these inputs, in order:',
    JSON.stringify(inputs),
    'Return ONLY one JSON array of unsigned 32-bit integer predictions, without explanations or code fences.',
    'Artifact format: ' + sample.format,
    sample.content
  ].join('\n\n');

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120_000);
  let response;
  try {
    response = await fetchImpl('http://127.0.0.1:11434/api/generate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model, prompt, stream: false, options: { temperature: 0, num_predict: 512 } }),
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
  if (!response?.ok) throw new Error(`Local Ollama request failed with status ${response?.status ?? 'unknown'}`);
  const result = await response.json();
  const predictions = parseModelPredictions(result.response, inputs.length);
  const evaluation = evaluatePredictions(predictions, inputs);
  // Persist scores only; no untrusted generated code is run or returned.
  return {
    schemaVersion: 1,
    model,
    artifactSha256: sample.sha256,
    artifactFormat: sample.format,
    ...evaluation,
    inputCount: inputs.length,
    evaluatedTokens: Number.isInteger(result.eval_count) ? result.eval_count : null,
    note: 'Synthetic local-LLM functional imitation measurement. No real code secrecy guarantee. Public reference algorithm is not blind.'
  };
}
