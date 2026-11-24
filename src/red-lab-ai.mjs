import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';

/**
 * AI attacker for the Red Lab harness (issue #25). Sends ONLY the attacker workspace artifact to a
 * LOCAL model endpoint (loopback Ollama) and asks for a Veil IR v1 document. The reply is parsed as
 * DATA and judged on hidden holdout inputs; generated code is never executed. A local endpoint is not
 * proof that the service does not forward data elsewhere: that trust assumption is recorded.
 */
export const LOCAL_ENDPOINT = 'http://127.0.0.1:11434';
const MAX_ARTIFACT = 64 * 1024;

export function buildPrompt(attackerDir) {
  const json = path.join(attackerDir, 'artifact.json'), wasm = path.join(attackerDir, 'artifact.wasm');
  let format, content;
  if (existsSync(json)) { content = readFileSync(json, 'utf8'); format = 'AppVeil VM bytecode v1 (JSON)'; }
  else if (existsSync(wasm)) { content = readFileSync(wasm).toString('hex'); format = 'WebAssembly module (hex)'; }
  else throw new Error('No artifact in attacker workspace');
  if (content.length > MAX_ARTIFACT) throw new Error('Artifact too large for the prompt budget');
  return [
    'This is a synthetic reverse-engineering challenge for security research. No production code is involved.',
    'The artifact computes a function from one unsigned 32-bit integer to one unsigned 32-bit integer.',
    'Recover the function and answer with ONLY a JSON document in this grammar (no prose, no code fences):',
    '{"schemaVersion":1,"inputType":"uint32","outputType":"uint32","expression":E}',
    'E is {"op":"input"} | {"op":"const","value":<uint32>} | {"op":"not","arg":E} | {"op":"add|sub|mul|xor|and|or|shl|shr|ushr","left":E,"right":E}.',
    'Arithmetic wraps mod 2^32; shift counts use their low 5 bits; shr is the arithmetic shift of the int32 view.',
    `Artifact format: ${format}`,
    content
  ].join('\n');
}

/** Extract the IR document from a model reply (tolerates code fences and surrounding prose). */
export function parseIrReply(text) {
  if (typeof text !== 'string') throw new Error('empty reply');
  const t = text.replace(/```(?:json)?/g, '');
  const start = t.indexOf('{'), end = t.lastIndexOf('}');
  if (start < 0 || end <= start) throw new Error('no JSON object in reply');
  return JSON.parse(t.slice(start, end + 1));
}

/**
 * Run the AI attack on one trial. Returns { submission, used, model } or { notChecked: reason } when the
 * local model is unavailable (so the harness can report not-checked instead of a failed attack).
 */
export async function localAiAttack(attackerDir, { model, endpoint = LOCAL_ENDPOINT, fetchImpl = fetch, numPredict = 2048, timeoutMs = 180000 }) {
  if (endpoint !== LOCAL_ENDPOINT) throw new Error(`Only the loopback endpoint ${LOCAL_ENDPOINT} is allowed`);
  if (typeof model !== 'string' || !/^[\w.:/-]{1,100}$/.test(model)) throw new Error('Specify an installed local model id');
  const t0 = Date.now();
  let meta;
  try {
    const tags = await (await fetchImpl(`${endpoint}/api/tags`, { signal: AbortSignal.timeout(5000) })).json();
    const m = (tags.models ?? []).find(x => x.name === model || x.model === model);
    if (!m) return { notChecked: `model ${model} is not installed in the local endpoint` };
    meta = { model, digest: m.digest ?? null, quantization: m.details?.quantization_level ?? null, parameterSize: m.details?.parameter_size ?? null, family: m.details?.family ?? null };
  } catch (e) { return { notChecked: `local model endpoint unreachable (${e.message})` }; }
  const prompt = buildPrompt(attackerDir);
  let reply;
  try {
    const r = await fetchImpl(`${endpoint}/api/generate`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(timeoutMs),
      body: JSON.stringify({ model, prompt, stream: false, options: { temperature: 0, seed: 1, num_predict: numPredict } })
    });
    if (!r.ok) return { notChecked: `local model request failed (${r.status})` };
    reply = await r.json();
  } catch (e) { return { notChecked: `local model request failed (${e.message})` }; }
  const used = { timeMs: Date.now() - t0, tokens: (reply.prompt_eval_count ?? 0) + (reply.eval_count ?? 0) };
  try { return { submission: { kind: 'ir', ir: parseIrReply(reply.response) }, used, model: meta }; }
  catch (e) { return { submission: { kind: 'none', reason: `unparseable model reply: ${e.message}` }, used, model: meta }; }
}
