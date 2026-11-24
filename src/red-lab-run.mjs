import { createTrial, assertAttackerIsolation, judge, destroyTrial, summarize, createOracle } from './red-lab-harness.mjs';
import { blackBoxImitationAttack } from './red-lab-blackbox.mjs';
import { staticDecompileAttack, dynamicTraceAttack } from './red-lab-attacks.mjs';
import { wasmStaticDecompile, wasmInstrumentationAttack } from './red-lab-wasm-attacks.mjs';
import { localAiAttack } from './red-lab-ai.mjs';

/** Registered baseline attacks: name -> { attackClass, run(trial) -> { submission, used } }. */
export const ATTACKS = {
  // Each attack picks its method from the artifact it was given (attackers can see the file type).
  'static-decompile': { attackClass: 'static', run: trial => trial.manifest.defender === 'veil-wasm-v1' ? wasmStaticDecompile(trial.attackerDir) : staticDecompileAttack(trial.attackerDir) },
  'dynamic-trace': { attackClass: 'dynamic', run: trial => trial.manifest.defender === 'veil-wasm-v1' ? wasmInstrumentationAttack(trial.attackerDir) : dynamicTraceAttack(trial.attackerDir) },
  // Black-box: the attacker gets only the oracle (query budget from --queries), never the artifact.
  // AI: a local model gets only the artifact; options.model selects it; options.fetchImpl is for tests.
  'local-ai': { attackClass: 'ai', run: (trial, options) => localAiAttack(trial.attackerDir, options) },
  'blackbox-enum': { attackClass: 'black-box', run: trial => blackBoxImitationAttack(createOracle(trial), { queries: trial.manifest.budget.queries }) }
};

/** Run `trials` independent challenges for one attack and return per-trial results and a summary. */
export async function runRedLab({ attack, trials = 20, size = 8, seed = 1, holdoutCount = 1000, queries = 0, defender = 'veil-vm-v1', attackOptions = {} }) {
  const spec = ATTACKS[attack];
  if (!spec) throw new Error(`Unknown attack: ${attack} (available: ${Object.keys(ATTACKS).join(', ')})`);
  if (!Number.isSafeInteger(trials) || trials < 1 || trials > 10000) throw new TypeError('trials must be in [1, 10000]');
  const results = [];
  for (let i = 0; i < trials; i++) {
    const trial = createTrial({ challengeSeed: (seed + i * 0x9e3779b1) >>> 0, size, holdoutCount, defender, budget: { queries } });
    try {
      assertAttackerIsolation(trial);
      const out = await spec.run(trial, attackOptions);
      // A missing attacker resource (e.g. no local model) is NOT a failed attack: the run is not-checked.
      if (out.notChecked) return { schemaVersion: 1, attack, attackClass: spec.attackClass, defender, status: 'not-checked', reason: out.notChecked, params: { trials, size, seed, holdoutCount, queries } };
      const res = judge(trial, out.submission, { attackClass: spec.attackClass, attacker: attack, used: out.used });
      results.push(out.model ? { ...res, model: out.model, trustAssumption: 'local endpoint assumed not to forward data; not verified' } : res);
    } finally { destroyTrial(trial); }
  }
  return { schemaVersion: 1, attack, attackClass: spec.attackClass, defender, status: 'completed', params: { trials, size, seed, holdoutCount, queries }, summary: summarize(results), results };
}
