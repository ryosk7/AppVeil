import { createTrial, assertAttackerIsolation, judge, destroyTrial, summarize } from './red-lab-harness.mjs';
import { staticDecompileAttack, dynamicTraceAttack } from './red-lab-attacks.mjs';

/** Registered baseline attacks: name -> { attackClass, run(trial) -> { submission, used } }. */
export const ATTACKS = {
  'static-decompile': { attackClass: 'static', run: trial => staticDecompileAttack(trial.attackerDir) },
  'dynamic-trace': { attackClass: 'dynamic', run: trial => dynamicTraceAttack(trial.attackerDir) }
};

/** Run `trials` independent challenges for one attack and return per-trial results and a summary. */
export async function runRedLab({ attack, trials = 20, size = 8, seed = 1, holdoutCount = 1000, queries = 0 }) {
  const spec = ATTACKS[attack];
  if (!spec) throw new Error(`Unknown attack: ${attack} (available: ${Object.keys(ATTACKS).join(', ')})`);
  if (!Number.isSafeInteger(trials) || trials < 1 || trials > 10000) throw new TypeError('trials must be in [1, 10000]');
  const results = [];
  for (let i = 0; i < trials; i++) {
    const trial = createTrial({ challengeSeed: (seed + i * 0x9e3779b1) >>> 0, size, holdoutCount, budget: { queries } });
    try {
      assertAttackerIsolation(trial);
      const { submission, used } = await spec.run(trial);
      results.push(judge(trial, submission, { attackClass: spec.attackClass, attacker: attack, used }));
    } finally { destroyTrial(trial); }
  }
  return { schemaVersion: 1, attack, attackClass: spec.attackClass, defender: 'veil-vm-v1', params: { trials, size, seed, holdoutCount, queries }, summary: summarize(results), results };
}
