import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { compileVeilIR, validateVeilIR, evaluateVeilIR, loadVeilBytecode, executeVeilBytecode, sha256Canonical } from './veil-ir.mjs';
import { compileVeilIRToWasm, instantiateVeilWasm, wasmDigest } from './veil-wasm.mjs';

/**
 * Red Lab harness (research). Attackers receive only a defender artifact (or a query-limited oracle)
 * and a budget; they submit DATA (output predictions or a candidate IR), never code. The judge keeps
 * the reference program and holdout inputs in a separate directory tree the attacker never receives.
 * Results are empirical, bounded by attacker skill and budget, and are not security proofs.
 */
export const RESULT_SCHEMA_VERSION = 1;
export const ATTACK_CLASSES = Object.freeze(['static', 'dynamic', 'black-box', 'ai']);
export const DEFENDERS = Object.freeze(['veil-vm-v1', 'veil-wasm-v1']);
/** File name of the artifact the attacker receives, per defender. */
export const ARTIFACT_FILE = Object.freeze({ 'veil-vm-v1': 'artifact.json', 'veil-wasm-v1': 'artifact.wasm' });

// Challenge generation is deliberately independent of the compiler and of test helpers:
// its own PRNG (splitmix32) and grammar, so defenders cannot shape the challenge distribution.
function splitmix32(seed) {
  let s = seed >>> 0;
  const next = () => {
    s = (s + 0x9e3779b9) >>> 0;
    let z = s;
    z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
    z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
    return (z ^ (z >>> 16)) >>> 0;
  };
  next.below = n => next() % n;
  return next;
}
const CHALLENGE_BINARY = ['add', 'sub', 'xor', 'and', 'or', 'mul', 'shl', 'shr', 'ushr'];

/** Generate a challenge IR with at most `size` operator nodes (difficulty), deterministic in `seed`. */
export function generateChallenge({ seed, size = 6 }) {
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) throw new TypeError('seed must be uint32');
  if (!Number.isSafeInteger(size) || size < 1 || size > 60) throw new TypeError('size must be an integer in [1, 60]');
  const next = splitmix32(seed);
  const leaf = () => (next.below(3) === 0 ? { op: 'const', value: next.below(4) === 0 ? next.below(32) : next() } : { op: 'input' });
  function build(ops) {
    if (ops === 0) return leaf();
    if (next.below(6) === 0) return { op: 'not', arg: build(ops - 1) };
    const op = CHALLENGE_BINARY[next.below(CHALLENGE_BINARY.length)];
    const left = next.below(ops);
    // Shift amounts are usually small constants, as in real code.
    const right = /sh/.test(op) && next.below(2) === 0 ? { op: 'const', value: 1 + next.below(31) } : build(ops - 1 - left);
    return { op, left: build(left), right };
  }
  // Ensure the function actually depends on its input.
  for (let attempt = 0; attempt < 64; attempt++) {
    const ir = { schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression: build(size) };
    validateVeilIR(ir);
    const probe = [0, 1, 0x80000000, 0xffffffff, next(), next()].map(x => evaluateVeilIR(ir, x));
    if (new Set(probe).size > 1) return ir;
  }
  throw new Error('Could not generate an input-dependent challenge');
}

function writeJson(file, value) { writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 }); }
const listFiles = dir => readdirSync(dir, { recursive: true, withFileTypes: true }).filter(e => e.isFile()).map(e => path.join(e.parentPath ?? e.path, e.name));

/**
 * Create a trial. Returns { attackerDir, judgeDir, manifest }. The two directories are siblings under
 * separate mkdtemp roots; only attackerDir is handed to an attacker.
 */
export function createTrial({ challengeSeed, size = 6, defender = 'veil-vm-v1', defenderSeed, holdoutCount = 1000, holdoutSeed, budget = {} }) {
  if (!DEFENDERS.includes(defender)) throw new Error(`Unknown defender: ${defender}`);
  if (!Number.isSafeInteger(holdoutCount) || holdoutCount < 10 || holdoutCount > 100000) throw new TypeError('holdoutCount must be in [10, 100000]');
  const reference = generateChallenge({ seed: challengeSeed, size });
  const dSeed = defenderSeed ?? splitmix32(challengeSeed ^ 0xa5a5a5a5)();
  // The artifact handed to the attacker carries no digest of the reference IR.
  let shipped, artifactDigest;
  if (defender === 'veil-vm-v1') {
    const { irDigest, ...bc } = compileVeilIR(reference, { seed: dSeed });
    shipped = bc; artifactDigest = sha256Canonical(bc);
  } else {
    shipped = compileVeilIRToWasm(reference); artifactDigest = wasmDigest(shipped);
  }
  const hNext = splitmix32(holdoutSeed ?? (challengeSeed ^ 0x5eed5eed));
  const holdout = Array.from({ length: holdoutCount }, (_, i) => (i < 6 ? [0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff][i] : hNext()));
  const attackerDir = mkdtempSync(path.join(tmpdir(), 'appveil-redlab-attacker-'));
  const judgeDir = mkdtempSync(path.join(tmpdir(), 'appveil-redlab-judge-'));
  const manifest = {
    schemaVersion: RESULT_SCHEMA_VERSION,
    defender,
    challenge: { seed: challengeSeed, size, referenceDigest: sha256Canonical(reference) },
    artifactFile: ARTIFACT_FILE[defender],
    artifactDigest,
    holdout: { count: holdoutCount, digest: sha256Canonical(holdout) },
    budget: { queries: budget.queries ?? 0, timeMs: budget.timeMs ?? 60000, tokens: budget.tokens ?? 0 }
  };
  if (defender === 'veil-vm-v1') writeJson(path.join(attackerDir, ARTIFACT_FILE[defender]), shipped);
  else writeFileSync(path.join(attackerDir, ARTIFACT_FILE[defender]), shipped, { mode: 0o600 });
  writeJson(path.join(attackerDir, 'task.json'), {
    schemaVersion: 1,
    task: `Recover the function computed by ${ARTIFACT_FILE[defender]} (uint32 -> uint32). Submit a Veil IR v1 document or output predictions. Do not submit code.`,
    defender, budget: manifest.budget
  });
  writeJson(path.join(judgeDir, 'reference.json'), reference);
  writeJson(path.join(judgeDir, 'holdout.json'), holdout);
  writeJson(path.join(judgeDir, 'manifest.json'), manifest);
  return { attackerDir, judgeDir, manifest };
}

/** Assert that nothing in the attacker workspace reveals the reference program or holdout data. */
export function assertAttackerIsolation(trial) {
  const reference = JSON.parse(readFileSync(path.join(trial.judgeDir, 'reference.json'), 'utf8'));
  const holdout = JSON.parse(readFileSync(path.join(trial.judgeDir, 'holdout.json'), 'utf8'));
  // Compare in canonical form so re-formatting or key reordering does not hide a leak.
  const refExpr = sha256Canonical(reference.expression);
  const textSecrets = [trial.manifest.challenge.referenceDigest, trial.manifest.holdout.digest, holdout.slice(6, 16).join(',')];
  const containsReference = v => {
    if (v && typeof v === 'object') {
      if (!Array.isArray(v) && typeof v.op === 'string') { try { if (sha256Canonical(v) === refExpr) return true; } catch { /* non-JSON value */ } }
      return Object.values(v).some(containsReference);
    }
    return false;
  };
  for (const file of listFiles(trial.attackerDir)) {
    const text = readFileSync(file, 'utf8');
    const compact = text.replace(/\s+/g, '');
    for (const s of textSecrets) if (text.includes(s) || compact.includes(s.replace(/\s+/g, ''))) throw new Error(`Attacker workspace leaks judge data in ${path.basename(file)}`);
    let parsed;
    try { parsed = JSON.parse(text); } catch { continue; }
    if (containsReference(parsed)) throw new Error(`Attacker workspace leaks judge data in ${path.basename(file)}`);
  }
  if (path.relative(trial.attackerDir, trial.judgeDir).split(path.sep)[0] !== '..') throw new Error('Judge directory is reachable from the attacker workspace');
  return true;
}

/**
 * Black-box oracle over the defender artifact with a hard query budget. The attacker gets this
 * function, not the artifact. Inputs are validated; exceeding the budget throws.
 */
export function createOracle(trial, { maxQueries } = {}) {
  const limit = maxQueries ?? trial.manifest.budget.queries;
  if (!Number.isSafeInteger(limit) || limit < 1) throw new TypeError('Oracle requires a positive query budget');
  const file = path.join(trial.attackerDir, ARTIFACT_FILE[trial.manifest.defender]);
  let run;
  if (trial.manifest.defender === 'veil-vm-v1') { const handle = loadVeilBytecode(JSON.parse(readFileSync(file, 'utf8'))); run = x => executeVeilBytecode(handle, x); }
  else run = instantiateVeilWasm(readFileSync(file));
  let used = 0;
  const oracle = x => {
    if (used >= limit) throw new Error('Oracle query budget exhausted');
    used++;
    return run(x);
  };
  Object.defineProperty(oracle, 'used', { get: () => used });
  return oracle;
}

/**
 * Judge a submission: { kind: 'ir', ir } or { kind: 'predictions', outputs: number[] } (aligned with
 * holdout order, only obtainable via `holdoutInputsForPredictionMode`). Submissions are data and are
 * never executed as code. Returns a schemaVersion 1 result.
 */
export function judge(trial, submission, { attackClass, attacker, used = {} } = {}) {
  if (!ATTACK_CLASSES.includes(attackClass)) throw new Error(`attackClass must be one of ${ATTACK_CLASSES.join(', ')}`);
  if (typeof attacker !== 'string' || !attacker) throw new Error('attacker name required');
  const reference = JSON.parse(readFileSync(path.join(trial.judgeDir, 'reference.json'), 'utf8'));
  const holdout = JSON.parse(readFileSync(path.join(trial.judgeDir, 'holdout.json'), 'utf8'));
  let predict, submissionKind = submission?.kind, error = null;
  if (submissionKind === 'ir') {
    try { validateVeilIR(submission.ir); predict = x => evaluateVeilIR(submission.ir, x); }
    catch (e) { error = `invalid IR submission: ${e.message}`; }
  } else if (submissionKind === 'predictions') {
    const out = submission.outputs;
    if (!Array.isArray(out) || out.length !== holdout.length) error = 'predictions must align with every holdout input';
    else predict = (_, i) => out[i];
  } else if (submissionKind === 'none') {
    error = submission.reason ? `no submission: ${String(submission.reason).slice(0, 200)}` : 'no submission';
  } else error = 'unknown submission kind';
  let correct = 0;
  if (predict) holdout.forEach((x, i) => { if (predict(x, i) === evaluateVeilIR(reference, x)) correct++; });
  return {
    schemaVersion: RESULT_SCHEMA_VERSION,
    attackClass, attacker, defender: trial.manifest.defender,
    challenge: trial.manifest.challenge, artifactDigest: trial.manifest.artifactDigest,
    budget: trial.manifest.budget,
    used: { queries: used.queries ?? 0, timeMs: used.timeMs ?? null, tokens: used.tokens ?? 0 },
    holdout: { count: holdout.length, digest: trial.manifest.holdout.digest },
    submission: submissionKind ?? 'invalid',
    correct, accuracy: correct / holdout.length,
    exactOnHoldout: correct === holdout.length,
    error,
    interpretation: 'Empirical result for this attacker, budget and challenge only. Success shows the defense failed for this setting; failure does not prove the defense works.'
  };
}

/** Prediction-mode inputs (released only after the attacker's artifact phase ends). */
export function holdoutInputsForPredictionMode(trial) {
  return JSON.parse(readFileSync(path.join(trial.judgeDir, 'holdout.json'), 'utf8'));
}

export function destroyTrial(trial) {
  rmSync(trial.attackerDir, { recursive: true, force: true });
  rmSync(trial.judgeDir, { recursive: true, force: true });
}

/** Aggregate results: success rate with a Wilson 95% interval. */
export function summarize(results) {
  const n = results.length, k = results.filter(r => r.exactOnHoldout).length;
  const z = 1.96, p = n ? k / n : 0;
  const denom = 1 + z * z / n, centre = (p + z * z / (2 * n)) / denom, half = n ? (z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom : 0;
  return {
    trials: n, exactRecoveries: k, successRate: p,
    wilson95: n ? [Math.max(0, centre - half), Math.min(1, centre + half)].map(v => Math.round(v * 1e6) / 1e6) : null,
    meanAccuracy: n ? results.reduce((s, r) => s + r.accuracy, 0) / n : 0
  };
}

