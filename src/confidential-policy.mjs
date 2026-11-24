import { createHmac, timingSafeEqual } from 'node:crypto';
import { sha256Canonical } from './veil-ir.mjs';

/**
 * Protection-mode policy engine (Track C, issue #21). RESEARCH PROTOTYPE — requires independent
 * security review. It decides which execution mode may run, and NEVER silently downgrades:
 *   - require 'confidential' -> 'confidential' only after full attestation verification, else DENY
 *   - require 'hardened'     -> 'software-hardened' (no confidentiality claim)
 *   - require 'none'         -> 'plain'
 * A policy engine is not a hardware boundary. With the mock verifier nothing is confidential.
 */
export const DENY = Object.freeze({
  MALFORMED_POLICY: 'MALFORMED_POLICY',
  CONTRADICTORY_POLICY: 'CONTRADICTORY_POLICY',
  UNSUPPORTED_ON_DEVICE: 'UNSUPPORTED_ON_DEVICE',
  MISSING_EVIDENCE: 'MISSING_EVIDENCE',
  MALFORMED_EVIDENCE: 'MALFORMED_EVIDENCE',
  UNKNOWN_PLATFORM: 'UNKNOWN_PLATFORM',
  UNTRUSTED_VERIFIER: 'UNTRUSTED_VERIFIER',
  VERIFIER_ERROR: 'VERIFIER_ERROR',
  VERIFICATION_FAILED: 'VERIFICATION_FAILED',
  NONCE_MISMATCH: 'NONCE_MISMATCH',
  STALE_EVIDENCE: 'STALE_EVIDENCE',
  FUTURE_EVIDENCE: 'FUTURE_EVIDENCE',
  UNTRUSTED_MEASUREMENT: 'UNTRUSTED_MEASUREMENT'
});
const REQUIRE = new Set(['confidential', 'hardened', 'none']);
const HEX64 = /^[0-9a-f]{64}$/;
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const plainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;

/** Validate a policy document. Throws { code } errors; returns a frozen normalized copy. */
export function validatePolicy(p) {
  const bad = (code, msg) => { const e = new Error(msg); e.code = code; throw e; };
  if (!plainObject(p) || p.schemaVersion !== 1) bad(DENY.MALFORMED_POLICY, 'policy must be a plain object with schemaVersion 1');
  for (const k of Object.keys(p)) if (!['schemaVersion', 'require', 'allowSoftwareFallback', 'attestation'].includes(k)) bad(DENY.MALFORMED_POLICY, `unknown policy field ${k}`);
  if (!REQUIRE.has(p.require)) bad(DENY.MALFORMED_POLICY, 'require must be confidential | hardened | none');
  if (own(p, 'allowSoftwareFallback') && typeof p.allowSoftwareFallback !== 'boolean') bad(DENY.MALFORMED_POLICY, 'allowSoftwareFallback must be boolean');
  if (p.require === 'confidential' && p.allowSoftwareFallback === true) bad(DENY.CONTRADICTORY_POLICY, 'a policy that requires confidentiality cannot allow software fallback');
  let attestation = null;
  if (p.require === 'confidential') {
    const a = p.attestation;
    if (!plainObject(a)) bad(DENY.MALFORMED_POLICY, 'confidential policies need an attestation section');
    for (const k of Object.keys(a)) if (!['platforms', 'trustedMeasurements', 'maxAgeSec'].includes(k)) bad(DENY.MALFORMED_POLICY, `unknown attestation field ${k}`);
    if (!Array.isArray(a.platforms) || !a.platforms.length || a.platforms.some(x => typeof x !== 'string' || !/^[a-z0-9-]{1,40}$/.test(x))) bad(DENY.MALFORMED_POLICY, 'attestation.platforms must list platform ids');
    if (!Array.isArray(a.trustedMeasurements) || !a.trustedMeasurements.length || a.trustedMeasurements.some(m => typeof m !== 'string' || !HEX64.test(m))) bad(DENY.MALFORMED_POLICY, 'attestation.trustedMeasurements must be non-empty lowercase sha256 hex');
    if (!Number.isSafeInteger(a.maxAgeSec) || a.maxAgeSec < 1 || a.maxAgeSec > 3600) bad(DENY.MALFORMED_POLICY, 'attestation.maxAgeSec must be in [1, 3600]');
    attestation = Object.freeze({ platforms: Object.freeze([...a.platforms]), trustedMeasurements: Object.freeze([...a.trustedMeasurements]), maxAgeSec: a.maxAgeSec });
  } else if (own(p, 'attestation')) bad(DENY.MALFORMED_POLICY, 'attestation is only meaningful when require is confidential');
  return Object.freeze({ schemaVersion: 1, require: p.require, allowSoftwareFallback: p.allowSoftwareFallback === true, attestation });
}

/**
 * Decide the mode. `verifiers` maps platform id -> { trusted: boolean, verify(evidence, { nonce }) }.
 * `device` is the host capability summary (e.g. from scripts/collect-hw-evidence.sh); `now` is seconds.
 * Returns { mode: 'confidential' | 'software-hardened' | 'plain' | 'deny', reason, audit }.
 */
export function decideProtectionMode({ policy, evidence, nonce, verifiers = {}, device = {}, now = Math.floor(Date.now() / 1000), allowUntrustedVerifiersForTesting = false }) {
  const audit = { schemaVersion: 1, at: now, policyDigest: null, evidenceDigest: null, decision: null, reason: null };
  const finish = (mode, reason, extra = {}) => { audit.decision = mode; audit.reason = reason; Object.assign(audit, extra); return Object.freeze({ mode, reason, audit: Object.freeze(audit) }); };
  let pol;
  try { pol = validatePolicy(policy); audit.policyDigest = sha256Canonical(pol); } catch (e) { return finish('deny', e.code ?? DENY.MALFORMED_POLICY); }
  if (pol.require === 'none') return finish('plain', 'POLICY_ALLOWS_PLAIN');
  if (pol.require === 'hardened') return finish('software-hardened', 'POLICY_REQUIRES_HARDENING_ONLY');
  // From here: confidentiality is required. Every failure is DENY; there is no fallback path.
  if (device && device.teeAvailable === false) return finish('deny', DENY.UNSUPPORTED_ON_DEVICE);
  if (evidence === undefined || evidence === null) return finish('deny', DENY.MISSING_EVIDENCE);
  if (!plainObject(evidence) || typeof evidence.platform !== 'string') return finish('deny', DENY.MALFORMED_EVIDENCE);
  try { audit.evidenceDigest = sha256Canonical({ platform: evidence.platform, measurement: evidence.measurement ?? null, issuedAt: evidence.issuedAt ?? null }); } catch { return finish('deny', DENY.MALFORMED_EVIDENCE); }
  if (!pol.attestation.platforms.includes(evidence.platform) || !own(verifiers, evidence.platform)) return finish('deny', DENY.UNKNOWN_PLATFORM);
  const verifier = verifiers[evidence.platform];
  if (verifier.trusted !== true && !allowUntrustedVerifiersForTesting) return finish('deny', DENY.UNTRUSTED_VERIFIER);
  if (typeof nonce !== 'string' || nonce.length < 32) return finish('deny', DENY.NONCE_MISMATCH);
  let result;
  try { result = verifier.verify(evidence, { nonce }); } catch { return finish('deny', DENY.VERIFIER_ERROR); }
  // Only an explicit `true` counts; truthy strings or objects do not.
  if (!plainObject(result) || result.ok !== true) return finish('deny', DENY.VERIFICATION_FAILED);
  if (result.nonce !== nonce) return finish('deny', DENY.NONCE_MISMATCH);
  if (!Number.isSafeInteger(result.issuedAt)) return finish('deny', DENY.MALFORMED_EVIDENCE);
  if (result.issuedAt > now + 5) return finish('deny', DENY.FUTURE_EVIDENCE);
  if (now - result.issuedAt > pol.attestation.maxAgeSec) return finish('deny', DENY.STALE_EVIDENCE);
  if (typeof result.measurement !== 'string' || !pol.attestation.trustedMeasurements.includes(result.measurement)) return finish('deny', DENY.UNTRUSTED_MEASUREMENT);
  return finish('confidential', 'ATTESTATION_VERIFIED', { platform: evidence.platform, measurement: result.measurement });
}

/**
 * MOCK verifier for tests ONLY. HMAC over (platform, measurement, nonce, issuedAt) with a test key.
 * `trusted: false`, so the engine rejects it unless the caller explicitly opts into testing.
 * This is NOT attestation: whoever holds the key (including host root) can forge evidence.
 */
export function createMockVerifier(key) {
  const mac = e => createHmac('sha256', key).update(`${e.platform}\n${e.measurement}\n${e.nonce}\n${e.issuedAt}`).digest('hex');
  return Object.freeze({
    trusted: false,
    sign: e => ({ ...e, signature: mac(e) }),
    verify(e, { nonce }) {
      if (typeof e.signature !== 'string' || !HEX64.test(e.signature) || typeof e.measurement !== 'string' || !Number.isSafeInteger(e.issuedAt)) return { ok: false };
      const ok = timingSafeEqual(Buffer.from(mac(e), 'hex'), Buffer.from(e.signature, 'hex'));
      return ok ? { ok: true, nonce: e.nonce, issuedAt: e.issuedAt, measurement: e.measurement } : { ok: false };
    }
  });
}

/** Map the read-only hardware evidence (scripts/collect-hw-evidence.sh key: value lines) to device capability. */
export function deviceCapabilityFromEvidence(text) {
  const kv = Object.fromEntries(String(text).split('\n').map(l => l.split(/:\s(.*)/s)).filter(p => p.length >= 2).map(([k, v]) => [k.trim(), v.trim()]));
  const present = k => kv[k] === 'present';
  const teeAvailable = present('cpuflag_sgx') || present('cpuflag_tdx_guest') || present('cpuflag_tdx_host_platform') || present('cpuflag_sev_snp');
  return { teeAvailable, secureBoot: /enabled/i.test(kv.secure_boot ?? ''), tpm2: kv.tpm_major === '2' };
}
