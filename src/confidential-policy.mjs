import { createHmac, timingSafeEqual } from 'node:crypto';
import { sha256Canonical } from './veil-ir.mjs';

/**
 * Protection-mode policy engine (Track C, issue #21). RESEARCH PROTOTYPE.
 * It decides which execution mode may run and NEVER silently downgrades:
 *   - require 'confidential' -> 'confidential' only after full attestation verification by a
 *     REGISTERED trusted verifier; 'confidential-test' only with the mock verifier and an explicit
 *     test flag; otherwise DENY
 *   - require 'hardened'     -> 'software-hardened' (no confidentiality claim)
 *   - require 'none'         -> 'plain'
 * All inputs are snapshotted ONCE into inert, null-prototype data before any check (no getters,
 * Proxies, prototype pollution or check-then-use races). Every internal error becomes DENY.
 * A policy engine is not a hardware boundary. With the mock verifier nothing is confidential.
 */
export const DENY = Object.freeze({
  MALFORMED_POLICY: 'MALFORMED_POLICY',
  CONTRADICTORY_POLICY: 'CONTRADICTORY_POLICY',
  MALFORMED_TIME: 'MALFORMED_TIME',
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
  UNTRUSTED_MEASUREMENT: 'UNTRUSTED_MEASUREMENT',
  INTERNAL_ERROR: 'INTERNAL_ERROR'
});
const REQUIRE = new Set(['confidential', 'hardened', 'none']);
const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{32,128}$/; // >= 128 bits, lowercase hex
const PLATFORM = /^[a-z0-9-]{1,40}$/;
const MAX_DATA = 64 * 1024;

/**
 * Snapshot arbitrary input into inert data: JSON round trip (each getter/Proxy trap runs at most once,
 * functions and symbols are dropped), revived into null-prototype objects and frozen. Throws on
 * cycles, BigInt or oversized input.
 */
function snapshot(value) {
  const text = JSON.stringify(value);
  if (text === undefined) return undefined;
  if (text.length > MAX_DATA) throw new Error('input too large');
  return JSON.parse(text, (_k, v) => {
    if (v && typeof v === 'object') return Object.freeze(Array.isArray(v) ? v : Object.assign(Object.create(null), v));
    return v;
  });
}
const isRecord = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const denseStrings = (a, re) => Array.isArray(a) && a.length > 0 && a.length <= 256 && a.every((x, i) => i in a && typeof x === 'string' && re.test(x));
class PolicyError extends Error { constructor(code, msg) { super(msg); this.code = code; } }

/** Validate a policy document (snapshotted first). Returns a frozen normalized copy or throws PolicyError. */
export function validatePolicy(input) {
  const bad = (code, msg) => { throw new PolicyError(code, msg); };
  let p;
  try { p = snapshot(input); } catch { bad(DENY.MALFORMED_POLICY, 'policy is not plain JSON data'); }
  if (!isRecord(p) || p.schemaVersion !== 1) bad(DENY.MALFORMED_POLICY, 'policy must be an object with schemaVersion 1');
  for (const k of Object.keys(p)) if (!['schemaVersion', 'require', 'allowSoftwareFallback', 'attestation'].includes(k)) bad(DENY.MALFORMED_POLICY, `unknown policy field ${k}`);
  if (!has(p, 'require') || !REQUIRE.has(p.require)) bad(DENY.MALFORMED_POLICY, 'require must be confidential | hardened | none');
  if (has(p, 'allowSoftwareFallback') && typeof p.allowSoftwareFallback !== 'boolean') bad(DENY.MALFORMED_POLICY, 'allowSoftwareFallback must be boolean');
  const fallback = has(p, 'allowSoftwareFallback') && p.allowSoftwareFallback === true;
  if (p.require === 'confidential' && fallback) bad(DENY.CONTRADICTORY_POLICY, 'a policy that requires confidentiality cannot allow software fallback');
  let attestation = null;
  if (p.require === 'confidential') {
    const a = has(p, 'attestation') ? p.attestation : undefined;
    if (!isRecord(a)) bad(DENY.MALFORMED_POLICY, 'confidential policies need an attestation section');
    for (const k of Object.keys(a)) if (!['platforms', 'trustedMeasurements', 'maxAgeSec'].includes(k)) bad(DENY.MALFORMED_POLICY, `unknown attestation field ${k}`);
    if (!has(a, 'platforms') || !denseStrings(a.platforms, PLATFORM)) bad(DENY.MALFORMED_POLICY, 'attestation.platforms must list platform ids');
    if (!has(a, 'trustedMeasurements') || !denseStrings(a.trustedMeasurements, HEX64)) bad(DENY.MALFORMED_POLICY, 'attestation.trustedMeasurements must be non-empty lowercase sha256 hex');
    if (!has(a, 'maxAgeSec') || !Number.isSafeInteger(a.maxAgeSec) || a.maxAgeSec < 1 || a.maxAgeSec > 3600) bad(DENY.MALFORMED_POLICY, 'attestation.maxAgeSec must be in [1, 3600]');
    attestation = Object.freeze({ platforms: Object.freeze([...a.platforms]), trustedMeasurements: Object.freeze([...a.trustedMeasurements]), maxAgeSec: a.maxAgeSec });
  } else if (has(p, 'attestation')) bad(DENY.MALFORMED_POLICY, 'attestation is only meaningful when require is confidential');
  return Object.freeze({ schemaVersion: 1, require: p.require, allowSoftwareFallback: fallback, attestation });
}

// Trust is not a self-declared property: only verifiers registered here (module-private) are trusted,
// and mock verifiers live in a separate set that can never yield 'confidential'.
const TRUSTED = new WeakMap(); // handle -> { id, verify }
const MOCK = new WeakMap();
/** Register a real verifier implementation. Returns an opaque handle to place in the verifier map. */
export function registerTrustedVerifier(id, verify) {
  if (typeof id !== 'string' || !PLATFORM.test(id) || typeof verify !== 'function') throw new TypeError('registerTrustedVerifier(id, verify)');
  const handle = Object.freeze({ kind: 'appveil-verifier', id });
  TRUSTED.set(handle, { id, verify });
  return handle;
}

/**
 * Decide the mode. `verifiers` maps platform id -> handle from registerTrustedVerifier or
 * createMockVerifier. `now` (seconds) is for tests; production should omit it.
 * Returns { mode: 'confidential' | 'confidential-test' | 'software-hardened' | 'plain' | 'deny', reason, audit }.
 * Synchronous verifiers only; a verifier returning a Promise is denied (VERIFICATION_FAILED).
 * Callers must treat any exception as DENY (none should escape; see INTERNAL_ERROR).
 */
export function decideProtectionMode(args) {
  const audit = Object.create(null);
  Object.assign(audit, { schemaVersion: 1, at: null, policyDigest: null, evidenceDigest: null, verifier: null, testing: false, decision: null, reason: null });
  const finish = (mode, reason, extra = {}) => { Object.assign(audit, extra, { decision: mode, reason }); return Object.freeze({ mode, reason, audit: Object.freeze(audit) }); };
  try {
    if (!isRecord(args)) return finish('deny', DENY.INTERNAL_ERROR);
    // Read each top-level argument exactly once.
    const policyIn = args.policy, evidenceIn = args.evidence, nonce = args.nonce, verifiers = args.verifiers, deviceIn = args.device, nowIn = args.now;
    const testing = args.allowMockVerifierForTesting === true;
    const now = nowIn === undefined ? Math.floor(Date.now() / 1000) : nowIn;
    if (!Number.isSafeInteger(now) || now <= 0) return finish('deny', DENY.MALFORMED_TIME);
    audit.at = now;
    let pol;
    try { pol = validatePolicy(policyIn); audit.policyDigest = sha256Canonical(pol); } catch (e) { return finish('deny', e instanceof PolicyError ? e.code : DENY.MALFORMED_POLICY); }
    if (pol.require === 'none') return finish('plain', 'POLICY_ALLOWS_PLAIN');
    if (pol.require === 'hardened') return finish('software-hardened', 'POLICY_REQUIRES_HARDENING_ONLY');
    // From here: confidentiality is required. Every failure is DENY; there is no fallback path.
    let device;
    try { device = snapshot(deviceIn); } catch { return finish('deny', DENY.UNSUPPORTED_ON_DEVICE); }
    if (!isRecord(device) || !has(device, 'teeAvailable') || device.teeAvailable !== true) return finish('deny', DENY.UNSUPPORTED_ON_DEVICE);
    if (evidenceIn === undefined || evidenceIn === null) return finish('deny', DENY.MISSING_EVIDENCE);
    let ev;
    try { ev = snapshot(evidenceIn); } catch { return finish('deny', DENY.MALFORMED_EVIDENCE); }
    if (!isRecord(ev) || !has(ev, 'platform') || typeof ev.platform !== 'string' || !PLATFORM.test(ev.platform)) return finish('deny', DENY.MALFORMED_EVIDENCE);
    const platform = ev.platform;
    audit.evidenceDigest = sha256Canonical({ platform, measurement: has(ev, 'measurement') ? ev.measurement ?? null : null, issuedAt: has(ev, 'issuedAt') ? ev.issuedAt ?? null : null });
    if (!pol.attestation.platforms.includes(platform)) return finish('deny', DENY.UNKNOWN_PLATFORM);
    if (!isRecord(verifiers) || !has(verifiers, platform)) return finish('deny', DENY.UNKNOWN_PLATFORM);
    const handle = verifiers[platform];
    const real = TRUSTED.get(handle), mock = MOCK.get(handle);
    if (!real && !(mock && testing)) return finish('deny', DENY.UNTRUSTED_VERIFIER);
    const impl = real ?? mock;
    audit.verifier = impl.id; audit.testing = !real;
    if (typeof nonce !== 'string' || !NONCE.test(nonce)) return finish('deny', DENY.NONCE_MISMATCH);
    let raw;
    try { raw = impl.verify(ev, Object.freeze({ nonce })); } catch { return finish('deny', DENY.VERIFIER_ERROR); }
    let result;
    try { result = snapshot(raw); } catch { return finish('deny', DENY.VERIFICATION_FAILED); }
    // Only an explicit own `ok: true` counts; truthy strings, objects or Promises do not.
    if (!isRecord(result) || !has(result, 'ok') || result.ok !== true) return finish('deny', DENY.VERIFICATION_FAILED);
    if (!has(result, 'nonce') || result.nonce !== nonce) return finish('deny', DENY.NONCE_MISMATCH);
    if (!has(result, 'issuedAt') || !Number.isSafeInteger(result.issuedAt) || result.issuedAt <= 0) return finish('deny', DENY.MALFORMED_EVIDENCE);
    if (result.issuedAt > now + 5) return finish('deny', DENY.FUTURE_EVIDENCE);
    if (now - result.issuedAt > pol.attestation.maxAgeSec) return finish('deny', DENY.STALE_EVIDENCE);
    if (!has(result, 'measurement') || typeof result.measurement !== 'string' || !pol.attestation.trustedMeasurements.includes(result.measurement)) return finish('deny', DENY.UNTRUSTED_MEASUREMENT);
    // The mock can only ever produce a distinct test mode, never 'confidential'.
    return finish(real ? 'confidential' : 'confidential-test', real ? 'ATTESTATION_VERIFIED' : 'MOCK_ATTESTATION_VERIFIED_FOR_TESTING', { platform, measurement: result.measurement });
  } catch {
    return finish('deny', DENY.INTERNAL_ERROR);
  }
}

/**
 * MOCK verifier for tests ONLY: HMAC over (platform, measurement, nonce, issuedAt) with a test key.
 * Its handle is never trusted; with allowMockVerifierForTesting === true the engine returns
 * 'confidential-test', never 'confidential'. Whoever holds the key (including host root) can forge it.
 */
export function createMockVerifier(key, id = 'mock-tee') {
  const mac = (platform, measurement, nonce, issuedAt) => createHmac('sha256', key).update(`${platform}\n${measurement}\n${nonce}\n${issuedAt}`).digest('hex');
  const verify = (e, { nonce }) => {
    // Read each field once; bind the expected nonce supplied by the engine, not the evidence's copy.
    const platform = e.platform, measurement = e.measurement, issuedAt = e.issuedAt, signature = e.signature;
    if (typeof signature !== 'string' || !HEX64.test(signature) || typeof measurement !== 'string' || !Number.isSafeInteger(issuedAt)) return { ok: false };
    const ok = timingSafeEqual(Buffer.from(mac(platform, measurement, nonce, issuedAt), 'hex'), Buffer.from(signature, 'hex'));
    return ok ? { ok: true, nonce, issuedAt, measurement } : { ok: false };
  };
  const handle = Object.freeze({ kind: 'appveil-mock-verifier', id });
  MOCK.set(handle, { id, verify });
  return Object.freeze({ handle, sign: e => ({ ...e, signature: mac(e.platform, e.measurement, e.nonce, e.issuedAt) }) });
}

/** Map the read-only hardware evidence (collect-hw-evidence.sh key: value lines) to device capability. */
export function deviceCapabilityFromEvidence(text) {
  const kv = Object.create(null);
  for (const line of String(text).split('\n')) { const i = line.indexOf(': '); if (i > 0) kv[line.slice(0, i).trim()] = line.slice(i + 2).trim(); }
  const present = k => kv[k] === 'present';
  const teeAvailable = present('cpuflag_sgx') || present('cpuflag_tdx_guest') || present('cpuflag_tdx_host_platform') || present('cpuflag_sev_snp');
  return { teeAvailable, secureBoot: /enabled/i.test(kv.secure_boot ?? ''), tpm2: kv.tpm_major === '2' };
}
