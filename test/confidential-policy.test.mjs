import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { decideProtectionMode, validatePolicy, createMockVerifier, registerTrustedVerifier, deviceCapabilityFromEvidence, DENY } from '../src/confidential-policy.mjs';

const M = 'a'.repeat(64), M2 = 'b'.repeat(64);
const policy = { schemaVersion: 1, require: 'confidential', attestation: { platforms: ['mock-tee', 'real-tee', 'tdx', 'sgx'], trustedMeasurements: [M], maxAgeSec: 60 } };
const mock = createMockVerifier(randomBytes(32));
const now = 1_800_000_000;
const nonce = randomBytes(24).toString('hex');
const good = () => mock.sign({ platform: 'mock-tee', measurement: M, nonce, issuedAt: now - 10 });
const run = (o = {}) => decideProtectionMode({ policy, evidence: good(), nonce, verifiers: { 'mock-tee': mock.handle }, device: { teeAvailable: true }, now, allowMockVerifierForTesting: true, ...o });
// A registered "real" verifier that echoes evidence fields (stands in for a hardware verifier).
const echo = registerTrustedVerifier('real-tee', (e, { nonce: n }) => ({ ok: true, nonce: n, issuedAt: e.issuedAt, measurement: e.measurement }));
const realRun = (o = {}) => decideProtectionMode({ policy, evidence: { platform: 'real-tee', measurement: M, issuedAt: now - 10 }, nonce, verifiers: { 'real-tee': echo }, device: { teeAvailable: true }, now, ...o });

test('only a registered verifier yields confidential; the mock yields confidential-test at most', () => {
  assert.equal(realRun().mode, 'confidential');
  assert.equal(realRun().audit.verifier, 'real-tee');
  const t = run();
  assert.equal(t.mode, 'confidential-test');
  assert.equal(t.audit.testing, true);
  assert.equal(decideProtectionMode({ policy: { schemaVersion: 1, require: 'hardened' } }).mode, 'software-hardened');
  assert.equal(decideProtectionMode({ policy: { schemaVersion: 1, require: 'none' } }).mode, 'plain');
});

test('every failure under a confidential policy is DENY with a specific reason, never a downgrade', () => {
  const cases = {
    [DENY.MISSING_EVIDENCE]: run({ evidence: undefined }),
    [DENY.MALFORMED_EVIDENCE]: run({ evidence: 'attested!' }),
    [DENY.UNKNOWN_PLATFORM]: run({ evidence: { ...good(), platform: 'other-tee' } }),
    [DENY.UNTRUSTED_VERIFIER]: run({ allowMockVerifierForTesting: false }),
    [DENY.VERIFIER_ERROR]: realRun({ verifiers: { 'real-tee': registerTrustedVerifier('real-tee', () => { throw new Error('boom'); }) } }),
    [DENY.VERIFICATION_FAILED]: run({ evidence: { ...good(), signature: 'c'.repeat(64) } }),
    // The mock binds the engine-supplied nonce, so a wrong nonce fails the signature; a verifier that
    // echoes a different nonce is caught by the nonce check.
    [DENY.NONCE_MISMATCH]: realRun({ verifiers: { 'real-tee': registerTrustedVerifier('real-tee', e => ({ ok: true, nonce: 'cd'.repeat(24), issuedAt: e.issuedAt, measurement: e.measurement })) } }),
    [DENY.STALE_EVIDENCE]: realRun({ evidence: { platform: 'real-tee', measurement: M, issuedAt: now - 61 } }),
    [DENY.FUTURE_EVIDENCE]: realRun({ evidence: { platform: 'real-tee', measurement: M, issuedAt: now + 600 } }),
    [DENY.UNTRUSTED_MEASUREMENT]: realRun({ evidence: { platform: 'real-tee', measurement: M2, issuedAt: now - 1 } }),
    [DENY.UNSUPPORTED_ON_DEVICE]: realRun({ device: { teeAvailable: false } }),
    [DENY.CONTRADICTORY_POLICY]: realRun({ policy: { ...policy, allowSoftwareFallback: true } }),
    [DENY.MALFORMED_POLICY]: realRun({ policy: { ...policy, require: 'confidential-ish' } }),
    [DENY.MALFORMED_TIME]: realRun({ now: -1 })
  };
  for (const [reason, r] of Object.entries(cases)) {
    assert.equal(r.mode, 'deny', `${reason}: got ${r.mode}/${r.reason}`);
    assert.equal(r.reason, reason);
  }
});

// Regression tests for the independent review of PR #52 (H = high, M = medium, L = low).
test('H1: now must be a positive safe integer (NaN or string time cannot disable freshness)', () => {
  const old = { platform: 'real-tee', measurement: M, issuedAt: now - 10 * 365 * 86400 };
  assert.equal(realRun({ now: NaN, evidence: old }).reason, DENY.MALFORMED_TIME);
  assert.equal(realRun({ now: String(now), evidence: { platform: 'real-tee', measurement: M, issuedAt: now + 8 * 3600 } }).reason, DENY.MALFORMED_TIME);
  assert.equal(realRun({ now: 1.5 }).reason, DENY.MALFORMED_TIME);
});

test('H2/M2: evidence getters and Proxies are snapshotted once (no check-then-use swap)', () => {
  // Measurement getter: untrusted for the first reads, trusted afterwards.
  let reads = 0;
  const swapping = { platform: 'real-tee', issuedAt: now - 1, get measurement() { return ++reads <= 3 ? M2 : M; } };
  const r = realRun({ evidence: swapping });
  assert.equal(r.reason, DENY.UNTRUSTED_MEASUREMENT, 'the value seen by checks is the value used');
  // Platform getter that changes at verifier lookup.
  const sgx = registerTrustedVerifier('sgx', (e, { nonce: n }) => ({ ok: true, nonce: n, issuedAt: e.issuedAt, measurement: e.measurement }));
  const tdx = registerTrustedVerifier('tdx', () => ({ ok: false }));
  let p = 0;
  const platformSwap = { get platform() { return ++p >= 5 ? 'sgx' : 'tdx'; }, measurement: M, issuedAt: now - 1 };
  const r2 = realRun({ policy: { ...policy, attestation: { ...policy.attestation, platforms: ['tdx'] } }, evidence: platformSwap, verifiers: { tdx, sgx } });
  assert.equal(r2.mode, 'deny');
  // Proxy evidence is reduced to data; a Proxy with a lying getPrototypeOf gains nothing.
  const proxy = new Proxy({ platform: 'real-tee', measurement: M2, issuedAt: now - 1 }, { getPrototypeOf: () => Object.prototype, get: (t, k) => (k === 'measurement' && Math.random() < 2 ? M2 : t[k]) });
  assert.equal(realRun({ evidence: proxy }).reason, DENY.UNTRUSTED_MEASUREMENT);
});

test('H3: the testing flag must be exactly true, and trust cannot be self-declared', () => {
  assert.equal(run({ allowMockVerifierForTesting: 'no' }).reason, DENY.UNTRUSTED_VERIFIER);
  assert.equal(run({ allowMockVerifierForTesting: 1 }).reason, DENY.UNTRUSTED_VERIFIER);
  const forged = { ...mock.handle, trusted: true };
  assert.equal(run({ verifiers: { 'mock-tee': forged }, allowMockVerifierForTesting: false }).reason, DENY.UNTRUSTED_VERIFIER);
  const fake = { trusted: true, verify: (e, { nonce: n }) => ({ ok: true, nonce: n, issuedAt: e.issuedAt, measurement: e.measurement }) };
  assert.equal(realRun({ verifiers: { 'real-tee': fake } }).reason, DENY.UNTRUSTED_VERIFIER);
  assert.notEqual(run().mode, 'confidential', 'mock can never produce confidential');
});

test('M1/L3: policy getters, custom iterators, overridden methods and sparse arrays cannot widen the policy', () => {
  let c = 0;
  const flipping = { schemaVersion: 1, get require() { return ++c <= 3 ? 'confidential' : 'none'; }, attestation: policy.attestation };
  assert.notEqual(realRun({ policy: flipping }).mode, 'plain');
  const tm = [M]; tm[Symbol.iterator] = function* () { yield M; yield M2; };
  assert.equal(realRun({ policy: { ...policy, attestation: { ...policy.attestation, trustedMeasurements: tm } }, evidence: { platform: 'real-tee', measurement: M2, issuedAt: now - 1 } }).reason, DENY.UNTRUSTED_MEASUREMENT);
  const lying = ['not-hex', 'E'.repeat(64)]; lying.some = () => false; lying.every = () => true;
  assert.throws(() => validatePolicy({ ...policy, attestation: { ...policy.attestation, trustedMeasurements: lying } }), /lowercase/);
  const sparse = [M]; sparse[2] = M;
  assert.throws(() => validatePolicy({ ...policy, attestation: { ...policy.attestation, trustedMeasurements: sparse } }), /lowercase/);
  let a = 0;
  const widening = { ...policy, attestation: { platforms: ['real-tee'], get trustedMeasurements() { return ++a === 1 ? [M] : [M, M2]; }, maxAgeSec: 60 } };
  assert.equal(realRun({ policy: widening, evidence: { platform: 'real-tee', measurement: M2, issuedAt: now - 1 } }).reason, DENY.UNTRUSTED_MEASUREMENT);
});

test('M3: exceptions never escape; all become DENY', () => {
  assert.equal(decideProtectionMode().reason, DENY.INTERNAL_ERROR);
  assert.equal(decideProtectionMode(null).mode, 'deny');
  assert.equal(realRun({ verifiers: null }).reason, DENY.UNKNOWN_PLATFORM);
  assert.equal(realRun({ evidence: { get platform() { throw new Error('x'); } } }).reason, DENY.MALFORMED_EVIDENCE);
  assert.equal(realRun({ policy: { schemaVersion: 1, get require() { throw null; } } }).reason, DENY.MALFORMED_POLICY);
  const throwingResult = registerTrustedVerifier('real-tee', () => ({ get ok() { throw new Error('x'); } }));
  assert.equal(realRun({ verifiers: { 'real-tee': throwingResult } }).mode, 'deny');
  const cyclic = { platform: 'real-tee' }; cyclic.self = cyclic;
  assert.equal(realRun({ evidence: cyclic }).reason, DENY.MALFORMED_EVIDENCE);
});

test('M4: prototype pollution has no effect', () => {
  const restore = [];
  const pollute = (k, v) => { restore.push(k); Object.prototype[k] = v; };
  try {
    pollute('trusted', true); pollute('maxAgeSec', 3600); pollute('ok', true); pollute('teeAvailable', true);
    const noAge = { schemaVersion: 1, require: 'confidential', attestation: { platforms: ['real-tee'], trustedMeasurements: [M] } };
    assert.equal(realRun({ policy: noAge }).reason, DENY.MALFORMED_POLICY);
    assert.equal(realRun({ device: {} }).reason, DENY.UNSUPPORTED_ON_DEVICE);
    const fake = { verify: () => ({}) };
    assert.equal(realRun({ verifiers: { 'real-tee': fake } }).reason, DENY.UNTRUSTED_VERIFIER);
    const emptyResult = registerTrustedVerifier('real-tee', () => ({}));
    assert.equal(realRun({ verifiers: { 'real-tee': emptyResult } }).reason, DENY.VERIFICATION_FAILED);
  } finally { for (const k of restore) delete Object.prototype[k]; }
  try {
    pollute('require', 'none');
    assert.equal(decideProtectionMode({ policy: { schemaVersion: 1 }, now }).mode, 'deny');
  } finally { delete Object.prototype.require; }
});

test('L1/L2/L4: device must affirm a TEE; nonce must be >=128-bit hex; async verifiers are denied', () => {
  for (const device of [{}, null, undefined, { teeAvailable: 'false' }, { teeAvailable: 1 }]) assert.equal(realRun({ device }).reason, DENY.UNSUPPORTED_ON_DEVICE);
  assert.equal(realRun({ nonce: ' '.repeat(32) }).reason, DENY.NONCE_MISMATCH);
  assert.equal(realRun({ nonce: 'ab'.repeat(8) }).reason, DENY.NONCE_MISMATCH, '64-bit nonce rejected');
  const asyncV = registerTrustedVerifier('real-tee', async () => ({ ok: true }));
  assert.equal(realRun({ verifiers: { 'real-tee': asyncV } }).reason, DENY.VERIFICATION_FAILED);
});

test('audit records carry digests, verifier id and testing marker, never signatures, nonces or keys', () => {
  const r = run();
  const text = JSON.stringify(r.audit);
  assert.ok(!text.includes(good().signature) && !text.includes(nonce));
  assert.match(r.audit.policyDigest, /^[0-9a-f]{64}$/);
  assert.equal(r.audit.verifier, 'mock-tee');
  assert.equal(run({ nonce: randomBytes(24).toString('hex') }).reason, DENY.VERIFICATION_FAILED, 'mock binds the engine nonce');
  assert.ok(Object.isFrozen(r) && Object.isFrozen(r.audit));
});

test('Olares One evidence maps to teeAvailable=false, so confidential policies deny there', () => {
  // Lines as printed by scripts/collect-hw-evidence.sh on Olares One (docs/OLARES_ONE_HW_EVIDENCE_2026-11-24.md).
  const cap = deviceCapabilityFromEvidence('cpuflag_sgx: absent\ncpuflag_tdx_guest: absent\ncpuflag_tdx_host_platform: absent\ncpuflag_sev_snp: absent\nsecure_boot: SecureBoot disabled\ntpm_major: 2\n');
  assert.deepEqual(cap, { teeAvailable: false, secureBoot: false, tpm2: true });
  assert.equal(realRun({ device: cap }).reason, DENY.UNSUPPORTED_ON_DEVICE);
});
