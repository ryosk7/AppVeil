import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { decideProtectionMode, validatePolicy, createMockVerifier, deviceCapabilityFromEvidence, DENY } from '../src/confidential-policy.mjs';

const M = 'a'.repeat(64), M2 = 'b'.repeat(64);
const policy = { schemaVersion: 1, require: 'confidential', attestation: { platforms: ['mock-tee'], trustedMeasurements: [M], maxAgeSec: 60 } };
const mock = createMockVerifier(randomBytes(32));
const now = 1_800_000_000;
const nonce = randomBytes(24).toString('hex');
const good = () => mock.sign({ platform: 'mock-tee', measurement: M, nonce, issuedAt: now - 10 });
const run = (o = {}) => decideProtectionMode({ policy, evidence: good(), nonce, verifiers: { 'mock-tee': mock }, device: { teeAvailable: true }, now, allowUntrustedVerifiersForTesting: true, ...o });

test('only full verification yields confidential; hardened/none never require evidence', () => {
  const r = run();
  assert.equal(r.mode, 'confidential'); assert.equal(r.reason, 'ATTESTATION_VERIFIED');
  assert.equal(decideProtectionMode({ policy: { schemaVersion: 1, require: 'hardened' } }).mode, 'software-hardened');
  assert.equal(decideProtectionMode({ policy: { schemaVersion: 1, require: 'none' } }).mode, 'plain');
});

test('every failure under a confidential policy is DENY with a specific reason, never a downgrade', () => {
  const cases = {
    [DENY.MISSING_EVIDENCE]: run({ evidence: undefined }),
    [DENY.MALFORMED_EVIDENCE]: run({ evidence: 'attested!' }),
    [DENY.UNKNOWN_PLATFORM]: run({ evidence: { ...good(), platform: 'other-tee' } }),
    [DENY.UNTRUSTED_VERIFIER]: run({ allowUntrustedVerifiersForTesting: false }),
    [DENY.VERIFIER_ERROR]: run({ verifiers: { 'mock-tee': { trusted: true, verify() { throw new Error('boom'); } } } }),
    [DENY.VERIFICATION_FAILED]: run({ evidence: { ...good(), signature: 'c'.repeat(64) } }),
    [DENY.NONCE_MISMATCH]: run({ nonce: randomBytes(24).toString('hex') }),
    [DENY.STALE_EVIDENCE]: run({ evidence: mock.sign({ platform: 'mock-tee', measurement: M, nonce, issuedAt: now - 61 }) }),
    [DENY.FUTURE_EVIDENCE]: run({ evidence: mock.sign({ platform: 'mock-tee', measurement: M, nonce, issuedAt: now + 600 }) }),
    [DENY.UNTRUSTED_MEASUREMENT]: run({ evidence: mock.sign({ platform: 'mock-tee', measurement: M2, nonce, issuedAt: now - 1 }) }),
    [DENY.UNSUPPORTED_ON_DEVICE]: run({ device: { teeAvailable: false } }),
    [DENY.CONTRADICTORY_POLICY]: run({ policy: { ...policy, allowSoftwareFallback: true } }),
    [DENY.MALFORMED_POLICY]: run({ policy: { ...policy, require: 'confidential-ish' } })
  };
  for (const [reason, r] of Object.entries(cases)) {
    assert.equal(r.mode, 'deny', `${reason}: got ${r.mode}`);
    assert.equal(r.reason, reason);
    assert.equal(r.audit.decision, 'deny');
  }
});

test('downgrade and type-confusion attempts are denied', () => {
  // Verifier returns truthy non-true values.
  for (const ok of ['true', 1, {}, [true]]) assert.equal(run({ verifiers: { 'mock-tee': { trusted: true, verify: () => ({ ok, nonce, issuedAt: now, measurement: M }) } } }).mode, 'deny');
  // Prototype tricks: platform inherited from Object.prototype, verifier map without own property.
  assert.equal(run({ evidence: { ...good(), platform: 'toString' }, policy: { ...policy, attestation: { ...policy.attestation, platforms: ['tostring'] } } }).mode, 'deny');
  assert.equal(run({ verifiers: Object.create({ 'mock-tee': mock }) }).mode, 'deny');
  assert.equal(run({ evidence: Object.assign(Object.create({ platform: 'mock-tee' }), good()) }).mode, 'deny', 'non-plain evidence object');
  // Short or missing nonce, mismatched nonce echoed by a lying verifier.
  assert.equal(run({ nonce: 'short' }).reason, DENY.NONCE_MISMATCH);
  assert.equal(run({ verifiers: { 'mock-tee': { trusted: true, verify: () => ({ ok: true, nonce: 'x'.repeat(48), issuedAt: now, measurement: M }) } } }).reason, DENY.NONCE_MISMATCH);
  // Unknown policy fields and attestation on non-confidential policies are rejected.
  assert.throws(() => validatePolicy({ ...policy, fallback: 'hardened' }), /unknown policy field/);
  assert.throws(() => validatePolicy({ schemaVersion: 1, require: 'hardened', attestation: policy.attestation }), /only meaningful/);
  assert.throws(() => validatePolicy({ ...policy, attestation: { ...policy.attestation, trustedMeasurements: ['A'.repeat(64)] } }), /lowercase/);
});

test('audit records carry digests and reason codes, never signatures, nonces or keys', () => {
  const r = run();
  const text = JSON.stringify(r.audit);
  assert.ok(!text.includes(good().signature) && !text.includes(nonce));
  assert.match(r.audit.policyDigest, /^[0-9a-f]{64}$/);
  assert.match(r.audit.evidenceDigest, /^[0-9a-f]{64}$/);
  assert.ok(Object.isFrozen(r) && Object.isFrozen(r.audit));
});

test('Olares One evidence maps to teeAvailable=false, so confidential policies deny there', () => {
  // Lines as printed by scripts/collect-hw-evidence.sh on Olares One (docs/OLARES_ONE_HW_EVIDENCE_2026-11-24.md).
  const cap = deviceCapabilityFromEvidence('cpuflag_sgx: absent\ncpuflag_tdx_guest: absent\ncpuflag_tdx_host_platform: absent\ncpuflag_sev_snp: absent\nsecure_boot: SecureBoot disabled\ntpm_major: 2\n');
  assert.deepEqual(cap, { teeAvailable: false, secureBoot: false, tpm2: true });
  assert.equal(run({ device: cap }).reason, DENY.UNSUPPORTED_ON_DEVICE);
});
