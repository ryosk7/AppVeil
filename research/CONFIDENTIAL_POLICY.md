# Protection-mode policy engine (Track C, issue #21). Prototype: independent security review required

`src/confidential-policy.mjs` implements the protection selection described in `docs/CONFIDENTIAL_RUNTIME.md`. **It is not a hardware boundary.** It decides which execution mode is allowed to run, and it never silently downgrades.

## Policy (schemaVersion 1)

```json
{ "schemaVersion": 1, "require": "confidential",
  "attestation": { "platforms": ["<verifier id>"], "trustedMeasurements": ["<sha256 hex>"], "maxAgeSec": 60 } }
```

| `require` | Outcome |
| --- | --- |
| `none` | `plain` |
| `hardened` | `software-hardened`, which makes no confidentiality claim and needs no evidence |
| `confidential` | `confidential` **only** after full attestation verification; otherwise **`deny`**. There is no fallback. A policy combining `require: confidential` with `allowSoftwareFallback: true` is rejected as contradictory. |

## Deny reasons (each one is tested)

| Reason | Cause |
| --- | --- |
| `MALFORMED_POLICY` | unknown fields, bad types |
| `CONTRADICTORY_POLICY` | confidential required but fallback allowed |
| `UNSUPPORTED_ON_DEVICE` | the device has no TEE; Olares One per `docs/OLARES_ONE_HW_EVIDENCE_2026-11-24.md` |
| `MISSING_EVIDENCE` / `MALFORMED_EVIDENCE` | no evidence, or evidence that is not a plain object or lacks a platform |
| `UNKNOWN_PLATFORM` | the platform is not in the policy, or there is no own verifier for it (inherited properties are ignored) |
| `UNTRUSTED_VERIFIER` | the verifier is not marked trusted; the mock verifier is accepted only when the caller explicitly opts into testing |
| `VERIFIER_ERROR` | the verifier threw |
| `VERIFICATION_FAILED` | the result is anything other than `ok === true` (truthy strings or objects do not count) |
| `NONCE_MISMATCH` | the nonce is missing or short, or the verifier echoed a different nonce |
| `STALE_EVIDENCE` / `FUTURE_EVIDENCE` | evidence older than `maxAgeSec`, or more than 5 s in the future |
| `UNTRUSTED_MEASUREMENT` | the measurement is not in the allow-list |

The audit record holds the time, policy digest, evidence digest, decision, reason, platform and measurement. It never holds signatures, nonces or keys, and it is frozen.

## Mock verifier

`createMockVerifier` signs and verifies evidence with an HMAC under a test key. Anyone who holds the key, including host root, can forge evidence, so **with the mock verifier nothing is confidential**. It exists only so the deny paths can be tested. A real deployment needs a hardware verifier, such as a vendor attestation service or an on-device quote verifier. Olares One has none (#20), and the external options are surveyed in #23.

## Review checklist for the independent reviewer

- Can any input (policy, evidence, verifier result, device capability) produce `confidential` without `ok === true`, a matching nonce, a fresh timestamp and an allow-listed measurement?
- Can a `confidential` policy ever produce `software-hardened` or `plain`?
- Is prototype pollution or a non-plain object handled everywhere?
- Does the audit record leak anything secret?
