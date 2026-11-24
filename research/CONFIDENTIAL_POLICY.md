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
| `confidential` | `confidential` **only** after full attestation verification by a verifier **registered** with `registerTrustedVerifier` (module-private registry; trust cannot be self-declared). With the mock verifier and `allowMockVerifierForTesting === true`, the result is the distinct mode **`confidential-test`**, never `confidential`. Otherwise **`deny`**. There is no fallback. A policy combining `require: confidential` with `allowSoftwareFallback: true` is rejected as contradictory. |

**Input handling:** every input (policy, evidence, device, verifier result) is snapshotted **once** into inert, frozen, null-prototype JSON data before any check. Getters, Proxies, custom iterators or overridden array methods cannot change a value between its check and its use, and prototype pollution has no effect. Only the snapshot is passed to the verifier. Any exception anywhere becomes `deny / INTERNAL_ERROR`. Callers must still treat an exception as deny.

## Deny reasons (each one is tested)

| Reason | Cause |
| --- | --- |
| `MALFORMED_POLICY` | unknown fields, bad types |
| `CONTRADICTORY_POLICY` | confidential required but fallback allowed |
| `MALFORMED_TIME` | `now` is not a positive safe integer; production should omit `now` and use the clock |
| `UNSUPPORTED_ON_DEVICE` | the device does not affirm `teeAvailable === true`; anything else (missing, `false`, `"false"`) denies. Olares One: `docs/OLARES_ONE_HW_EVIDENCE_2026-11-24.md` |
| `MISSING_EVIDENCE` / `MALFORMED_EVIDENCE` | no evidence, or evidence that is not a plain object or lacks a platform |
| `UNKNOWN_PLATFORM` | the platform is not in the policy, or there is no own verifier for it (inherited properties are ignored) |
| `UNTRUSTED_VERIFIER` | the verifier handle is not registered; a mock handle without `allowMockVerifierForTesting === true`; forged handles or `trusted: true` properties do not count |
| `VERIFIER_ERROR` | the verifier threw |
| `VERIFICATION_FAILED` | the result is anything other than an own `ok === true`. Truthy strings or objects do not count, and neither does a Promise: verifiers must be synchronous (a known limitation, because real attestation is usually asynchronous) |
| `INTERNAL_ERROR` | any unexpected exception, including a missing argument object |
| `NONCE_MISMATCH` | the nonce is not lowercase hex of 128 to 512 bits, or the verifier returned a different nonce. The engine passes its expected nonce to the verifier, and the mock binds that value, so a wrong nonce usually fails as `VERIFICATION_FAILED`. Callers must generate the nonce freshly and use it once. |
| `STALE_EVIDENCE` / `FUTURE_EVIDENCE` | evidence older than `maxAgeSec`, or more than 5 s in the future |
| `UNTRUSTED_MEASUREMENT` | the measurement is not in the allow-list |

The audit record holds the time, policy digest, evidence digest, decision, reason, platform and measurement. It never holds signatures, nonces or keys, and it is frozen.

## Mock verifier

`createMockVerifier` returns `{ handle, sign }`. It signs and verifies evidence with an HMAC under a test key. Anyone who holds the key, including host root, can forge evidence, so the engine **never returns `confidential` for the mock**: only `confidential-test`, and only with the explicit flag. The audit record marks `testing: true` and the verifier id. It exists only so the deny paths can be tested. A real deployment needs a hardware verifier, such as a vendor attestation service or an on-device quote verifier. Olares One has none (#20), and the external options are surveyed in #23.

## Review checklist for the independent reviewer

- Can any input (policy, evidence, verifier result, device capability) produce `confidential` without `ok === true`, a matching nonce, a fresh timestamp and an allow-listed measurement?
- Can a `confidential` policy ever produce `software-hardened` or `plain`?
- Is prototype pollution or a non-plain object handled everywhere?
- Does the audit record leak anything secret?

## Independent review (PR #52)

An AI reviewer agent, independent of the implementing session, rejected the first version. Its findings:
- **H1:** an unvalidated `now` (`NaN` or a string) disabled the freshness checks.
- **H2 / M2:** live evidence getters and Proxies allowed check-then-use swaps of the measurement and the platform.
- **H3:** a truthy testing flag or a self-declared `trusted: true` produced `confidential` from the mock.
- **M1:** policy getters, iterators and overridden array methods could widen the allow-list.
- **M3:** exceptions escaped the function.
- **M4:** prototype pollution of `trusted`, `maxAgeSec`, `require` or `ok` changed outcomes.
- **L1:** the device check failed open.
- **L2:** the nonce was checked only for length.
- **L3:** sparse arrays were accepted.

All are fixed, and each has a regression test in `test/confidential-policy.test.mjs`. Async verifiers (L4) remain denied by design until the API changes. A human security review is still recommended before any use outside research.
