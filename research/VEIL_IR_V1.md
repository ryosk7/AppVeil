# AppVeil IR + Virtual Execution Engine — research prototype 1

## Implemented (not secure)

A deliberately narrow JSON expression IR with **uint32** input/output and pure operations: addition, subtraction, XOR, AND, OR, multiplication, shifts and bitwise NOT. Compilation emits register-based bytecode, with deterministic opcode permutations driven by a 32-bit seed. Runtime checks opcode tables, register references, and instruction shape. A reference evaluator interprets IR directly, enabling differential correctness tests against a JS oracle.

**No automatic arbitrary-TypeScript compilation exists yet.** This prototype accepts a checked JSON IR. Neither opcode permutation nor VM interpretation hides source from the host owner; the opcode table and register semantics ship with the executable. The result is **not encryption, iO, a TEE, or an anti-AI guarantee**.

## Normative semantics (v1)

All values are uint32 (`0..2^32-1`). Every result is reduced modulo 2^32. Shift counts use only their low 5 bits (`b mod 32`).

| op | Result |
| --- | --- |
| `add`, `sub`, `mul` | `(a op b) mod 2^32`. `sub` wraps (e.g. `0 - 1 = 0xffffffff`). `mul` uses the low 32 bits of the full product. |
| `xor`, `and`, `or` | Bitwise operation. |
| `not` | Bitwise complement, `0xffffffff - a`. |
| `shl` | `(a << (b mod 32)) mod 2^32`. |
| `ushr` | **Logical** right shift: `floor(a / 2^(b mod 32))`, zero-filled. |
| `shr` | **Arithmetic** right shift of the *int32 view* of `a` (sign bit replicated), result re-read as uint32. Example: `shr(0x80000000, 1) = 0xc0000000`, whereas `ushr(0x80000000, 1) = 0x40000000`. |

Operand order is `left op right`. The IR is limited to 256 nodes and nesting depth 32. Bytecode is SSA: instruction `i` writes register `i`, operands must reference earlier registers, and the single `ret` is last. Ground truth for these semantics is the BigInt reference in `test/veil-ir-semantics.test.mjs`. It shares no code with the evaluator or VM.

### Opcode table diversification

The opcode table is a Fisher–Yates permutation driven by xorshift32. The seed is first mixed with the murmur3 `fmix32` finalizer, so seed `0` (the CLI default) no longer starts xorshift at its fixed point. In the original prototype, seed `0` produced a near-identity rotation. Diversification only varies the encoding. **The table ships inside the artifact, so the permutation is not secret.** `research/RED_LAB_BASELINE.md` shows it is statically reversible for every seed.

### Digests

`irDigest` and the Red Lab `artifactSha256` are SHA-256 over **canonical JSON**: object keys sorted recursively, no whitespace, non-finite numbers rejected. They do not depend on source key order.

## Schemas and compatibility policy

Machine-readable structural schemas: [`schemas/veil-ir-v1.schema.json`](../schemas/veil-ir-v1.schema.json) and [`schemas/veil-bytecode-v1.schema.json`](../schemas/veil-bytecode-v1.schema.json) (JSON Schema 2020-12).

- **Code is never more permissive than the schema.** Every document the validators accept conforms to the schema (`test/veil-schema.test.mjs`, 300 generated programs). Every structural violation in the test corpus is rejected by both.
- **Semantic constraints JSON Schema cannot express** (node budget, depth, SSA ordering, operand arity per decoded opcode) are enforced only by the code. Each is listed in the schema's `x-appveil-semantic-constraints`, and a test case proves the code rejects it.
- **Unknown fields are rejected** at every level, top level included. A consumer must never silently ignore a field added by a newer format.
- **Versioning:** any change to accepted documents or to semantics bumps `schemaVersion` (IR) or `version` (bytecode) and adds a new schema file. Existing versions are never edited in place except to tighten a bug that let invalid documents through, and such a change is called out in the PR. A reader that does not support a version fails closed.
- `src/json-schema-lite.mjs` supports only the keywords these schemas use. Unknown keywords throw, so a schema cannot quietly lose a constraint.

## Measured cost

Reproduce with `node --expose-gc scripts/veil-ir-bench.mjs 200000`. The script reports resource cost only, never confidentiality.

Measured at commit `93ec7ff` on an Apple M2 (arm64) running macOS 27.2 (Darwin 27.2.0) with Node.js v23.11.0. The workload is `examples/veil-ir-score.json` compiled with seed 42: 446 bytes of bytecode, canonical digest `05ed9151d2f65d52…`. There were 200,000 xorshift-seeded inputs, and each figure is the median of 7 runs after 3 warm-up runs. The script was run 3 times; the table shows the range.

| Metric | Plain JS (`oracle`) | IR evaluator | VM (`runVeilBytecode`) |
| --- | --- | --- | --- |
| ns per call | 2.1–2.3 | 208–235 | 639–666 |
| Slowdown vs plain JS | 1× | ~99–103× | ~285–312× |
| Compile time | — | — | ~0.0065 ms per program |
| Heap delta after 200k VM calls | — | — | ~1.6 MiB (before GC) |

Limitations:
- This is one tiny expression on one machine.
- The plain-JS baseline is likely inlined by the JIT.
- Each VM call re-validates the whole envelope, including the opcode-table `Set` and `includes` checks. A validate-once API would shrink the VM overhead, but that is not done here.
- Native, Wasm and minified-JS backends are not compared yet; see research gate 3.
- None of these numbers say anything about confidentiality.

## Research gates

1. Validate semantics: 100% conformance for supported functions on seeded properties and edge cases; develop formal equivalence for a defined subset.
2. Compare static extraction, dynamic tracing with root access, black-box functional imitation and hardware-assisted extraction as separate attack classes.
3. Compare reconstruction under matched model/time/token/tool budgets against plain JS, native machine code and Wasm; use independently withheld algorithms.
4. Quantify interpreter slowdown, memory allocation and compile time. A lower string count or changed opcode mapping is not proof of security.
5. Require hardware isolation to claim confidentiality against host root; fail closed when required isolation is unavailable.

## Next engineering components

- Restricted TypeScript subset frontend using TypeScript compiler APIs, purity analysis and declared I/O boundaries.
- Typed SSA-based IR, verified optimization and deterministic serialization.
- Rust and JavaScript interpreters with cross-language golden vectors and SMT equivalence.
- Local-only hardware execution adapter with attestation, offline keys and deny-on-unsupported policy.
- Red Lab harness with withheld independent challenge programs and sandboxed execution of untrusted generated code.

This stage establishes a compiler-correctness research harness, not a confidential runtime.
