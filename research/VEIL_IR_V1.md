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

## Measured cost

Reproduce with `node --expose-gc scripts/veil-ir-bench.mjs 200000`. The script reports resource cost only, never confidentiality.

COST_TABLE_PLACEHOLDER

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
