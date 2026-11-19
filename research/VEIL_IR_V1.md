# AppVeil IR + Virtual Execution Engine — research prototype 1

## Implemented (not secure)

A deliberately narrow JSON expression IR with **uint32** input/output and pure operations: addition, subtraction, XOR, AND, OR, multiplication, shifts and bitwise NOT. Compilation emits register-based bytecode, with deterministic opcode permutations driven by a 32-bit seed. Runtime checks opcode tables, register references, and instruction shape. A reference evaluator interprets IR directly, enabling differential correctness tests against a JS oracle.

**No automatic arbitrary-TypeScript compilation exists yet.** This prototype accepts a checked JSON IR. Neither opcode permutation nor VM interpretation hides source from the host owner; the opcode table and register semantics ship with the executable. The result is **not encryption, iO, a TEE, or an anti-AI guarantee**.

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
