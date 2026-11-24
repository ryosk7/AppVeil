# Backend matrix (issue #10)

`node scripts/backend-matrix.mjs [ir.json | --challenge-size N]` compiles **one** Veil IR program to every backend. Each backend is verified against an independent BigInt reference on 1,000 inputs **before** it is measured, and an incorrect backend is reported as `incorrect` and not timed. A backend whose toolchain is missing is reported as `not-checked`, with the reason. CI runs the matrix as a correctness gate on Linux with `lld` installed, so clang's Wasm target is exercised there too.

Each JS-side backend is timed in a **fresh Node process**, so JIT type feedback from one backend cannot bias another. The first version of this script shared one timing loop and reported minified JS at 17 ns against 9 ns for the identical plain JS; that was a measurement artifact. The native backend is timed by a C harness that calls `f` from a separate object file, so it is not inlined.

## Measured (Apple M2, macOS 27.2, Node v23.11.0, Apple clang 21.0.0; 100,000 inputs; 2 runs each)

`examples/veil-ir-score.json` (4 operations):

| Backend | Bytes | ns per call |
| --- | --- | --- |
| plain JS | 115 | 13.5–13.8 |
| minified JS | 82 | 13.7–13.8 |
| Veil VM v1 (load once) | 446 | 66.5 |
| Veil Wasm v1 | 47 | 8.0–8.1 |
| native clang -O2 | 512 (object) | 1.0–1.3 |
| clang wasm32 | — | not-checked locally (no `wasm-ld`); measured in CI |

Generated challenge, seed 1, size 16:

| Backend | Bytes | ns per call | Constants > 255 visible in the artifact bytes |
| --- | --- | --- | --- |
| plain JS | 322 | 12.1–12.5 | 5/5 |
| minified JS | 289 | 11.7–11.8 | 5/5 |
| Veil VM v1 | 730 | 395–402 | 5/5 |
| Veil Wasm v1 | 103 | 8.2–8.6 | 5/5 |
| native clang -O2 | 528 | 1.0–1.3 | 0/5 |

## Reading this table

- **Cost:** on this machine the Veil VM is about 30× slower than plain JS on the larger function and about 400× slower than native. Veil Wasm is slightly faster than JS here.
- **"Visible constants" is a mechanical count, not resistance.** Native code shows 0/5 only because arm64 splits 32-bit immediates across `mov`/`movk` instructions; disassembly recovers them trivially. Every encoding in this table is fully recovered by the static and dynamic Red Lab attacks (`research/RED_LAB_BASELINE.md`), and none affects black-box imitation (`research/RED_LAB_BLACKBOX.md`).
- Native timings exclude any JS↔native call overhead. JS-side timings include the loop and the call.
