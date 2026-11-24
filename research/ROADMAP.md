# AppVeil research roadmap

Derived from [`agent.md`](../agent.md). Each task is a GitHub issue with a falsifiable claim, acceptance criteria, a failure criterion and a "not guaranteed" section. Status here is updated when the corresponding PR merges. The issue tracker is authoritative.

Legend: ⬜ open · 🟨 in progress · ✅ merged · ⛔ blocked on hardware, independent review or an external release

## M1 — Foundation & correctness

| Key | Issue | Task | Track | Status |
| --- | --- | --- | --- | --- |
| F1 | [#2](https://github.com/ryosk7/AppVeil/issues/2) | CLI exit-status contract and strict argument parsing | Foundation | ⬜ |
| F2 | [#3](https://github.com/ryosk7/AppVeil/issues/3) | CI Node 20 + 24 matrix; explicit Wasm *not checked* | Foundation | ⬜ |
| A0 | [#4](https://github.com/ryosk7/AppVeil/issues/4) | Versioned JSON Schemas for IR v1 / bytecode v1 | A | ⬜ |
| B0 | [#5](https://github.com/ryosk7/AppVeil/issues/5) | VM validate-once loader and fuel limit | B | ⬜ |
| B1 | [#6](https://github.com/ryosk7/AppVeil/issues/6) | Deterministic fuzz harness | B | ⬜ |
| E1 | [#7](https://github.com/ryosk7/AppVeil/issues/7) | OCI layer history and config inspection | E | ⬜ |
| E2 | [#8](https://github.com/ryosk7/AppVeil/issues/8) | Secret-pattern detection (metadata-only) | E | ⬜ |

## M2 — Independent backend & Red Lab foundation

| Key | Issue | Task | Track | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| B2 | [#9](https://github.com/ryosk7/AppVeil/issues/9) | Veil IR → WebAssembly backend | B | B0, B1 | ⬜ |
| B3 | [#10](https://github.com/ryosk7/AppVeil/issues/10) | Benchmark matrix across backends | B | B2 | ⬜ |
| D1 | [#11](https://github.com/ryosk7/AppVeil/issues/11) | Red Lab harness (hidden challenges, budgets) | D | — | ⬜ |
| D2 | [#12](https://github.com/ryosk7/AppVeil/issues/12) | Static attack: full IR recovery | D | D1 | ⬜ |
| D3 | [#13](https://github.com/ryosk7/AppVeil/issues/13) | Dynamic tracing attack | D | D1, B2 | ⬜ |
| D4 | [#14](https://github.com/ryosk7/AppVeil/issues/14) | Non-AI black-box imitation baseline | D | D1 | ⬜ |

## M3 — Language frontend

| Key | Issue | Task | Track | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| A1 | [#15](https://github.com/ryosk7/AppVeil/issues/15) | Veil IR v2 (typed SSA, multi I/O, bounded loops) | A | B0, B1 | ⬜ |
| A2 | [#16](https://github.com/ryosk7/AppVeil/issues/16) | Restricted TypeScript subset frontend | A | A1 | ⬜ |
| A3 | [#17](https://github.com/ryosk7/AppVeil/issues/17) | Optimizations with translation validation | A | A1, B1 | ⬜ |
| A4 | [#18](https://github.com/ryosk7/AppVeil/issues/18) | Reproducible builds and build manifest | A | A1 | ⬜ |
| B4 | [#19](https://github.com/ryosk7/AppVeil/issues/19) | Bounded SMT equivalence (optional local z3) | B | A1 | ⬜ |

## M4 — Hardware isolation

Track C must be independently security-reviewed (`agent.md` §5). Items marked ⛔ cannot be completed by an implementing agent alone.

| Key | Issue | Task | Track | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| C1 | [#20](https://github.com/ryosk7/AppVeil/issues/20) | Olares One hardware capability evidence | C | real device | ⬜ |
| C2 | [#21](https://github.com/ryosk7/AppVeil/issues/21) | Fail-closed policy engine + attestation interface | C | independent review | ⬜ |
| C3 | [#22](https://github.com/ryosk7/AppVeil/issues/22) | Authenticated local IPC protocol | C | independent review | ⬜ |
| C4 | [#23](https://github.com/ryosk7/AppVeil/issues/23) | Survey of isolated hardware candidates | C | hardware testing | ⬜ |
| D5 | [#24](https://github.com/ryosk7/AppVeil/issues/24) | Key/material extraction lab | D | C2, C3 | ⬜ |

## M5 — AI trials & Olares release

| Key | Issue | Task | Track | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| D6 | [#25](https://github.com/ryosk7/AppVeil/issues/25) | Local AI reconstruction trials | D | D1–D4, local model | ⬜ |
| E3 | [#26](https://github.com/ryosk7/AppVeil/issues/26) | Chart digest pinning and OAC metadata verification | E | — | ⬜ |
| E4 | [#27](https://github.com/ryosk7/AppVeil/issues/27) | Re-audit new published Proofy / Shipboard releases | E | new releases, E1, E3 | ⬜ |
| F3 | [#28](https://github.com/ryosk7/AppVeil/issues/28) | README / SECURITY / terminology alignment | Foundation | — | ⬜ |

## Parallel-work ownership

Following `agent.md` §4, concurrent agents take non-overlapping ownership:

- compiler: `src/veil-ir*.mjs`, `research/VEIL_IR_*.md`
- runtime and backends: `src/veil-vm*.mjs`, `src/veil-wasm*.mjs`
- hardware: `src/confidential-*.mjs`, `docs/CONFIDENTIAL_RUNTIME.md`
- Red Lab: `src/red-lab*.mjs`, `research/RED_LAB_*.md`
- Olares integration: `src/inspect*.mjs`, `src/oci-*.mjs`, `src/olares-*.mjs`

Red Lab evaluators must not read hidden references or test answers.
