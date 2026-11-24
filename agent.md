# AppVeil — AI Agent Development Charter

> This file is the canonical operating guide for AI coding and research agents working on AppVeil. Read it before changing the repository. For agents that automatically discover `AGENTS.md`, that file points here.

## 1. Mission and hard constraints

AppVeil is a **public, experimental research project** for protecting proprietary TypeScript applications deployed on Olares, with **fully local application execution as the top priority**.

We research five connected areas: a restricted TypeScript compiler and Veil IR, software hardening and multi-backend execution, local hardware-backed confidential execution, AI-assisted reverse-engineering evaluation (Red Lab), and verifiable Olares release hygiene.

Requirements:
- Preserve local execution of application logic and user data. Never transmit proprietary source, secrets, documents, generated artifacts, or prompts to a remote AI service as part of protection or experiments. A local model endpoint is not proof of no forwarding; document the trust assumption.
- Treat the customer's Olares host as **attacker-controlled**, including root, filesystem access, image export, process instrumentation, tracing, and memory inspection.
- **Never claim absolute secrecy**, AI-proof code, mathematically guaranteed protection, or host-root confidentiality from obfuscation, encryption with a host-accessible key, a custom VM, WebAssembly, or conventional containers.
- A hardware-bound confidentiality mode must fail closed when its attested isolation boundary is missing, unsupported, or unverifiable. Do not silently downgrade to software hardening.
- Hardware capability claims about Olares One, CPU, TPM, Secure Boot, SGX, TDX, GPU or firmware need device-specific evidence. Do not equate measured boot with runtime secrecy.
- Reuse Olares OAC/Helm, Market, existing app deployment, and licensing facilities. Do not build a competing app store, container scheduler, or license system.
- **Never copy** proprietary Proofy or Shipboard AI application code into this public repository. Use public synthetic fixtures and sanitized metadata only.

## 2. Ground truth, scope, and terminology

Keep these concepts separate in designs, implementations, test names, documentation and release notes:

| Term | Meaning | Does *not* imply |
| --- | --- | --- |
| Artifact hygiene | Preventing unintended maps, original sources, keys and configuration in releases | Reverse-engineering resistance |
| Software hardening | Increasing the measured cost of static/dynamic reconstruction | Confidentiality from root |
| Functional imitation resistance | Making an attacker less successful at reconstructing externally observable behavior within a stated budget | Source secrecy or impossibility of cloning |
| Confidential execution | An independently validated hardware isolation and key boundary under an explicit attacker model | Resistance to all side channels, physical attacks or output inference |
| AI attack benchmark | Empirical success/cost measurements with documented models, budgets and hidden tests | A cryptographic security proof |

Where evidence is missing, label statements **hypothesis**, **prototype**, **not tested**, or **unsupported**. Negative results are valuable research results.

## 3. Repository map (verify before relying on it)

- `bin/appveil.mjs`: Node.js CLI. Keep argument parsing deterministic and exit statuses meaningful.
- `src/inspect.mjs`, `src/image-policy.mjs`, `src/dockerfile-audit.mjs`: release-artifact scanning and policy.
- `src/olares-image-check.mjs`: Olares Chart image-reference checks; a new tag alone is not proof of clean content.
- `src/benchmark.mjs`, `src/reconstruction-eval.mjs`, `src/local-ai-trial.mjs`: observability and functional evaluation tools. They do not establish confidentiality.
- `test/`: Node built-in test runner. `examples/`: synthetic fixtures. `docs/`: research and audit evidence.
- `.github/workflows/`: CI and opt-in public image checks.
- `research/veil-ir-vm-v1`: initial IR/VM/Red Lab research branch and PR #1 at time of writing. **This work is not necessarily merged into `main`. Check current branches and commits; do not describe unmerged work as released.**

Repository structure and docs can evolve. Check actual files and CI before editing.

## 4. Agent workflow

1. **Inspect first**: read `README.md`, relevant docs and actual implementation; check the latest target branch and CI. Do not assume previous conversational plans are implemented.
2. **Define a falsifiable claim**: write an experiment hypothesis, relevant attacker capability, baseline, expected outcome and failure criterion. Where relevant, separate static analysis, live instrumentation, key extraction and black-box imitation.
3. **Work in a scoped branch** for substantive research; make changes in small, reviewable commits. Never merge a security-sensitive change solely because tests compile.
4. **Implement with independent checks**: validate inputs, bound memory/time/size, avoid `eval` and dynamic execution of untrusted generated code, isolate red-team generated programs, and provide a deterministic reference interpreter for compiler work.
5. **Test regressions and invariants**: run `npm test` and `node bin/appveil.mjs --help`; run `bash scripts/benchmark-local.sh` only where Node.js and clang are available. Record exact missing dependencies instead of reporting success.
6. **Document what was actually measured**: source commit, hardware/OS, compiler flags, artifact digest, AI model/version/quantization, token/tool/time budget, seeded input distribution, accuracy, latency, memory, and limitations. No invented results.
7. **Submit a PR** with threat model, security changes, test evidence, negative findings, performance cost, and rollback plan. Prefer draft PR for new compiler, runtime, cryptography or device-boundary work.
8. **Verify post-merge artifacts separately**: a merged fix or successful candidate-image test does not update an already-published GHCR image or Olares Chart. Scan the exact published digest and check OAC release metadata.

When multiple agents work concurrently, assign non-overlapping ownership (compiler, runtime, hardware, Red Lab, Olares integration); agree on versioned IR/API schemas and use explicit integration checkpoints. Independent Red Lab evaluators must not read hidden reference implementations or test answers.

## 5. Research architecture and priorities

### Track A — Language frontend / Veil IR
Build a well-specified, **restricted** subset of TypeScript first: pure functions, explicit uint32 or other typed inputs/outputs, predictable arithmetic, bounded control flow, and no ambient Node API access. Expand only with correctness and preservation tests. Evolve toward typed SSA, verified optimizations, canonical serialization, versioned bytecode and reproducible builds. Do not interpret arbitrary JavaScript text using `eval`.

### Track B — Virtual execution and backends
Use a reference interpreter and at least one independent backend; cross-check with seeded and boundary vectors, fuzzing, and later formal or SMT equivalence. Compare ordinary JS, minified JS, native, Wasm and candidate Veil VM builds. VM opcode shuffling is a **research control**, not a claim of secrecy: an attacker may reconstruct it from the shipped decoder or trace.

### Track C — Hardware isolation
Investigate on-premises dedicated hardware with secure/measured boot, hardware-rooted identity and keys, attestation, authenticated local IPC, update and rollback protections. Design assuming a hostile host OS. Isolate keys and code **inside** a verified hardware boundary; do not release plaintext or keys to untrusted host memory and call it protected. Distinguish host-root, firmware, side-channel and invasive physical threat levels. Do not claim support until tested on actual hardware.

### Track D — Red Lab
Build a reproducible adversarial test harness: static semantic recovery, dynamic tracing, functional imitation and (in a safely isolated environment) key/material extraction. Include **simple attacks** that break superficial controls. Use hidden, independently generated challenge programs, holdout inputs and separate attacker/defender access to prevent answer contamination. Measure both attack success and attacker resources. Never run arbitrary model-generated code on production systems or CI workers holding secrets.

### Track E — Olares integration / distribution
Preserve existing deployment and commercial mechanisms. Add verifiable publish gates, OCI layer and config checks, release digest pinning, hermetic builds and private debug artifacts. Metadata-only findings are appropriate for public reports; **never upload discovered secrets, source-map bodies or confidential images**.

Tracks A, B and D can advance in parallel. Track C must be independently security-reviewed. Track E connects validated results to products; do not prematurely wire unreviewed research code into Proofy/Shipboard production.

## 6. Engineering standards

- Runtime target: follow the `engines` field in `package.json` (initially Node.js 20+), ESM modules, built-in `node:test`. Avoid adding dependencies without clear value and maintenance justification.
- Validate schema versions, opcode operands, bounds and sizes before processing. Unknown or malformed formats must fail closed with actionable errors; no arbitrary program execution during scans.
- Keep deterministic tests and pinned input seeds. Include adversarial and malformed-input tests, not only successful examples.
- Never log authentication tokens, private keys, hidden evaluation answers, protected source, source-map contents or personal data. Audit outputs should default to metadata and counts.
- Do not silently swallow test or security scanner failures. Fail with nonzero exit code when the documented policy is violated. Distinguish `not checked` from `passed`.
- Use reproducible experiment artifacts and record SHA-256 digests. Avoid comparing inconsistent optimizations or benchmark budgets.
- Keep new code straightforward, reviewable, and maintainable. Security value must come from evidence, not obscurity of the implementation or marketing terms.
- Maintain the MIT license and preserve existing functionality unless a change is explicitly part of the task.

## 7. Definition of done

A research change is complete only when:
- The specific claim and threat model are documented.
- Correctness is verified against independent ground truth, with automated positive and negative tests.
- Performance and resource impact are recorded where relevant.
- An appropriate Red Lab baseline has been attempted and its outcome reported, including if the defense fails.
- No confidential application data or credentials entered the public repo or third-party services.
- CI passes on the exact proposed commit, or failures and blockers are explicitly disclosed.
- The PR states what **is not guaranteed**, and no release is represented as protected before the published image has been audited.

## 8. Practical commands

```bash
npm test
node bin/appveil.mjs --help
bash scripts/benchmark-local.sh

# Locally inspect a built artifact without executing it:
node bin/appveil.mjs inspect /path/to/dist --json --strict

# On a Docker host:
node bin/appveil.mjs inspect-image ghcr.io/ryosk7/shipboardai:<new-version> --json > image-audit.json
node bin/appveil.mjs verify-image-report image-audit.json

# Optional synthetic experiments only, using a local Ollama instance:
node bin/appveil.mjs local-ai-trial /tmp/synthetic.o <installed-local-model>
```

Read `docs/CONFIDENTIAL_RUNTIME.md`, `docs/RELEASE_GATE.md`, `docs/RECONSTRUCTION_EVALUATION.md`, and any research PR specifications before changing those systems.

## 9. Communication policy for agents

Communicate in the user's language (normally Japanese). Keep code comments, APIs, security contracts and research papers in clear technical English when interoperability benefits. Provide precise GitHub links and CI run identifiers. Never assert that a tool ran, a branch merged, an artifact shipped, a test passed, or a vulnerability was fixed without verifying it. Describe partial results and blockers plainly.

**Long-term ambition:** create a credible, locally executed protection platform whose security claims survive independent adversarial scrutiny. The project should be willing to publish evidence that one of its own defenses does not work.
