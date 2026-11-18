# AppVeil local confidential runtime research — architecture v0

## Non-negotiable constraints

- All user documents and proprietary computation execute locally on the owner's Olares One (no SaaS back-end).
- Buyer may have host root access and can export image layers, instrument Node.js, observe memory and modify binaries.
- AI-assisted reverse engineering and black-box imitation are included in the adversary model.
- Standard Olares One Core Ultra 9 275HX (Arrow Lake) does not provide SGX/TDX host-resistant confidential enclaves. Independently verify device firmware and OS configuration before security claims.
- No software-only technique guarantees that owner-controlled CPU-executed code will remain secret from the owner.

## Architecture

```text
Olares OAC & Market (reuse existing mechanisms)
  -> standard app: React/Hono/DB/Router (inspectable)
     -> explicit local IPC protocol to secret module
        -> protection selection (validated at runtime)
           A: standard CPU hardened bundle [best-effort only]
           B: measured boot and TPM policy [boot integrity only, NOT runtime secrecy]
           C: isolated on-prem compute device with hardware-bound keys [research]
```

A pure software encrypted bytecode loader running under host root is not a confidential runtime. No decryption key should be shipped or obtained by an untrusted standard container and then described as secret. If the selected policy requires confidentiality and the boundary cannot be verified, fail closed instead of silently switching to A/B.

## Olares integration

Preserve OAC/Helm packaging, Market installation and Merchant paid app licensing. Olares licensing/identity should not be confused with execution-code confidentiality. Proposed adapter must verify supported Olares environment variables and credential schema before implementation.

## Experiment protocol

1. Prepare a **synthetic, open-source** algorithm with known specification and hidden reference answers.
2. Compile equivalent functionality into plain JS, minified JS, Wasm, and native binary; record compiler flags and versions.
3. Measure size, exposed literals/symbols, correctness, CPU/latency and memory.
4. Independently run *controlled* AI reconstruction trials with fixed model/version/budget/time, prohibited source access and an evaluator with hidden test vectors. Track functional imitation success and attack cost.
5. Under root access, test extraction of process memory and module bypass as a separate axis.
6. Publish measured outcomes and limitations; do not call file-size reduction or missing plaintext symbols 'AI-proof'.

## Current status

Architecture and benchmark measurement scaffolding exist. No root-level enclave isolation or AI reconstruction experiment has been validated. Hardware-backed local confidentiality needs a hardware boundary outside the standard Olares One CPU, with nontrivial integration and physical threat-model limits.
