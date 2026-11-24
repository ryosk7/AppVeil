# Protecting a first-party core library (ragturbo): what is achievable, and the ceiling

This is the honest answer to "protect the core technology comprehensively". It is organised by **who the attacker is**, because that is what decides what is possible. `ragturbo` (`@ryosk7/ragturbo`) is the shared AI foundation of Proofy and Shipboard AI, shipped inside each app image's `node_modules` and as the `ragturbo-docai` image.

## The ceiling (measured, not assumed)

AppVeil's own Red Lab and device evidence establish the limit:
- Opcode permutation, VM interpretation and Wasm encoding are recovered 100% by static and dynamic attacks (`research/RED_LAB_BASELINE.md`).
- A software secret module's keys are extracted from memory by ptrace-level access (`research/RED_LAB_EXTRACTION.md`).
- Olares One has no SGX/TDX/TME (`docs/OLARES_ONE_HW_EVIDENCE_2026-11-24.md`), and every surveyed on-prem hardware boundary is defeated by the physical owner (`research/HARDWARE_ISOLATION_SURVEY.md`).

**Therefore: the Olares administrator can read ragturbo's compiled code, and no software technique in this repository changes that.** Against that one attacker, protection is a **licensing and contractual** boundary, not a technical one. Claiming otherwise is the overclaim `agent.md` forbids. Everything below is about the attackers who are *not* that administrator, where cost can genuinely be raised.

## Attacker-tiered protection

| Attacker | Can we raise their cost? | How (achievable today) |
| --- | --- | --- |
| Someone who pulls the public image, or a competitor who installs the app | **Yes, materially** | 1. Minimise the shipped package (below). 2. Keep secret logic server-side only, never in `/app/web`. 3. Minify compiled JS (raises reading cost; not a barrier). |
| Accidental leak (source maps, declarations, raw source) | **Yes, fully** | The exposure policy below fails the build if non-runtime artifacts ship. |
| App user in the browser | **Yes** | Nothing secret in client bundles; enforced by the first-party source-exposure policy. |
| Host root / physical owner (the Olares administrator) | **No (technical)** | Licensing, contract, and — only if ever justified — moving a *small* critical kernel off the device, which conflicts with local-first execution. |

## The new technology in this PR: first-party package exposure policy

`node bin/appveil.mjs audit-package-exposure <app-root> --scope @ryosk7 [--json] [--strict]` (and `auditFirstPartyExposure` in `src/package-exposure.mjs`).

The existing image policy (`src/image-policy.mjs`) deliberately excludes `node_modules`, so a first-party library published to a private registry was never checked. This analyzer walks the installed copies of configured first-party **scopes** and flags runtime-unnecessary artifacts per package: `.d.ts` declarations, source maps, raw `.ts`, Python sources, `.proto`, build config. It is metadata only (paths and counts, never contents), bounded, and does not follow symlinks. Under `--strict` it exits 2 when a first-party package leaks declarations, maps, TS or Python.

### Measured on the live Proofy 2.6.19 image (2026-11-25, read-only, counts only)

`@ryosk7/ragturbo` in `/app/node_modules`:

| Artifact | Count | Runtime-needed? |
| --- | --- | --- |
| compiled `.js` | 62 | yes |
| `.d.ts` declarations | 62 (~176 KB) | **no** — reveal the full typed API surface |
| Python sources | 34 | runtime-needed only in `ragturbo-docai`, not in the Node image |
| `.proto` | 3 | no (generated code is enough at runtime) |
| source maps / raw `.ts` | 0 | already clean |

The declarations alone hand a reader the exact shape of the core library's API and types. They are not loaded at runtime in the Node image.

## Recommended build change (ragturbo repo, out of scope for this PR)

In ragturbo's `package.json`, publish only runtime files (`"files": ["dist/**/*.js"]` or an `.npmignore` excluding `**/*.d.ts`, `src/`, `python/` from the Node package and `**/*.map`), or add a prune step in the app Dockerfiles' build stage before copying `node_modules` into the final image. Then add `audit-package-exposure --scope @ryosk7 --strict` to the release gate so a regression fails the build. This removes ~176 KB of declarations, 34 Python files and the protos from the image for every non-root reader.

## What this is not

It does not make the compiled JavaScript unreadable, and it does not protect against the Olares administrator. It reduces the attack surface for everyone else and prevents accidental source leakage — real, measurable, and honestly bounded.
