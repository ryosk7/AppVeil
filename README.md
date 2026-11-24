# AppVeil

Experimental open-source tooling and research for protecting commercial TypeScript applications deployed on **Olares** while keeping application execution local.

> **Security status: experimental.** AppVeil v0.1.0 does not make code unreadable or prevent reverse engineering. An Olares One administrator can generally inspect distributed container files and running processes. No guarantee of complete secrecy is made.

## Current feature: inspect released artifacts

AppVeil starts by addressing a measurable risk: accidentally shipping source files, source maps and configuration material in Docker images. It does **not** yet implement code obfuscation, a secure runtime, licensing, confidential computing, or OAC generation.

Requirements: Node.js 20+; Docker for image inspection.

```sh
git clone https://github.com/ryosk7/AppVeil.git
cd AppVeil
npm test

# Scan a local build directory
node bin/appveil.mjs inspect /path/to/dist --json --strict

# Inspect a local Docker image without running it
docker pull ghcr.io/ryosk7/shipboardai:0.4.33
node bin/appveil.mjs inspect-image ghcr.io/ryosk7/shipboardai:0.4.33 --strict
```

In strict mode, high/critical indicators exit with status 2. An empty report is **not** proof of security. Scan your own images; image extraction requires disk space and access to Docker.

### Exit status contract

| Status | Meaning |
| --- | --- |
| `0` | Success, and no documented policy violation |
| `1` | Usage error (unknown command or option, missing option value, wrong argument count), malformed input, or execution error (for example Docker or Ollama unreachable) |
| `2` | Documented policy violation: `--strict` with high/critical findings, `verify-image-report` FAIL, `check-olares-image` FAIL |

Every command follows this contract (`test/cli-contract.test.mjs`). An error is never reported as `0` or `2`, and exit `0` is not proof of security.

## New research and audit tools

```bash
# Inspect a Dockerfile without pulling its image
node bin/appveil.mjs audit-dockerfile docker/Dockerfile.server --json

# Measure observability of *synthetic* JS, Wasm and native artifacts
bash scripts/benchmark-local.sh

# Measure pre-existing build artifacts, not their security
node bin/appveil.mjs benchmark path/to/a.js path/to/module.wasm --marker somePublicSymbol

# Score numeric predictions from an independent reconstruction trial
node bin/appveil.mjs evaluate-reconstruction predictions.json inputs.json

# Optional: ask a locally running Ollama model to reconstruct a tiny synthetic artifact
node bin/appveil.mjs local-ai-trial /tmp/synthetic.o <installed-local-ollama-model>
```

- [Actual Proofy & Shipboard AI public image audit results (2026-11-19)](docs/IMAGE_AUDIT_RESULTS_2026-11-19.md)
- [Static image audit and Dockerfile findings](docs/IMAGE_AUDIT.md)
- [Reproducible AI reverse-engineering experiment protocol](docs/AI_REVERSE_ENGINEERING_BENCHMARK.md)
- [Functional reconstruction scoring protocol](docs/RECONSTRUCTION_EVALUATION.md)
- [Run a local-only AI reconstruction trial using Ollama](docs/LOCAL_AI_TRIAL.md)
- [Verified unpublished candidate image results](docs/CANDIDATE_IMAGE_VERIFICATION_2026-11-19.md)
- [Published release audit: old image digests remain affected](docs/PUBLISHED_RELEASE_VERIFICATION_2026-11-19.md)
- [Fail-closed GitHub Actions gate for newly published image](https://github.com/ryosk7/AppVeil/actions/workflows/verify-published-image.yml)
- [Production image release verification gate](docs/RELEASE_GATE.md)
- [Olares Chart reference & image release checklist](docs/OLARES_IMAGE_RELEASE.md)
- [Local confidential runtime architecture](docs/CONFIDENTIAL_RUNTIME.md)
- [Manually run the public-image audit workflow](https://github.com/ryosk7/AppVeil/actions/workflows/image-audit.yml) after confirming the image tag. This workflow reports file-based indicators, not evidence of confidentiality.

## Roadmap

1. **Artifact hygiene**: source map and source leakage inspections; extend to layers, common secret patterns, and signed attestations.
2. **Olares compatibility**: validate OAC/Helm image references, image architecture, versions and release checks without reimplementing Olares Market.
3. **Reverse engineering benchmark**: measure AI-assisted reconstruction against JS, minified bundles, Wasm and native modules under an explicit threat model.
4. **Confidential runtime research**: evaluate the real hardware trust boundaries of Olares One before claiming any protection against the host administrator. Keep confidential modules local; use an external on-premises isolated execution device only if a genuine hardware security boundary is needed.

See [security assumptions and limitations](docs/SECURITY.md).

## Design principles

- Reuse Olares OAC, Market, existing container distribution, and Merchant where applicable.
- Never require publishing proprietary application source code.
- Do not claim that obfuscation protects a secret from a root-level administrator.
- Do not send proprietary code or user documents to an external server as part of protection.
- Keep the AppVeil repository public and self-contained; no private Proofy or Shipboard AI source code is included.

## License

MIT. See [LICENSE](LICENSE).
