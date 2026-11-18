# Olares application image audit — 2026-11-19

## Verification status

**Static Dockerfile inspection complete; published GHCR image extraction NOT performed.**
The GitHub source repositories were inspected; this report does not claim to have downloaded or scanned either released image.

Sources:
- Proofy: https://github.com/ryosk7/olares-patentproof/blob/main/docker/Dockerfile.server (private)
- Shipboard AI: https://github.com/ryosk7/Shipboard-AI-Cloud/blob/main/docker/Dockerfile.server (private)

Both final stages copy compiled `apps/server/dist`, `packages/contracts/dist`, `packages/db/dist`, `packages/db/migrations`, `packages/db/sql`, and `apps/web/dist`. Both copy `.npmrc` into the runtime stage, install production npm dependencies, and run as UID 1000. Source `.ts` files are not explicitly copied into final stages; transitive dependencies and source maps inside generated artifacts must still be checked in actual images. BuildKit secret mount for npm token is preferable to baking tokens into image layers.

**Static concern**: unnecessary `.npmrc` in runtime image. Remove it after confirming runtime installation requirements. No claim that credentials are leaked: contents were not independently audited for tokens.

## Reproducible image inspection (Docker host)

These commands require access to the public image registry and Docker:

```bash
docker pull ghcr.io/ryosk7/patentproof:2.6.18
docker pull ghcr.io/ryosk7/shipboardai:0.4.33
node bin/appveil.mjs inspect-image ghcr.io/ryosk7/patentproof:2.6.18 --json --strict > proofy-audit.json
node bin/appveil.mjs inspect-image ghcr.io/ryosk7/shipboardai:0.4.33 --json --strict > shipboard-audit.json
```

The exact image tags may differ from current Chart values; confirm before running. The scanner copies the container root filesystem without starting the container. It has no layer-history analysis, cannot detect runtime code exfiltration, and its path-based rules can flag legitimate dependency files (especially node_modules). Treat reports as triage, not proof of confidentiality.

## Follow-up checks
- Compare the pinned image digests with the OAC values; avoid mutable tags.
- Inventory `.js`, `.map`, `.ts`, `.env*`, `.npmrc`, license and key-like material, including runtime dependencies.
- Test `--strict` against production images with documented allowlist rules (not implemented yet).
- Inspect image history and config for credential leakage separately.
- Never post secret scan matches or tokens to the public repo.
