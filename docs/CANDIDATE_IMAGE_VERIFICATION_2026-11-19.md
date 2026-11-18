# Local candidate-image verification — 2026-11-19

The production source-map removal changes have been merged into the private application repositories, but those commits do **not** modify previously published GHCR tags.

AppVeil's first-party source-exposure policy was run against **locally rebuilt, unpublished** candidate Docker images in the private source repositories.

| Candidate | Verification run | Total file-based indicators | First-party findings | Policy |
|---|---|---:|---:|---|
| Proofy | [candidate CI](https://github.com/ryosk7/olares-patentproof/actions/runs/44356883569) | 7,611 | **0** | **PASS** |
| Shipboard AI | [candidate CI](https://github.com/ryosk7/Shipboard-AI-Cloud/actions/runs/44356894209) | 7,611 | **0** | **PASS** |

All 7,611 residual file-based indicators in each candidate were located outside the known first-party build directories: 3,679 map files, 2,820 map references, 1,110 TS/TSX files, and 2 .npmrc files. Most originate in transitive dependencies. These remaining indicators should be audited by provenance/necessity before release; the current first-party policy deliberately does not block on vendor packages.

The gate checks `app/apps/server/dist/`, `app/packages/contracts/dist/`, `app/packages/db/dist/`, and `app/web/`. It does **not** inspect historical image layer content, detect every embedded secret, eliminate introspection of shipped JS, or provide confidentiality against a host root administrator.

The final application Dockerfiles remove application maps **in the private build stage, before copying results to the runtime stage**. They also strip the generated `sourceMappingURL` comments from first-party JS.

PRs for ongoing pre-release verification:
- Proofy: [#34](https://github.com/ryosk7/olares-patentproof/pull/34)
- Shipboard AI: [#66](https://github.com/ryosk7/Shipboard-AI-Cloud/pull/66)

**Not a production release:** No candidate image was pushed or tagged as a new public GHCR release, and no Olares Chart was updated by these checks. Older public image digests remain accessible and cannot be made confidential retroactively.

**Not an AI reverse-engineering proof:** This is a deterministic image hygiene gate only.
