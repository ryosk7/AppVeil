# Public GHCR image audit — 2026-11-19

Status: **actual public image filesystem scans completed** through [GitHub Actions run 44349799979](https://github.com/ryosk7/AppVeil/actions/runs/44349799979). Both matrix jobs succeeded. Counts below are findings in exported image root filesystems, not claims that all these files contain proprietary secrets.

| Detected indicator | Proofy | Shipboard AI |
| --- | ---: | ---: |
| Total scanner findings | 7,849 | 8,131 |
| `.map` files | 3,829 | 3,970 |
| JavaScript source-map references | 2,908 | 3,049 |
| `.ts` / `.tsx` files | 1,110 | 1,110 |
| `.npmrc` files | 2 | 2 |
| First-party `apps/server/dist` maps | 54 | 117 |
| First-party `packages/contracts/dist` maps | 10 | 30 |
| First-party `packages/db/dist` maps | 8 | 10 |
| Application `web` maps | 16 | 72 |
| **First-party application map count** | **88** | **229** |
| **First-party maps containing original source text** | **16** | **72** |

Source map references at the matching four first-party directories were also present. A large share of all findings originates in vendor packages (`node_modules`). The 1,110 TypeScript source files in each full image scan appear in transitive dependencies, not the application's own `src` tree.

Pinned image references at scan time:
- Proofy: `ghcr.io/ryosk7/patentproof:2.6.18`, manifest digest `sha256:d3a192a4aed14cb91b9963469c9af7071ffd3668a51eb3482895971a10d91345`
- Shipboard AI: `ghcr.io/ryosk7/shipboardai:0.4.33`, manifest digest `sha256:3c46a52185b3485931f28561ed3164f479408ef8d04a97ff88d19be8894f30af`

A follow-up metadata-only scanner checked whether first-party maps contain nonempty `sourcesContent` (without printing the source). It found **16 Proofy frontend maps** and **72 Shipboard AI frontend maps** with embedded original source text. This does not establish whether the backend maps embed source text; the sampled first-party backend maps did not trigger the same rule. The corresponding private source repositories have `sourceMap: true` in `tsconfig.base.json`; the Dockerfile copies generated `dist` directories to the final stage. This explains why generated map files survive in production images.

## Remediation PRs merged; release image verification still required

- Proofy: [PR #33](https://github.com/ryosk7/olares-patentproof/pull/33)
- Shipboard AI: [PR #65](https://github.com/ryosk7/Shipboard-AI-Cloud/pull/65)

Both PRs were merged on 2026-11-19 JST. They disable production frontend maps and remove application map files in the private build stage before copying into the runtime stage. **Merging these changes does not change an already-published image digest.**

A follow-up GHCR scan of `ghcr.io/ryosk7/shipboardai:0.4.35` (digest `sha256:cb3134ef90b3953c9f1dc0af0955bbae817955723e60e1eb6b36a0fb81ea0eb7`) still showed **229 first-party maps and 72 embedded-source maps**; this tag is not proven to have been rebuilt from the merged fix. Proofy `2.6.18` remained on its previous digest and had **88 first-party maps and 16 embedded-source maps**. See [re-audit GitHub Actions run](https://github.com/ryosk7/AppVeil/actions/runs/44355900571).

A candidate-image verification gate has been proposed in [Proofy PR #34](https://github.com/ryosk7/olares-patentproof/pull/34) and [Shipboard AI PR #66](https://github.com/ryosk7/Shipboard-AI-Cloud/pull/66). It must pass before a new public image is released.

## Priority remediation recommendations

1. For both applications, create production-only TypeScript build configs overriding `sourceMap: false` and `inlineSourceMap: false`, or remove maps from the runtime stage; keep maps privately in restricted debug artifacts if needed.
2. Verify the final production image does not include application maps or map references (and optionally prune vendors after assessing compatibility). Add an exact-scope regression gate.
3. Remove the runtime `.npmrc` copy only after verifying runtime package installation behavior. Check for embedded credentials separately without publishing them.
4. Do not assume map deletion makes JavaScript unreadable; runtime JS is still extractable by image recipients.
5. Treat prior public images as permanently obtainable. Rotate credentials if any were truly embedded (not established here).

**The audit itself did not publish, retag, or change any production Docker image.** Public image audit artifacts contain file-path findings and digests; avoid publishing source-map bytes or credential values.
