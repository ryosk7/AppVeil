# Published release re-audit — 2026-11-25 (issue #27)

This re-audit was run with `.github/workflows/verify-published-release.yml`, the fail-closed gate added in #50. The gate checks:
- the chart's image references, with tags resolved to registry digests and compared with the known-affected list
- the exact server image's final filesystem
- every image layer, including files deleted or overwritten later, plus config and history

Only metadata is recorded.

| | Proofy v2.6.19 | Shipboard AI v0.4.35 |
| --- | --- | --- |
| Workflow run | [45424606777](https://github.com/ryosk7/AppVeil/actions/runs/45424606777) **success** | [45424613725](https://github.com/ryosk7/AppVeil/actions/runs/45424613725) **failure** (expected) |
| Chart server image | `ghcr.io/ryosk7/proofy:2.6.19` | `ghcr.io/ryosk7/shipboardai:0.4.35` |
| Index digest | `sha256:b4f049ad7b07afc1b0add00dacb2b8cee997d935a2179a232209c5ff33066a34` (new) | `sha256:cb3134ef…`, **known-affected** |
| Chart check | pass | **FAIL**, so the image steps did not run |
| First-party final-filesystem policy | **pass, 0 violations** | not reached |
| First-party layer policy (deleted and overwritten files included) | **pass, 0 violations**; scan complete | not reached |
| Config and history secret-like names | none | not reached |

Non-first-party layer findings for Proofy 2.6.19, all in vendor packages and all present in the final filesystem: 3,679 source maps, 2,820 `sourceMappingURL` references, 1,110 TypeScript files, 2 `.npmrc`, 4 private-key blocks and 3 secret-like assignments. Vendor packages are outside the first-party policy. They may still be worth reviewing, as noted in #8.

## The running deployment is the audited image

The digest chain was resolved with read-only `docker buildx imagetools inspect` and checked against `kubectl` and `crictl` on the device:

chart `proofy-2.6.19.tgz` → tag `2.6.19` → OCI index `sha256:b4f049…` → linux/amd64 manifest `sha256:bf4428e8…` → config `sha256:1864796d6b2b…`. That config equals the image ID of the running `api` and `worker` containers on Olares One. The CI audit ran on linux/amd64, so it scanned the same platform image that is deployed.

Health on the device, read-only, 2026-11-25:
- `ApplicationManager proofy-shared-proofy` is `running`, and every pod is Ready with 0 restarts.
- The `migrate` initContainer finished (`applied: none`).
- The API and worker logged 0 error lines in the last 24 h.
- The web root returns 200 inside the cluster. `/api/health` returns 401 because identity comes from the Olares gateway.
- **Authenticated, read-only check in the user's browser session (2026-11-25):**
  - The app home page (`https://<app>.<zone>/`) renders with the user's recent jobs.
  - `GET /api/me` → 200 and `GET /api/runs?limit=5` → 200. All page assets returned 200, and the browser console showed no errors.
  - The recent-runs list shows completed proofing runs, the latest on 2026-11-20, after the 2.6.19 deployment. That indicates the worker processed jobs on this release.
  - No in-app action was taken: no upload, no new run and no settings change. **Not exercised:** starting a new job, write paths of the API, and downloading results.

## Status

- **Proofy:** release 2.6.19 meets the release acceptance criteria of `docs/PUBLISHED_RELEASE_VERIFICATION_2026-11-19.md`. The authenticated routes were checked read-only. Write paths were not exercised, because that would mean taking actions in the user's account. It is a new digest, not affected, and both the first-party final-filesystem policy and the layer policy pass. The affected image `sha256:d3a192a4…` (2.6.18 and earlier) remains published and cannot be retracted retroactively.
- **Shipboard AI:** **blocked.** The latest chart, v0.4.35, still deploys the affected digest. A new image built from the merged source-map fix (Shipboard-AI-Cloud PR #65) and a new chart release are needed. Then re-run the workflow with `app=shipboardai tag=<new>`.

Passing hygiene checks does not prevent reverse engineering of the shipped JavaScript.
