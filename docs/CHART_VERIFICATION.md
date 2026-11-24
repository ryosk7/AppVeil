# Published chart verification (issue #26)

```sh
node bin/appveil.mjs verify-chart proofy-2.6.19.tgz --resolve [--require-digest] [--affected data/known-affected-images.json]
```

The command reads the chart archive offline, with bounded gzip/tar parsing and path-traversal rejection. It never renders or executes the chart. It collects every image reference: the `image:` section of `values.yaml`, and literal `image:` lines in the templates. It then checks:

- **Tags:** a reference must carry an explicit non-`latest` tag or a digest. With `--require-digest`, every reference must be pinned with `@sha256:`.
- **Known-affected images** (`data/known-affected-images.json`, from `docs/PUBLISHED_RELEASE_VERIFICATION_2026-11-19.md`): matching is by literal tag, by literal digest, and with `--resolve` by the digest the registry currently serves for the tag. `--resolve` uses `docker buildx imagetools inspect`, a read-only manifest query; nothing is pulled or run. A new tag that points at an old affected digest fails.
- **Versions:** `Chart.yaml` `version` must equal OlaresManifest `metadata.version` and `spec.versionName`.
- A digest that cannot be resolved is a failure, not a pass. Exit codes: 0 pass, 2 problems, 1 malformed or execution error.

**What passing means:** the chart deploys images that are not on the affected list. It does **not** mean those images are clean. Audit each digest separately with `inspect-image --layers` and `verify-image-report`. `.github/workflows/verify-published-release.yml` does both, fail-closed.

## Results on the currently published charts (2026-11-25, counts and digests only)

| Chart release | Server image | Resolved digest | Result |
| --- | --- | --- | --- |
| proofy v2.6.18 | `ghcr.io/ryosk7/patentproof:2.6.18` | `sha256:d3a192a4…` | **FAIL**: known-affected Proofy digest |
| proofy v2.6.19 (latest) | `ghcr.io/ryosk7/proofy:2.6.19` | `sha256:b4f049ad7b07afc1b0add00dacb2b8cee997d935a2179a232209c5ff33066a34` | chart check passes: a new digest, not on the affected list. Image audit: see #27 |
| shipboardai v0.4.35 (latest) | `ghcr.io/ryosk7/shipboardai:0.4.35` | `sha256:cb3134ef…` | **FAIL**: known-affected Shipboard AI digest. No newer release exists |

None of the three charts pins any image by digest (docai, aiRuntime and busybox included), so all three fail `--require-digest`.
