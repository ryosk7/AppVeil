# Published Olares release verification — 2026-11-19

## Finding: both published images still contain application source maps

AppVeil pulled both currently Chart-referenced public image tags in [GitHub Actions run 44499878494](https://github.com/ryosk7/AppVeil/actions/runs/44499878494). The workflow exported container root filesystems, ran the AppVeil image inspector, and applied `olares-first-party-source-exposure-v1`.

| Check | Proofy | Shipboard AI |
|---|---|---|
| Source repository | [ryosk7/proofy](https://github.com/ryosk7/proofy) | [ryosk7/Shipboard-AI-Cloud](https://github.com/ryosk7/Shipboard-AI-Cloud) |
| Chart server reference | `ghcr.io/ryosk7/proofy:2.6.18` | `ghcr.io/ryosk7/shipboardai:0.4.35` |
| Published image digest | `sha256:d3a192a4aed14cb91b9963469c9af7071ffd3668a51eb3482895971a10d91345` | `sha256:cb3134ef90b3953c9f1dc0af0955bbae817955723e60e1eb6b36a0fb81ea0eb7` |
| First-party source-map files | 88 | 229 |
| First-party source-map reference comments | 88 | 229 |
| First-party source maps embedding source bodies | 16 | 72 |
| Production image policy | **FAIL** | **FAIL** |

The Proofy registry path changed from `ghcr.io/ryosk7/patentproof:2.6.18` to `ghcr.io/ryosk7/proofy:2.6.18`, but the digest remains **identical** to the earlier audited image. Shipboard AI also retains the prior audited digest.

### Publication timing

- Latest published [Proofy chart release v2.6.18](https://github.com/ryosk7/proofy-releases/releases/tag/v2.6.18): 2026-11-18 06:08 UTC.
- Latest published [Shipboard AI chart release v0.4.35](https://github.com/ryosk7/shipboardai-releases/releases/tag/v0.4.35): 2026-11-18 16:44 UTC.
- [Proofy source-map removal PR #33](https://github.com/ryosk7/proofy/pull/33) merged 2026-11-18 17:08 UTC.
- [Shipboard AI source-map removal PR #65](https://github.com/ryosk7/Shipboard-AI-Cloud/pull/65) merged 2026-11-18 17:08 UTC.
- Candidate-image scanning CI was merged after that.

The latest published OAC releases thus predate the source-map fixes. Changing a chart reference or registry repository name does not eliminate original source maps present in an old image digest.

## Next release acceptance criteria

1. Build new versioned Docker images from the merged and verified source on protected infrastructure. Do not overwrite old public tags.
2. Run the candidate image verification workflow or `appveil inspect-image` plus `verify-image-report`. **Require policy pass** with zero first-party map/reference/source-body findings.
3. Check OCI image layer history and image config, especially build secrets; current AppVeil filesystem scans do not inspect deleted layer contents.
4. Publish the new Docker image and record its new digest; ensure it differs from the above affected digests.
5. Update the Olares Chart to the new tag or immutable digest and publish new `.tgz` releases.
6. Pull the **published** image by the exact Chart reference and run AppVeil policy again; exercise API, worker, migration and web routes on Olares.

No production images were modified during this verification. Previously published code cannot be retroactively retracted.

A passing image hygiene check still does not prevent reverse engineering of compiled JavaScript or imply confidential execution.
