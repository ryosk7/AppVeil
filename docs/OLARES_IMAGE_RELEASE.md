# Olares release: verify an image was actually replaced

Merging source-map-removal code does not update an already published Docker image. The Olares Application Chart contains an `image.server` reference and should point to a **new, audited release**, ideally by immutable digest.

## AppVeil CLI

```bash
# Run against an application repo after a candidate image was successfully scanned:
node /path/to/AppVeil/bin/appveil.mjs check-olares-image charts/proofy/values.yaml --previous ghcr.io/ryosk7/patentproof:2.6.18
node /path/to/AppVeil/bin/appveil.mjs check-olares-image charts/shipboardai/values.yaml --previous ghcr.io/ryosk7/shipboardai:0.4.35
# Stronger: additionally require @sha256:... digest pinning
node /path/to/AppVeil/bin/appveil.mjs check-olares-image charts/proofy/values.yaml --require-digest
```

This compares the text reference and detects unchanged or unpinned image references. **It cannot verify** the referenced image exists, was freshly built, passed the candidate image scan, contains the intended commit, or was delivered to Olares.

## Safe publishing sequence

1. Build a new, unpublished Docker candidate from the merged source.
2. Run `inspect-image` and `verify-image-report`, confirm zero first-party source maps and references.
3. Inspect Docker image history and config separately for build-time credentials. Do not assume a final filesystem scan covers older image layers.
4. Push a newly versioned tag (do not overwrite an old public tag); note the manifest digest.
5. Update the OAC Chart's `image.server` with the new tag or immutable digest and rerun Helm/Olares installation tests.
6. Publish a new OAC package; old public images may remain accessible indefinitely.

Proofy's source repository is now [ryosk7/proofy](https://github.com/ryosk7/proofy), renamed from `ryosk7/olares-patentproof`. The image name `ghcr.io/ryosk7/patentproof` is a different identifier and remains unchanged unless deliberately migrated.

## As observed 2026-11-19

- Proofy chart: `ghcr.io/ryosk7/patentproof:2.6.18`
- Shipboard AI chart: `ghcr.io/ryosk7/shipboardai:0.4.35`

Both references were also used in historical scans with first-party maps. **Do not treat a merged PR or passing build-only candidate as proof that those public tags are now protected.**
