# Production image first-party source exposure gate

Use `appveil verify-image-report <image-audit.json>` after generating a JSON report using `appveil inspect-image`. Exit 0 indicates **no detected first-party build-source indicators** in the exported container filesystem. Exit 2 means a violation was found. Exit 1 means an execution or format error.

The default policy checks specific paths in the Olares application layout: `/app/apps/server/dist`, `/app/packages/contracts/dist`, `/app/packages/db/dist`, and `/app/web`. It flags app source maps, sourcemap references, TypeScript sources, private-key-like filenames, env files, and embedded sources. It deliberately excludes third-party `node_modules` from this policy, though the scanner reports those separately.

Example on a Docker-capable workstation:

```sh
docker pull ghcr.io/ryosk7/shipboardai:<new-version>
node bin/appveil.mjs inspect-image ghcr.io/ryosk7/shipboardai:<new-version> --json > image-audit.json
node bin/appveil.mjs verify-image-report image-audit.json
```

**Important**: this policy inspects the exported final filesystem, not the full immutable image layer history. Files added and later deleted in the final stage may remain recoverable from an older layer. For production images, remove unwanted artifacts in the **build stage before** copying to the final stage, as the merged fixes are designed to do.

No previous image version can be made secret retroactively. Confirm a new immutable image digest is referenced by the Olares Chart before a security-related release announcement. An OAC upload without building a new image does not remove leaked source maps.
