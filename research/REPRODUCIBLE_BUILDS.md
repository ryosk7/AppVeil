# Reproducible builds and build manifest (issue #18)

```sh
node bin/appveil.mjs build examples/ts/score.ts out/ --seed 7 --optimize   # writes ir.json, bytecode.json, manifest.json
node bin/appveil.mjs verify-build out/ examples/ts/score.ts                 # exit 0 reproducible, 2 not
```

A build is a pure function of **(source bytes, compiler name and version, options)**.

- **Serialization:** every JSON artifact is canonical JSON (keys sorted recursively, no whitespace) plus `\n`. Wasm modules come from the deterministic binary emitter.
- **Manifest:** compiler `{name, version}`, source `{kind, sha256, bytes}`, options `{seed, optimize}`, the IR version, the TS output map, optimizer statistics, and the SHA-256 and size of every output.
- **Excluded by construction (nondeterminism sources):** timestamps, absolute paths, hostnames, environment variables, locale and time zone, `Math.random`, filesystem iteration order, and object key order in the source. Source key order changes only the source digest, not any output digest, because outputs are canonical. A test asserts this.
- `build` refuses to overwrite an existing output directory. `verify-build` checks each output against the manifest, then **rebuilds from the source** and requires byte identity.

## Evidence

- **Golden digests:** `test/golden/build-digests.json` holds the digests of 6 corpus builds (`test/golden/corpus.mjs`: v1 and v2 IR, TypeScript, with and without optimization, several seeds). They were generated on macOS arm64 with Node v23.11.0. CI checks them on Linux x64 with Node 20 and with Node 24, so a pass is a cross-OS and cross-Node-version reproducibility check.
- Two `build` runs in separate processes, with different working directories, `TZ` and `LANG`, produce byte-identical directories. Tampering with an output, or changing one source byte, is detected.
- `.gitattributes` pins LF line endings for the examples, schemas and golden files.

## Changing the compiler

An intentional change to compiler output must regenerate the golden file with `node scripts/update-golden-builds.mjs` and **say so in the PR**. A changed golden digest means every downstream build changes. An unintentional change makes CI fail.

## Not guaranteed

Reproducibility lets an auditor confirm that an artifact matches its source and options. It provides no secrecy: anyone with the artifact can still recover the program (`research/RED_LAB_BASELINE.md`).
