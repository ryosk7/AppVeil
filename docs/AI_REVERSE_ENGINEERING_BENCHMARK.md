# Reverse engineering benchmark protocol

This project **has not demonstrated AI-resistant software protection**. The reproducible baseline only reports artifact size, SHA-256, visible strings and other mechanical features.

Run `bash scripts/benchmark-local.sh` on a host with Node.js and clang. It generates JS, a whitespace-reduced JS variant, a native object and, where supported by clang, a Wasm module from a synthetic algorithm. Results go to untracked `benchmark-results.json`. The JS and C source use equivalent fixed-width unsigned arithmetic but equivalence across the 32-bit range should be independently verified.

These output measurements **do not measure** the ability of an AI model to recover logic. For a real AI experiment, keep hidden functional test vectors, fixed model identifier/version, exact time/token/tool budgets, and blind assessors. Measure task success and resource cost separately; publish confidence intervals and failures. A single missing marker or smaller binary proves nothing about source secrecy.

Don't include private Proofy/Shipboard algorithms in this public test. Do not expose secrets in public CI artifacts.
