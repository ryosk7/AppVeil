# Local AI-assisted artifact reconstruction experiment (experimental)

AppVeil can ask a locally running [Ollama](https://ollama.com/) model to predict the outputs of a **synthetic** unsigned-32-bit function, based solely on a short artifact. It sends evidence only to `http://127.0.0.1:11434/api/generate`, and does not run model-generated source code.

## Run on an Olares One / development workstation

1. Install a local coding model in Ollama and start the local daemon. Keep the daemon bound to loopback and avoid proxying it to an external model provider.
2. Generate synthetic artifacts with `bash scripts/benchmark-local.sh` (the script cleans up temporary files afterward). Alternatively, compile `examples/reverse-engineering/algorithm.c` with `clang -O2 -c -o /tmp/synthetic.o examples/reverse-engineering/algorithm.c`.
3. Call `node bin/appveil.mjs local-ai-trial /tmp/synthetic.o <installed-local-model>`.
4. Record the model identifier and digest, model quantization, available context, artifact SHA-256, latency, score, and tooling/budget. Compare the same algorithm across plain JS, minified JS, Wasm and native object builds.

**Security limitations**

- It is *not* a blinded benchmark: the reference JS and C are publicly present in this repository, and a pretrained model may have seen related examples.
- The code currently scores a single deterministic input set; a model could overfit or guess.
- An accuracy of 0% does not establish that an implementation is secret or cannot be reconstructed.
- The HTTP client connects to a loopback address only, but cannot prove that the local service is not forwarding to a remote model.
- Do not provide genuine proprietary artifacts in a public CI run or expose private documents or secrets in prompt logs.
- This test checks black-box functional imitation only, not memory extraction, instrumentation, or algorithm recovery.

The real research phase requires independently withheld challenge algorithms and inputs, multiple model versions/attack budgets, and tests that also permit decompilers or runtime instrumentation.

## Hidden-challenge AI trials through the Red Lab harness (issue #25)

`node bin/appveil.mjs red-lab-run local-ai --model <installed-model> [--defender veil-vm-v1|veil-wasm-v1] [--trials 30] [--size 8] --full`

This addresses the limitations above. Each trial uses a **freshly generated hidden challenge** (`research/RED_LAB_HARNESS.md`). The model receives only the attacker workspace artifact; the prompt is built by `buildPrompt`, and a test asserts that it contains no reference or holdout data. The model's reply is parsed as a Veil IR document, which is **data**, and judged on 1,000 hidden holdout inputs. Generated code is never run.

Each result records:
- the model id, digest, quantization, parameter size and family (from the local `/api/tags`)
- token use and wall time
- the trust assumption that the loopback endpoint does not forward data, which is not verified

A missing endpoint or model is reported as **`not-checked`** with exit 1; it is never recorded as a failed attack. Compare the results with the non-AI baselines: static and dynamic attacks recover 100% (`research/RED_LAB_BASELINE.md`), and black-box enumeration results are in `research/RED_LAB_BLACKBOX.md`.

**Status (2026-11-25): no trial has been run.** There is no Ollama installation or local model on the development machine, and none on CI. The pipeline is tested end to end against a fake loopback model (`test/red-lab-ai.test.mjs`). That test checks scoring, metadata, prompt isolation, garbage and code replies, and `not-checked` handling. Running real trials needs an installed local model, a choice of model and quantization, and a fixed token and time budget. Results must be published with confidence intervals, including failures.
