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
