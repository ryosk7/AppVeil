# Red Lab: baseline static extraction attack

This first attack demonstrates a deliberate **negative security result**: the Veil IR v1 compiler embeds the opcode permutation table directly inside the distributed artifact. A static analyst therefore reads each encoded instruction and recovers every operation mnemonic, independent of seed. This requires neither AI nor root privileges.

Run:

```bash
node bin/appveil.mjs compile-ir examples/veil-ir-score.json --seed 42 > /tmp/score-42.json
node bin/appveil.mjs red-lab-decode /tmp/score-42.json
```

The decoded operation trace is an attack baseline, **not** a successful decompilation to original TypeScript source. It nevertheless falsifies any claim that changing opcode numbers alone conceals program semantics.

Future defensive mechanisms must beat meaningful attacker controls: static trace extraction, runtime instrumentation, AI-assisted function recovery and black-box imitation, each with independent evaluation inputs and fixed budgets. Keep raw private binaries and outputs out of public benchmark storage.

## Full IR recovery (issue #12)

`appveil red-lab-run static-decompile` uses the Red Lab harness (`research/RED_LAB_HARNESS.md`). Each trial generates a hidden challenge, compiles it with a per-trial opcode permutation, gives the attacker only the artifact, and judges the attacker's submitted IR on 1,000 hidden holdout inputs.

The attacker (`src/red-lab-attacks.mjs`) reads the shipped opcode table and inlines the SSA registers back into an expression tree. It uses no defender code.

| Setting | Result |
| --- | --- |
| 200 trials, size 12, seed 1, 1,000 holdout inputs each | **200/200 exact recoveries** (Wilson 95%: 0.981–1.000), mean accuracy 1.0 |

The recovered IR is **structurally identical** to the reference, not merely equivalent on the holdout set (`test/red-lab-static.test.mjs`). Attack cost: milliseconds per artifact, with no AI and no root.

**Conclusion:** Veil bytecode v1 provides no protection against a static attacker. Future formats must be evaluated against this baseline before any protective claim is made.

## Dynamic tracing (issue #13, VM backend)

`appveil red-lab-run dynamic-trace` models a host-root debugger. It attaches the V8 inspector (`node:inspector`) in-process, without modifying defender code. It sets breakpoints in the shipped, readable runtime, and for each executed step it records the operand register indices and the register file over 24 inputs (6 edge values plus 18 pseudo-random). The operation at each step is inferred **only from the observed values** (`out == input`, constant output, `~x`, or which binary operation maps `(x, y)` to `out`). The opcode table and the bytecode format are never read; a test asserts this.

| Setting | Result |
| --- | --- |
| 100 trials, size 12, seed 1, 1,000 holdout inputs each | **100/100 exact recoveries** (Wilson 95%: 0.963–1.000) |

**Conclusion:** even if the opcode table were hidden or encrypted at rest, a host-root attacker who can observe execution recovers the computation. Any confidentiality claim needs an execution boundary the host cannot instrument (Track C), not a different encoding.

The Wasm backend will be traced once it exists (issue #9).
