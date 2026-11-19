# Red Lab: baseline static extraction attack

This first attack demonstrates a deliberate **negative security result**: the Veil IR v1 compiler embeds the opcode permutation table directly inside the distributed artifact. A static analyst therefore reads each encoded instruction and recovers every operation mnemonic, independent of seed. This requires neither AI nor root privileges.

Run:

```bash
node bin/appveil.mjs compile-ir examples/veil-ir-score.json --seed 42 > /tmp/score-42.json
node bin/appveil.mjs red-lab-decode /tmp/score-42.json
```

The decoded operation trace is an attack baseline, **not** a successful decompilation to original TypeScript source. It nevertheless falsifies any claim that changing opcode numbers alone conceals program semantics.

Future defensive mechanisms must beat meaningful attacker controls: static trace extraction, runtime instrumentation, AI-assisted function recovery and black-box imitation, each with independent evaluation inputs and fixed budgets. Keep raw private binaries and outputs out of public benchmark storage.
