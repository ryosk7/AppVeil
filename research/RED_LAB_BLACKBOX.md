# Red Lab: non-AI black-box imitation baseline (issue #14)

**Attacker:** query access to the defender only. It receives no artifact and no runtime. The method (`src/red-lab-blackbox.mjs`) is bottom-up enumerative synthesis over Veil IR v1, pruned by observational equivalence, plus algebraic solving of a single top-level 32-bit constant (`t op c` for `add`, `sub`, `xor`, `mul`, `and` and `or`).

**Budget per trial:** N oracle queries, 1,000 ms wall time, 20,000 terms. The attacker's submitted IR is judged on 1,000 hidden holdout inputs.

Reproduce with `node scripts/red-lab-blackbox-sweep.mjs 30 8`. Measured on `main` at `acc2bb8` plus this change, on an Apple M2 with Node v23.11.0, 30 trials per cell, challenge seeds derived from seed 1:

| Size (ops) | Exact @ 8 queries | Exact @ 32 | Exact @ 128 | Wrong submissions @ 8 / 32 / 128 |
| --- | --- | --- | --- | --- |
| 1 | 28/30 | 28/30 | 28/30 | 0 / 0 / 0 |
| 2 | 22/30 | 22/30 | 22/30 | 0 / 0 / 0 |
| 3 | 18/30 | 18/30 | 18/30 | 1 / 0 / 0 |
| 4 | 16/30 | 16/30 | 16/30 | 0 / 0 / 0 |
| 5 | 10/30 | 10/30 | 10/30 | 2 / 0 / 0 |
| 6 | 5/30 | 5/30 | 5/30 | 3 / 0 / 0 |
| 7 | 6/30 | 6/30 | 6/30 | 2 / 0 / 0 |
| 8 | 5/30 | 5/30 | 5/30 | 2 / 0 / 0 |

Wilson 95% intervals: size 1, [0.787, 0.982]; size 4, [0.361, 0.698]; size 8, [0.073, 0.336].

## Findings

1. **Success falls with function size**, from 93% at one operation to 17% at eight, under this time budget.
2. **More queries did not raise exact recovery.** This attacker is limited by search, not by data. With only 8 queries, though, some submissions fit the examples but are wrong on holdout inputs (overfitting). With 32 or more queries there were none.
3. **This axis is independent of the artifact encoding.** A black-box attacker never sees the bytecode, so opcode permutation, VM interpretation, minification or Wasm cannot change these numbers: the same function compiled any other way yields the same table. Obfuscation is irrelevant to functional imitation. Only limiting or monitoring queries, or making the function itself harder to learn, affects it.
4. **This is a floor, not a ceiling.** The attacker is weak: no AI, one second, no deeper constant solving. Failing against it says nothing about stronger attackers (#25).
