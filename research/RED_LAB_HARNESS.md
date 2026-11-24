# Red Lab harness (research, issue #11)

`src/red-lab-harness.mjs` runs reproducible attack trials against defender artifacts. Results are **empirical**: they describe one attacker with one budget against one challenge distribution. They are not security proofs.

## Separation of roles

| Role | Receives | Never receives |
| --- | --- | --- |
| Attacker | `attackerDir/artifact.json` (defender output, without the reference digest), `task.json` (budget) and, for black-box attacks, a query-counted oracle function | reference IR, holdout inputs, holdout answers |
| Judge | `judgeDir/reference.json`, `holdout.json`, `manifest.json` | — |

- `attackerDir` and `judgeDir` are separate `mkdtemp` roots. `assertAttackerIsolation` checks every attacker file for the reference expression and the holdout data. The check is structural, so reformatting or embedding the data does not hide it.
- Attackers submit **data only**: a Veil IR v1 document (`kind: 'ir'`) or output predictions (`kind: 'predictions'`). The harness never executes attacker-supplied code. Any other submission kind scores 0.
- The challenge generator (`generateChallenge`) has its own PRNG (splitmix32) and grammar. It shares no code with the compiler or the test helpers, so defender code cannot shape the challenge distribution.

## Result schema (v1)

`attackClass` (`static` / `dynamic` / `black-box` / `ai`), `attacker`, `defender`, `challenge {seed, size, referenceDigest}`, `artifactDigest`, `budget` and `used` (`queries`, `timeMs`, `tokens`), `holdout {count, digest}`, `correct`, `accuracy`, `exactOnHoldout`, `error`, `interpretation`. `summarize()` adds a success rate with a Wilson 95% interval.

## Interpretation

A successful attack shows that the defense **failed** in that setting. A failed attack does **not** show that the defense works: the cause may be the attacker's skill, its budget, or the challenge distribution. Attack classes are reported separately: static analysis, dynamic tracing, black-box imitation and AI-assisted recovery.
