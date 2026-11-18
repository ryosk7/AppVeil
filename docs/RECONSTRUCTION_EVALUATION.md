# AI functional reconstruction evaluation (first iteration)

## What is implemented

`src/reconstruction-eval.mjs` provides a deterministic synthetic reference oracle, and a scorer that checks a candidate's **predicted outputs** against held-out inputs. It does not run untrusted generated code, access any AI model, or claim to measure AI-resistant confidentiality.

### Experiment design

1. Generate held-out uint32 inputs privately and save as `inputs.json` (array of numbers).
2. Provide only a compiled artifact and a fixed development budget to an AI system. Do not provide the original algorithm source or evaluation outputs. For the current repo's synthetic example, the source is public, so it is only suitable for wiring checks and not a blinded security trial.
3. Have the candidate submit JSON output predictions for every evaluation input, or evaluate a candidate in a separately isolated environment you control.
4. Invoke `node bin/appveil.mjs evaluate-reconstruction predictions.json inputs.json`.
5. Record exact model, tools, available time/tokens, trial count, artifact digest, runtime, test vector distribution, and reconstruction accuracy.

Do not put real proprietary source, credentials or confidential held-out tests into the public repo. Never execute arbitrary model-submitted code on the normal CI runner or on an Olares system containing user data.

### Interpretation

Even 0% predicted-output success on one distribution, task, or model version does not imply that the protected implementation is unrecoverable. It may show poor prompting, insufficient budget, or unfamiliar binary format. Repeat with multiple independent attackers and distribution shifts.
