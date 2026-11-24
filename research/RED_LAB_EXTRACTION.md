# Red Lab: key and material extraction from a software secret module (issue #24)

**Expected negative result, demonstrated before any hardware boundary is evaluated.** It is required by #24 and by `agent.md` §5 (Track D: include simple attacks).

## Setup (synthetic data only, in an isolated test process)

- **Target:** `test/helpers/secret-module-child.mjs`, a Node process modeling a software secret module.
  - It loads an Ed25519 private key from a PEM file, as typical software does, and keeps a synthetic secret (`APPVEIL-SYNTHETIC-SECRET-<random>`) in memory.
  - It announces only its PID, its public key and the SHA-256 of the secret.
  - The key file is **deleted** before the attack, so process memory is the only source.
- **Attacker:** `src/red-lab-extraction.mjs` models host root. It reads `/proc/<pid>/mem` across all writable mappings, which requires ptrace-level access; root always has it, and in the test the parent process has it.
- **Judge:** the attacker must recover (a) the exact secret, checked against its announced hash, and (b) a private key whose signature verifies under the module's announced public key. That is proof that the attacker can **impersonate** the module on the authenticated IPC channel (#22).

## Result

Run in CI on Linux (Ubuntu runners, Node 20 and 24; [run 45426754299](https://github.com/ryosk7/AppVeil/actions/runs/45426754299), 127 passed and 0 skipped): **`extracted`**. Both the secret and the signing key were recovered from memory. On macOS the lab reports `not-checked` (there is no `/proc/<pid>/mem`); it does not report success or failure.

## Implications

- The policy engine (#21) and the authenticated IPC (#22) protect against **unprivileged** local attackers only. Against host root, a software secret module provides **no** confidentiality and **no** authentication: root can read its keys and data.
- This is exactly why the policy engine denies `confidential` on Olares One (`UNSUPPORTED_ON_DEVICE`, from the #20 evidence). The same lab must be run against any future hardware boundary from the #23 survey. A failure to extract in one attempt will not prove resistance.
- Out of scope here: physical attacks, side channels, cold-boot attacks.
