# Red Lab: key and material extraction from a software secret module (issue #24)

**This is a negative *security* result:** the lab demonstrates that the attack **succeeds**, so the test passing means the defense fails. It is required before any hardware boundary is evaluated (#24, `agent.md` §5).

## Setup (synthetic data only)

- **Target:** `test/helpers/secret-module-child.mjs`, a Node process modeling a software secret module. It loads an Ed25519 private key from a PEM file, and it **keeps the PEM string referenced** (deliberately, as many long-running services keep their config text). It also holds a synthetic secret, `APPVEIL-SYNTHETIC-SECRET-<random>`. It announces only its PID, its public key and the SHA-256 of the secret. The key file is deleted before the scan, so the attack does not read it from disk; the scan reads only the child's memory.
- **Attacker access actually exercised:** an **unprivileged parent process reading its own child** through `/proc/<pid>/mem`. This is ptrace-level access (`PTRACE_MODE_ATTACH`), which Linux grants to a same-user ancestor under Yama `ptrace_scope=1`. Root was **not** exercised. The threat-model assumption is that host root has at least this access.
- **Judge:** the result is `extracted` only if the attacker recovers (a) the exact secret, checked against the announced hash, **and** (b) a private key whose public key equals the module's announced key; a signature under it is checked as well. Regions skipped because of read caps, and unreadable regions, are counted. If the scan was incomplete, the result can be `not-checked` but never `not-extracted`.

## Result

CI on Linux (Ubuntu, Node 20 and 24): **`extracted`**. The secret and the signing key were recovered from the child's memory. The run that validates the head commit of this PR is cited in the PR. On macOS the lab reports `not-checked`; there is no `/proc/<pid>/mem`.

## What this shows, and what it does not

- **Shown (measured):** for *this module design* (Node, Linux, key text kept in the heap), any process with ptrace-level access to the module reads its long-term key and its secrets. It can therefore impersonate the module on the authenticated IPC channel (#22).
- **Consequence (threat-model reasoning, not measured here):** a software secret module offers no confidentiality or authentication against host root, which has at least this access. The policy engine (#21) and the IPC (#22) only resist processes **without** ptrace access to the module. A same-user parent or tracer *has* that access, so they do not resist it either. This is why `confidential` is denied on Olares One (`UNSUPPORTED_ON_DEVICE`, #20).
- **Not tested:**
  - a module that discards the PEM after parsing and keeps the key only inside OpenSSL, which would need a different search method
  - hardened runtimes (for example, `prctl(PR_SET_DUMPABLE, 0)`, Yama `ptrace_scope=3`, or a separate user)
  - root specifically
  - physical attacks, side channels, cold boot

  Each of these would raise the bar against non-root attackers. Against root, the threat model does not depend on them. The lab must be re-run against any future hardware boundary (#23), and a single failed attempt there will not prove resistance.
