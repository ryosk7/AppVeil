# Authenticated local IPC protocol v1 (Track C, issue #22). Prototype: independent security review required

`src/local-ipc.mjs` defines how the inspectable app container talks to a **secret module**: a process that, in a real deployment, should run inside an attested isolation boundary (see #21 and #23). Only `node:crypto` is used.

## Handshake (mutual authentication, forward secrecy)

```
C -> S  HELLO  : eph_c (X25519, 32 B) | nonce_c (32 B) | id_c (Ed25519 SPKI, 44 B)
S -> C  REPLY  : eph_s (32 B) | nonce_s (32 B) | sig_s = Ed25519_S("appveil-ipc-v1 server sig" || T)
C -> S  FINISH : sig_c = Ed25519_C("appveil-ipc-v1 client sig" || T || sig_s)
T = "appveil-ipc-v1 transcript" || HELLO frame || eph_s || nonce_s || id_c || id_s
keys = HKDF-SHA256(ikm = X25519(eph_c, eph_s), salt = SHA-256(T || sig_s), info = "appveil-ipc-v1 keys") -> 32 B c→s, 32 B s→c
```

- Both identities are **pinned**. The client pins the server key, and the server keeps an allow-list of client keys. An unpinned client is rejected at HELLO.
- HELLO and REPLY are bound in full by the transcript and the signatures; role-specific labels separate the two signatures. Handshake frames must carry `seq = 0`. A man-in-the-middle who swaps an ephemeral key, or a client claiming someone else's identity, fails signature verification.
- `finish()` (client) and `complete()` (server) are **single-use**. The client drops its ephemeral private key after `finish()`. The server marks a handshake used only **after** FINISH verifies, so a forged FINISH cannot burn the legitimate one.
- The pin check at HELLO is a **filter, not authentication**: anyone can send a pinned public key and make the server do one DH and one signature. FINISH is what authenticates the client, so the transport must bound the number of pending accepts.
- Rejecting low-order X25519 points, such as an all-zero shared secret, relies on OpenSSL refusing them. Both sides turn that refusal into `MALFORMED`.
- There is no explicit key confirmation from server to client; the client learns that the handshake succeeded from the first valid server record.
- Identities must be 44-byte Ed25519 SPKI DER, and both sides check this.

## Records

`header = version (1) | type (1) | seq (8, big-endian) | length (4)`, followed by AES-256-GCM ciphertext and tag. The header is the AAD, and the IV is `0^4 || seq`.

- The receiver accepts only `seq == expected`, which rejects **replay, reordering and dropped records that are followed by a later record**.
- **Truncation:** `sealClose()` sends an authenticated `CLOSE` record. Only after one arrives is `peerClosed` true. A stream that ends without it must be treated as truncated.
- **Any** protocol error (AEAD, sequence, type, version, length) closes the channel permanently.
- The payload limit is 1 MiB. Oversized lengths, including lying length fields, are rejected before decryption.
- Unknown versions and record types are rejected.
- The two directions use separate keys, so a record cannot be reflected back to its sender.
- At most 2^24 records per key and direction, about 2^40 AES blocks at 1 MiB each, well under the AES-GCM bound. After that, `EXHAUSTED` requires a new handshake.

## Threat levels: what each one does and does not cover

| Attacker | Covered? | Notes |
| --- | --- | --- |
| Another unprivileged local process (or container) sniffing or injecting on the socket or pipe | **Yes**: confidentiality, integrity, replay protection, authentication | Assumes both static private keys are out of that process's reach. |
| A compromised app container talking to the module | **Partially** | It can use the channel exactly as the legitimate client could, because it holds the client key. The protocol authenticates *endpoints*, not *intent*. |
| **Host root** on a standard host, such as Olares One (#20) | **No** | Root can read either side's static key and the session keys from process memory, impersonate either side, or read plaintext after decryption. Only an attested hardware boundary that keeps the module's key and plaintext out of host memory changes this, and Olares One has none. |
| Firmware or hypervisor | **No** | Same as host root. |
| Side channels (timing, cache, power) | **Not addressed** | The comparisons used are constant-time (`timingSafeEqual`, AEAD). Nothing beyond that was analyzed. |
| Physical or invasive | **No** | |

## Evidence (`test/local-ipc.test.mjs`)

- Round trips in both directions (50 messages each way, plus 1 MiB).
- Rejection of:
  - tampered ciphertext (the channel then closes)
  - reordering, replay, and a tampered `seq` in the authenticated header
  - wrong version, unknown type, oversized or lying length, truncated frames
  - reflection back to the sender
  - an impostor server, an unpinned client, a client lying about its identity
  - FINISH reuse, a man-in-the-middle swapping keys, and cross-session records

## Review checklist

- Is the transcript complete? For example, is HELLO bound in its entirety, and is every field signed?
- Is key separation correct between the two directions and between sessions?
- Is the IV unique for every key? (The `seq` is never reused because the channel closes on exhaustion.)
- Is there any path that accepts data before FINISH has been verified?

## Independent review (PR #54)

An AI reviewer agent, independent of the implementing session, gave the verdict "approve with fixes". It found no unknown key-share, misbinding or KCI attack, and confirmed transcript binding and the direction and session separation. Fixed:
1. Client `finish()` was reusable, which reused AES-GCM nonces and exposed plaintext.
2. End-of-stream truncation went undetected, because `CLOSE` was defined but unused; non-AEAD errors also left the channel open.
3. A raw OpenSSL error was raised on an invalid server ephemeral key.
4. A forged FINISH could burn the legitimate one.
5. The record limit was effectively unbounded.
6. Input, key-type and handshake-`seq` validation was missing.
7. Spec wording overclaimed in places.

Each fix has a regression test in `test/local-ipc.test.mjs`. A human security review is still recommended.
