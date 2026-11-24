# Authenticated local IPC protocol v1 (Track C, issue #22). Prototype: independent security review required

`src/local-ipc.mjs` defines how the inspectable app container talks to a **secret module**: a process that, in a real deployment, should run inside an attested isolation boundary (see #21 and #23). Only `node:crypto` is used.

## Handshake (mutual authentication, forward secrecy)

```
C -> S  HELLO  : eph_c (X25519, 32 B) | nonce_c (32 B) | id_c (Ed25519 SPKI, 44 B)
S -> C  REPLY  : eph_s (32 B) | nonce_s (32 B) | sig_s = Ed25519_S(T)
C -> S  FINISH : sig_c = Ed25519_C(T || sig_s)
T = "appveil-ipc-v1 transcript" || HELLO frame || eph_s || nonce_s || id_c || id_s
keys = HKDF-SHA256(ikm = X25519(eph_c, eph_s), salt = SHA-256(T || sig_s), info = "appveil-ipc-v1 keys") -> 32 B c→s, 32 B s→c
```

- Both identities are **pinned**. The client pins the server key, and the server keeps an allow-list of client keys. An unpinned client is rejected at HELLO.
- Everything either side sends is covered by a signature or by the transcript, so a man-in-the-middle who swaps an ephemeral key, or a client claiming someone else's identity, fails signature verification. A completed handshake cannot be replayed.

## Records

`header = version (1) | type (1) | seq (8, big-endian) | length (4)`, followed by AES-256-GCM ciphertext and tag. The header is the AAD, and the IV is `0^4 || seq`.

- The receiver accepts only `seq == expected`, which rejects **replay, reordering and dropped records**.
- After an authentication failure the channel closes permanently.
- The payload limit is 1 MiB. Oversized lengths, including lying length fields, are rejected before decryption.
- Unknown versions and record types are rejected.
- The two directions use separate keys, so a record cannot be reflected back to its sender.
- Sequence exhaustion forces a rekey, which here means a new handshake.

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
