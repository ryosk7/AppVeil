import { generateKeyPairSync, diffieHellman, sign, verify, hkdfSync, createCipheriv, createDecipheriv, randomBytes, createHash, createPublicKey, timingSafeEqual } from 'node:crypto';

/**
 * Authenticated local IPC between an app and a secret module (Track C, issue #22). RESEARCH
 * PROTOTYPE. Spec: research/LOCAL_IPC_PROTOCOL.md.
 *
 * Handshake (mutual authentication, forward secrecy):
 *   C -> S  HELLO   { eph_c(X25519), nonce_c, id_c(Ed25519 SPKI) }
 *   S -> C  REPLY   { eph_s, nonce_s, sig_s = Ed25519_s("server sig" || T) }
 *   C -> S  FINISH  { sig_c = Ed25519_c("client sig" || T || sig_s) }
 * Keys: HKDF-SHA256(X25519(eph_c, eph_s), salt = H(T || sig_s)) -> per-direction AES-256-GCM keys.
 * Records: header = version(1) | type(1) | seq(8, BE) | length(4); AEAD with the header as AAD and IV
 * derived from seq. Strict seq == expected; an authenticated CLOSE ends the stream (truncation is
 * detectable); ANY protocol error closes the channel. At most MAX_RECORDS records per key.
 *
 * If either static private key lives in host-accessible memory, host root can impersonate that side.
 */
export const VERSION = 1;
export const MAX_PAYLOAD = 1024 * 1024;
export const MAX_RECORDS = 2 ** 24; // per direction and key; then a new handshake is required
const TYPE = { HELLO: 1, REPLY: 2, FINISH: 3, DATA: 16, CLOSE: 17 };
const HEADER = 14;
const ID_LEN = 44; // Ed25519 SubjectPublicKeyInfo DER
const label = s => Buffer.from(`appveil-ipc-v1 ${s}`);

export class IpcError extends Error { constructor(code, msg) { super(`${code}: ${msg}`); this.code = code; } }
const fail = (code, msg) => { throw new IpcError(code, msg); };

export function generateIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey, publicDer: publicKey.export({ type: 'spki', format: 'der' }) };
}
/** Accept only an Ed25519 SPKI DER (exactly 44 bytes) as an identity. */
function ed25519Spki(der, what) {
  if (!(der instanceof Uint8Array) || der.length !== ID_LEN) fail('MALFORMED', `${what} must be a 44-byte Ed25519 SPKI DER`);
  let key;
  try { key = createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' }); } catch { fail('MALFORMED', `${what} is not a valid SPKI key`); }
  if (key.asymmetricKeyType !== 'ed25519') fail('MALFORMED', `${what} must be Ed25519`);
  return { der: Buffer.from(der), key };
}
const ephemeral = () => generateKeyPairSync('x25519');
const rawX25519 = k => k.export({ type: 'spki', format: 'der' }).subarray(-32);
const x25519FromRaw = raw => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), raw]), format: 'der', type: 'spki' });
const H = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
function dh(privateKey, raw) {
  // OpenSSL refuses low-order points (all-zero shared secret); map that to a protocol error.
  try { return diffieHellman({ privateKey, publicKey: x25519FromRaw(raw) }); } catch { fail('MALFORMED', 'invalid X25519 public key'); }
}

function header(type, seq, length) {
  const h = Buffer.alloc(HEADER);
  h[0] = VERSION; h[1] = type; h.writeBigUInt64BE(seq, 2); h.writeUInt32BE(length, 10);
  return h;
}
const frame = (type, seq, body) => Buffer.concat([header(type, seq, body.length), body]);
function unframe(buf) {
  if (!(buf instanceof Uint8Array)) fail('MALFORMED', 'frame must be bytes');
  buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  if (buf.length < HEADER) fail('MALFORMED', 'short frame');
  if (buf[0] !== VERSION) fail('VERSION', `unsupported version ${buf[0]}`);
  const len = buf.readUInt32BE(10);
  if (len > MAX_PAYLOAD + 16) fail('OVERSIZE', 'declared length too large');
  if (buf.length !== HEADER + len) fail('MALFORMED', 'length mismatch');
  return { type: buf[1], seq: buf.readBigUInt64BE(2), header: buf.subarray(0, HEADER), body: buf.subarray(HEADER) };
}
function handshakeFrame(buf, type, name) {
  const f = unframe(buf);
  if (f.type !== type) fail('UNEXPECTED', `expected ${name}`);
  if (f.seq !== 0n) fail('MALFORMED', `${name} must carry seq 0`);
  return f;
}
const pick = (b, n, what) => { if (b.length < n) fail('MALFORMED', `${what} truncated`); return [b.subarray(0, n), b.subarray(n)]; };

function deriveKeys(shared, transcript) {
  const okm = Buffer.from(hkdfSync('sha256', shared, H(transcript), label('keys'), 64));
  return { c2s: okm.subarray(0, 32), s2c: okm.subarray(32, 64) };
}
function channel(sendKey, recvKey) {
  let sendSeq = 0n, recvSeq = 0n, closed = false, peerClosed = false;
  const iv = seq => { const b = Buffer.alloc(12); b.writeBigUInt64BE(seq, 4); return b; };
  const sealRecord = (type, data) => {
    if (closed) fail('CLOSED', 'channel closed');
    if (sendSeq >= BigInt(MAX_RECORDS)) fail('EXHAUSTED', 'record limit for this key reached; perform a new handshake');
    const h = header(type, sendSeq, data.length + 16);
    const c = createCipheriv('aes-256-gcm', sendKey, iv(sendSeq)); c.setAAD(h);
    const ct = Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
    sendSeq++;
    return Buffer.concat([h, ct]);
  };
  return {
    seal(payload) {
      if (!(payload instanceof Uint8Array) && typeof payload !== 'string') fail('MALFORMED', 'payload must be bytes or a string');
      const data = Buffer.from(payload);
      if (data.length > MAX_PAYLOAD) fail('OVERSIZE', 'payload too large');
      return sealRecord(TYPE.DATA, data);
    },
    /** Authenticated end of stream. After it, the sender's channel is closed. */
    sealClose() { const r = sealRecord(TYPE.CLOSE, Buffer.alloc(0)); closed = true; return r; },
    open(record) {
      if (closed) fail('CLOSED', 'channel closed');
      // Any protocol error is fatal: the channel closes and later records are refused.
      try {
        const { type, seq, header: h, body } = unframe(record);
        if (type !== TYPE.DATA && type !== TYPE.CLOSE) fail('UNEXPECTED', `unexpected record type ${type}`);
        if (seq !== recvSeq) fail('REPLAY', `sequence ${seq} != expected ${recvSeq} (replay, reorder or drop)`);
        if (body.length < 16) fail('MALFORMED', 'missing tag');
        const d = createDecipheriv('aes-256-gcm', recvKey, iv(seq)); d.setAAD(h); d.setAuthTag(body.subarray(-16));
        let pt;
        try { pt = Buffer.concat([d.update(body.subarray(0, -16)), d.final()]); } catch { fail('AUTH', 'authentication failed'); }
        recvSeq++;
        if (type === TYPE.CLOSE) { if (pt.length) fail('MALFORMED', 'CLOSE carries no payload'); peerClosed = true; closed = true; return null; }
        return pt;
      } catch (e) { closed = true; throw e; }
    },
    /** True only if the peer ended the stream with an authenticated CLOSE (otherwise: truncated). */
    get peerClosed() { return peerClosed; },
    close() { closed = true; }
  };
}

/** Client side. `serverPublicDer` is the pinned server identity (Ed25519 SPKI DER). */
export function createClient({ identity, serverPublicDer }) {
  const own = ed25519Spki(identity?.publicDer, 'client identity');
  const server = ed25519Spki(serverPublicDer, 'serverPublicDer');
  let eph = ephemeral();
  const nonce = randomBytes(32);
  const hello = frame(TYPE.HELLO, 0n, Buffer.concat([rawX25519(eph.publicKey), nonce, own.der]));
  let used = false;
  return {
    hello,
    /** Single use: a second call throws (reusing it would reuse AES-GCM keys and nonces). */
    finish(replyFrame) {
      if (used) fail('REPLAY', 'finish() already called');
      used = true;
      const priv = eph.privateKey;
      eph = null; // drop the ephemeral private key after this attempt (forward secrecy)
      const { body } = handshakeFrame(replyFrame, TYPE.REPLY, 'REPLY');
      let [ephS, rest] = pick(body, 32, 'server key'); let nonceS; [nonceS, rest] = pick(rest, 32, 'server nonce');
      const [sigS, extra] = pick(rest, 64, 'server signature');
      if (extra.length) fail('MALFORMED', 'trailing bytes');
      const transcript = Buffer.concat([label('transcript'), hello, ephS, nonceS, own.der, server.der]);
      if (!verify(null, Buffer.concat([label('server sig'), transcript]), server.key, sigS)) fail('AUTH', 'server signature invalid (wrong or impersonated server)');
      const sigC = sign(null, Buffer.concat([label('client sig'), transcript, sigS]), identity.privateKey);
      const keys = deriveKeys(dh(priv, ephS), Buffer.concat([transcript, sigS]));
      return { finishFrame: frame(TYPE.FINISH, 0n, sigC), channel: channel(keys.c2s, keys.s2c) };
    }
  };
}

/** Server side. `allowedClients` is a non-empty list of pinned client identities (Ed25519 SPKI DER). */
export function createServer({ identity, allowedClients }) {
  const own = ed25519Spki(identity?.publicDer, 'server identity');
  if (!Array.isArray(allowedClients) || !allowedClients.length) fail('MALFORMED', 'allowedClients must be a non-empty list');
  const pinned = allowedClients.map((d, i) => ed25519Spki(d, `allowedClients[${i}]`).der);
  return {
    /**
     * Process HELLO; returns { replyFrame, complete(finishFrame) -> channel }. The pin check here is a
     * filter, not authentication (anyone can send a pinned public key); FINISH authenticates. Bound
     * the number of pending accepts in the transport.
     */
    accept(helloFrame) {
      const { body } = handshakeFrame(helloFrame, TYPE.HELLO, 'HELLO');
      if (body.length !== 64 + ID_LEN) fail('MALFORMED', 'bad HELLO length');
      const ephC = body.subarray(0, 32), cpk = Buffer.from(body.subarray(64));
      if (!pinned.some(p => timingSafeEqual(p, cpk))) fail('AUTH', 'client identity is not pinned');
      const clientKey = ed25519Spki(cpk, 'client identity').key;
      const eph = ephemeral(), nonceS = randomBytes(32);
      const ephS = rawX25519(eph.publicKey);
      let shared = dh(eph.privateKey, ephC);
      const helloCopy = Buffer.from(helloFrame);
      const transcript = Buffer.concat([label('transcript'), helloCopy, ephS, nonceS, cpk, own.der]);
      const sigS = sign(null, Buffer.concat([label('server sig'), transcript]), identity.privateKey);
      let done = false;
      return {
        replyFrame: frame(TYPE.REPLY, 0n, Buffer.concat([ephS, nonceS, sigS])),
        complete(finishFrame) {
          if (done) fail('REPLAY', 'handshake already completed');
          const f = handshakeFrame(finishFrame, TYPE.FINISH, 'FINISH');
          if (f.body.length !== 64) fail('MALFORMED', 'bad FINISH length');
          if (!verify(null, Buffer.concat([label('client sig'), transcript, sigS]), clientKey, f.body)) fail('AUTH', 'client signature invalid');
          // Marked used only after verification: a forged FINISH cannot burn the legitimate one.
          done = true;
          const keys = deriveKeys(shared, Buffer.concat([transcript, sigS]));
          shared = null;
          return channel(keys.s2c, keys.c2s);
        }
      };
    }
  };
}
