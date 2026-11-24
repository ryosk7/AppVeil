import { generateKeyPairSync, diffieHellman, sign, verify, hkdfSync, createCipheriv, createDecipheriv, randomBytes, createHash, createPublicKey, timingSafeEqual } from 'node:crypto';

/**
 * Authenticated local IPC between an app and a secret module (Track C, issue #22). RESEARCH
 * PROTOTYPE — requires independent security review. Spec: research/LOCAL_IPC_PROTOCOL.md.
 *
 * Handshake (mutual authentication, forward secrecy):
 *   C -> S  HELLO   { v, eph_c(X25519), nonce_c, id_c(Ed25519 SPKI) }
 *   S -> C  REPLY   { v, eph_s, nonce_s, sig_s = Ed25519_s(transcript) }
 *   C -> S  FINISH  { sig_c = Ed25519_c(transcript || sig_s) }
 * Keys: HKDF-SHA256(X25519(eph_c, eph_s), salt = H(transcript)) -> per-direction AES-256-GCM keys.
 * Records: header = version(1) | type(1) | seq(8, big endian) | length(4); AEAD with the header as
 * AAD and the nonce derived from seq. The receiver requires seq == expected (strictly increasing, no
 * gaps): replay, reordering and truncation-with-continuation are rejected.
 *
 * If either static private key lives in host-accessible memory, host root can impersonate that side.
 */
export const VERSION = 1;
export const MAX_PAYLOAD = 1024 * 1024;
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
const ephemeral = () => generateKeyPairSync('x25519');
const rawX25519 = k => k.export({ type: 'spki', format: 'der' }).subarray(-32);
const x25519FromRaw = raw => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), raw]), format: 'der', type: 'spki' });
const H = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };

function frame(type, seq, body) {
  if (body.length > MAX_PAYLOAD + 16) fail('OVERSIZE', 'payload too large');
  const h = Buffer.alloc(HEADER);
  h[0] = VERSION; h[1] = type; h.writeBigUInt64BE(seq, 2); h.writeUInt32BE(body.length, 10);
  return Buffer.concat([h, body]);
}
function unframe(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < HEADER) fail('MALFORMED', 'short frame');
  if (buf[0] !== VERSION) fail('VERSION', `unsupported version ${buf[0]}`);
  const len = buf.readUInt32BE(10);
  if (len > MAX_PAYLOAD + 16) fail('OVERSIZE', 'declared length too large');
  if (buf.length !== HEADER + len) fail('MALFORMED', 'length mismatch');
  return { type: buf[1], seq: buf.readBigUInt64BE(2), header: buf.subarray(0, HEADER), body: buf.subarray(HEADER) };
}
const pick = (b, n, what) => { if (b.length < n) fail('MALFORMED', `${what} truncated`); return [b.subarray(0, n), b.subarray(n)]; };

function deriveKeys(shared, transcript) {
  const okm = Buffer.from(hkdfSync('sha256', shared, H(transcript), label('keys'), 64));
  return { c2s: okm.subarray(0, 32), s2c: okm.subarray(32, 64) };
}
function channel(sendKey, recvKey) {
  let sendSeq = 0n, recvSeq = 0n, closed = false;
  const iv = seq => { const b = Buffer.alloc(12); b.writeBigUInt64BE(seq, 4); return b; };
  return {
    seal(payload) {
      if (closed) fail('CLOSED', 'channel closed');
      const data = Buffer.from(payload);
      if (data.length > MAX_PAYLOAD) fail('OVERSIZE', 'payload too large');
      if (sendSeq === 0xffffffffffffffffn) fail('EXHAUSTED', 'sequence space exhausted; rekey');
      const header = frame(TYPE.DATA, sendSeq, Buffer.alloc(data.length + 16)).subarray(0, HEADER);
      const c = createCipheriv('aes-256-gcm', sendKey, iv(sendSeq)); c.setAAD(header);
      const ct = Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
      sendSeq++;
      return Buffer.concat([header, ct]);
    },
    open(record) {
      if (closed) fail('CLOSED', 'channel closed');
      const { type, seq, header, body } = unframe(record);
      if (type !== TYPE.DATA) fail('UNEXPECTED', `unexpected record type ${type}`);
      if (seq !== recvSeq) fail('REPLAY', `sequence ${seq} != expected ${recvSeq} (replay, reorder or drop)`);
      if (body.length < 16) fail('MALFORMED', 'missing tag');
      const d = createDecipheriv('aes-256-gcm', recvKey, iv(seq)); d.setAAD(header); d.setAuthTag(body.subarray(-16));
      let pt;
      try { pt = Buffer.concat([d.update(body.subarray(0, -16)), d.final()]); } catch { closed = true; fail('AUTH', 'authentication failed; channel closed'); }
      recvSeq++;
      return pt;
    },
    close() { closed = true; }
  };
}

/** Client side. `serverPublicDer` is the pinned server identity. */
export function createClient({ identity, serverPublicDer }) {
  const eph = ephemeral(), nonce = randomBytes(32);
  if (identity.publicDer.length !== ID_LEN) fail('MALFORMED', 'client identity must be an Ed25519 SPKI key');
  const hello = frame(TYPE.HELLO, 0n, Buffer.concat([rawX25519(eph.publicKey), nonce, identity.publicDer]));
  return {
    hello,
    finish(replyFrame) {
      const { type, body } = unframe(replyFrame);
      if (type !== TYPE.REPLY) fail('UNEXPECTED', 'expected REPLY');
      let [ephS, rest] = pick(body, 32, 'server key'); let nonceS; [nonceS, rest] = pick(rest, 32, 'server nonce');
      const [sigS, extra] = pick(rest, 64, 'server signature');
      if (extra.length) fail('MALFORMED', 'trailing bytes');
      const transcript = Buffer.concat([label('transcript'), hello, ephS, nonceS, identity.publicDer, Buffer.from(serverPublicDer)]);
      if (!verify(null, transcript, createPublicKey({ key: Buffer.from(serverPublicDer), format: 'der', type: 'spki' }), sigS)) fail('AUTH', 'server signature invalid (wrong or impersonated server)');
      const sigC = sign(null, Buffer.concat([transcript, sigS]), identity.privateKey);
      const keys = deriveKeys(diffieHellman({ privateKey: eph.privateKey, publicKey: x25519FromRaw(ephS) }), Buffer.concat([transcript, sigS]));
      return { finishFrame: frame(TYPE.FINISH, 0n, sigC), channel: channel(keys.c2s, keys.s2c) };
    }
  };
}

/** Server side. `allowedClients` is a list of pinned client identities (SPKI DER). */
export function createServer({ identity, allowedClients }) {
  const pinned = allowedClients.map(d => Buffer.from(d));
  return {
    /** Process HELLO; returns { replyFrame, complete(finishFrame) -> channel }. */
    accept(helloFrame) {
      const { type, body } = unframe(helloFrame);
      if (type !== TYPE.HELLO) fail('UNEXPECTED', 'expected HELLO');
      if (body.length !== 64 + ID_LEN) fail('MALFORMED', 'bad HELLO length');
      const ephC = body.subarray(0, 32), cpk = Buffer.from(body.subarray(64));
      if (!pinned.some(p => p.length === cpk.length && timingSafeEqual(p, cpk))) fail('AUTH', 'client identity is not pinned');
      const eph = ephemeral(), nonceS = randomBytes(32);
      const ephS = rawX25519(eph.publicKey);
      let shared;
      try { shared = diffieHellman({ privateKey: eph.privateKey, publicKey: x25519FromRaw(ephC) }); } catch { fail('MALFORMED', 'invalid client ephemeral key'); }
      const transcript = Buffer.concat([label('transcript'), helloFrame, ephS, nonceS, cpk, identity.publicDer]);
      const sigS = sign(null, transcript, identity.privateKey);
      let used = false;
      return {
        replyFrame: frame(TYPE.REPLY, 0n, Buffer.concat([ephS, nonceS, sigS])),
        complete(finishFrame) {
          if (used) fail('REPLAY', 'handshake already completed');
          used = true;
          const f = unframe(finishFrame);
          if (f.type !== TYPE.FINISH || f.body.length !== 64) fail('UNEXPECTED', 'expected FINISH');
          if (!verify(null, Buffer.concat([transcript, sigS]), createPublicKey({ key: cpk, format: 'der', type: 'spki' }), f.body)) fail('AUTH', 'client signature invalid');
          const keys = deriveKeys(shared, Buffer.concat([transcript, sigS]));
          return channel(keys.s2c, keys.c2s);
        }
      };
    }
  };
}
