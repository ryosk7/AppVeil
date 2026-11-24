import test from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, createClient, createServer, IpcError, MAX_PAYLOAD } from '../src/local-ipc.mjs';

const serverId = generateIdentity(), clientId = generateIdentity(), mallory = generateIdentity();
function handshake({ client = clientId, serverPin = serverId.publicDer, allowed = [clientId.publicDer], server = serverId } = {}) {
  const c = createClient({ identity: client, serverPublicDer: serverPin });
  const s = createServer({ identity: server, allowedClients: allowed });
  const a = s.accept(c.hello);
  const { finishFrame, channel: cc } = c.finish(a.replyFrame);
  const sc = a.complete(finishFrame);
  return { cc, sc, c, s, a, finishFrame };
}
const code = c => err => err instanceof IpcError && err.code === c;

test('mutual authentication and bidirectional confidential, ordered messages', () => {
  const { cc, sc } = handshake();
  for (let i = 0; i < 50; i++) {
    assert.equal(sc.open(cc.seal(`req ${i}`)).toString(), `req ${i}`);
    assert.equal(cc.open(sc.seal(`res ${i}`)).toString(), `res ${i}`);
  }
  const big = Buffer.alloc(MAX_PAYLOAD, 7);
  assert.deepEqual(sc.open(cc.seal(big)), big);
  const ct = cc.seal('secret-marker-123');
  assert.ok(!ct.includes(Buffer.from('secret-marker-123')), 'ciphertext must not contain plaintext');
});

test('rejects tampering, replay, reordering, oversize, wrong version and wrong direction', () => {
  let { cc, sc } = handshake();
  const r0 = cc.seal('a'), r1 = cc.seal('b');
  assert.throws(() => sc.open(r1), code('REPLAY'), 'reordered');
  assert.equal(sc.open(r0).toString(), 'a');
  assert.throws(() => sc.open(r0), code('REPLAY'), 'replayed');
  ({ cc, sc } = handshake());
  const t = cc.seal('hello'); t[t.length - 1] ^= 1;
  assert.throws(() => sc.open(t), code('AUTH'));
  assert.throws(() => sc.open(cc.seal('next')), code('CLOSED'), 'channel closes after an authentication failure');
  ({ cc, sc } = handshake());
  const h = cc.seal('x'); h[1] = 99;
  assert.throws(() => sc.open(h), code('UNEXPECTED'));
  const hv = cc.seal('x'); hv[0] = 2;
  assert.throws(() => sc.open(hv), code('VERSION'));
  ({ cc, sc } = handshake());
  const hs = cc.seal('x'); hs.writeBigUInt64BE(0n, 2); // header (AAD) tamper on seq
  const hs2 = cc.seal('y'); hs2.writeBigUInt64BE(0n, 2);
  assert.throws(() => sc.open(hs2), code('AUTH'), 'seq is authenticated');
  assert.throws(() => cc.seal(Buffer.alloc(MAX_PAYLOAD + 1)), code('OVERSIZE'));
  ({ cc, sc } = handshake());
  assert.throws(() => cc.open(cc.seal('to myself')), code('AUTH'), 'client-to-server key cannot decrypt in the other direction');
  const lie = Buffer.alloc(14); lie[0] = 1; lie[1] = 16; lie.writeUInt32BE(0xffffffff, 10);
  assert.throws(() => sc.open(lie), code('OVERSIZE'));
  assert.throws(() => sc.open(Buffer.from([1, 16])), code('MALFORMED'));
});

test('rejects impersonation, unpinned clients and handshake replay', () => {
  // Client pinned to the real server: an impostor server (mallory) is rejected.
  const c = createClient({ identity: clientId, serverPublicDer: serverId.publicDer });
  const evil = createServer({ identity: mallory, allowedClients: [clientId.publicDer] }).accept(c.hello);
  assert.throws(() => c.finish(evil.replyFrame), code('AUTH'));
  // Unpinned client is rejected at HELLO.
  const c2 = createClient({ identity: mallory, serverPublicDer: serverId.publicDer });
  assert.throws(() => createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(c2.hello), code('AUTH'));
  // A client that lies about its identity (mallory's key in HELLO swapped for the real one) cannot sign FINISH.
  const c3 = createClient({ identity: mallory, serverPublicDer: serverId.publicDer });
  const hello = Buffer.from(c3.hello); clientId.publicDer.copy(hello, 14 + 64);
  const a = createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(hello);
  assert.throws(() => c3.finish(a.replyFrame), code('AUTH'), 'transcript mismatch detected by the client');
  // FINISH cannot be reused.
  const { a: acc, finishFrame } = handshake();
  assert.throws(() => acc.complete(finishFrame), code('REPLAY'));
  // A man-in-the-middle swapping the server ephemeral key breaks the server signature.
  const c4 = createClient({ identity: clientId, serverPublicDer: serverId.publicDer });
  const r = createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(c4.hello).replyFrame;
  const swapped = Buffer.from(r); swapped[14] ^= 0xff;
  assert.throws(() => c4.finish(swapped), code('AUTH'));
});

test('sessions are independent: each handshake derives fresh keys', () => {
  const s1 = handshake(), s2 = handshake();
  assert.throws(() => s2.sc.open(s1.cc.seal('cross-session')), code('AUTH'));
});
