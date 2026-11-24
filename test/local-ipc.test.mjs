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
  assert.ok(!cc.seal('secret-marker-123').includes(Buffer.from('secret-marker-123')));
});

test('rejects tampering, replay, reordering, oversize, wrong version and type; every error is fatal', () => {
  const cases = {
    REPLAY: (cc, sc) => { cc.seal('a'); sc.open(cc.seal('b')); },
    AUTH: (cc, sc) => { const t = cc.seal('hello'); t[t.length - 1] ^= 1; sc.open(t); },
    UNEXPECTED: (cc, sc) => { const h = cc.seal('x'); h[1] = 99; sc.open(h); },
    VERSION: (cc, sc) => { const h = cc.seal('x'); h[0] = 2; sc.open(h); },
    OVERSIZE: (cc, sc) => { const lie = Buffer.alloc(14); lie[0] = 1; lie[1] = 16; lie.writeUInt32BE(0xffffffff, 10); sc.open(lie); },
    MALFORMED: (cc, sc) => sc.open(Buffer.from([1, 16]))
  };
  for (const [c, attack] of Object.entries(cases)) {
    const { cc, sc } = handshake();
    assert.throws(() => attack(cc, sc), code(c), c);
    assert.throws(() => sc.open(cc.seal('next')), code('CLOSED'), `${c}: channel must be closed after the error`);
  }
  const { cc, sc } = handshake();
  cc.seal('x');
  const hs2 = cc.seal('y'); hs2.writeBigUInt64BE(0n, 2);
  assert.throws(() => sc.open(hs2), code('AUTH'), 'seq is authenticated');
  const h2 = handshake();
  assert.throws(() => h2.cc.seal(Buffer.alloc(MAX_PAYLOAD + 1)), code('OVERSIZE'));
  assert.throws(() => h2.cc.open(h2.cc.seal('to myself')), code('AUTH'), 'no reflection');
});

test('rejects impersonation, unpinned clients and handshake replay', () => {
  const c = createClient({ identity: clientId, serverPublicDer: serverId.publicDer });
  const evil = createServer({ identity: mallory, allowedClients: [clientId.publicDer] }).accept(c.hello);
  assert.throws(() => c.finish(evil.replyFrame), code('AUTH'));
  const c2 = createClient({ identity: mallory, serverPublicDer: serverId.publicDer });
  assert.throws(() => createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(c2.hello), code('AUTH'));
  const c3 = createClient({ identity: mallory, serverPublicDer: serverId.publicDer });
  const hello = Buffer.from(c3.hello); clientId.publicDer.copy(hello, 14 + 64);
  const a = createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(hello);
  assert.throws(() => c3.finish(a.replyFrame), code('AUTH'));
  const { a: acc, finishFrame } = handshake();
  assert.throws(() => acc.complete(finishFrame), code('REPLAY'));
  const c4 = createClient({ identity: clientId, serverPublicDer: serverId.publicDer });
  const r = createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(c4.hello).replyFrame;
  const swapped = Buffer.from(r); swapped[14] ^= 0xff;
  assert.throws(() => c4.finish(swapped), code('AUTH'));
});

test('sessions are independent: each handshake derives fresh keys', () => {
  const s1 = handshake(), s2 = handshake();
  assert.throws(() => s2.sc.open(s1.cc.seal('cross-session')), code('AUTH'));
});

// Regression tests for the independent review of PR #54.
test('review #1: client finish() is single-use (no AES-GCM key/nonce reuse)', () => {
  const c = createClient({ identity: clientId, serverPublicDer: serverId.publicDer });
  const a = createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(c.hello);
  c.finish(a.replyFrame);
  assert.throws(() => c.finish(a.replyFrame), code('REPLAY'));
});

test('review #2: authenticated CLOSE distinguishes clean end from truncation', () => {
  const { cc, sc } = handshake();
  assert.equal(sc.open(cc.seal('one')).toString(), 'one');
  const closeRec = cc.sealClose();
  assert.throws(() => cc.seal('after close'), code('CLOSED'));
  assert.equal(sc.peerClosed, false, 'before CLOSE arrives, a stream end would be a truncation');
  assert.equal(sc.open(closeRec), null);
  assert.equal(sc.peerClosed, true);
  const t = handshake();
  const forged = t.cc.sealClose(); forged[forged.length - 1] ^= 1;
  assert.throws(() => t.sc.open(forged), code('AUTH'));
  assert.equal(t.sc.peerClosed, false, 'a forged CLOSE does not count');
});

test('review #3/#6: invalid keys, inputs and handshake headers raise IpcError', () => {
  const c = createClient({ identity: clientId, serverPublicDer: serverId.publicDer });
  const reply = createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(c.hello).replyFrame;
  const badSeq = Buffer.from(reply); badSeq.writeBigUInt64BE(42n, 2);
  assert.throws(() => c.finish(badSeq), code('MALFORMED'));
  const zeroEph = Buffer.from(createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(c.hello).replyFrame);
  assert.throws(() => createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(Buffer.concat([c.hello.subarray(0, 14), Buffer.alloc(32), c.hello.subarray(46)])), code('MALFORMED'), 'all-zero X25519 point');
  const { cc } = handshake();
  for (const bad of [123, null, {}]) assert.throws(() => cc.seal(bad), code('MALFORMED'));
  assert.throws(() => createClient({ identity: clientId, serverPublicDer: Buffer.alloc(44) }), code('MALFORMED'));
  const x25519Der = Buffer.from('302a300506032b656e032100' + '11'.repeat(32), 'hex');
  assert.throws(() => createServer({ identity: serverId, allowedClients: [x25519Der] }), code('MALFORMED'), 'pins must be Ed25519');
  assert.throws(() => createServer({ identity: serverId, allowedClients: [] }), code('MALFORMED'));
  assert.throws(() => createServer({ identity: serverId }), code('MALFORMED'));
  assert.ok(zeroEph.length > 0);
});

test('review #4: a forged FINISH does not burn the legitimate one', () => {
  const c = createClient({ identity: clientId, serverPublicDer: serverId.publicDer });
  const a = createServer({ identity: serverId, allowedClients: [clientId.publicDer] }).accept(c.hello);
  const { finishFrame, channel: cc } = c.finish(a.replyFrame);
  const forged = Buffer.from(finishFrame); forged[20] ^= 1;
  assert.throws(() => a.complete(forged), code('AUTH'));
  const sc = a.complete(finishFrame);
  assert.equal(sc.open(cc.seal('ok')).toString(), 'ok');
});
