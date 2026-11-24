import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { supported, scanProcessMemory, judgeExtraction } from '../src/red-lab-extraction.mjs';

const ON_LINUX = supported();
test('on unsupported platforms the lab reports not-checked, never success or failure', { skip: ON_LINUX ? 'Linux: the real extraction test below runs instead' : false }, () => {
  const r = judgeExtraction(scanProcessMemory(process.pid), { secretSha256: '', publicDer: '' });
  assert.equal(r.result, 'not-checked');
});

test('ptrace-level memory extraction (parent reading its child; root has at least this access) recovers the secret and the private key of a software secret module (expected negative result)', { skip: ON_LINUX ? false : '/proc/<pid>/mem required (Linux); CI runs this' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'appveil-extract-'));
  const keyFile = join(dir, 'module-key.pem');
  writeFileSync(keyFile, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const child = spawn(process.execPath, [fileURLToPath(new URL('./helpers/secret-module-child.mjs', import.meta.url)), keyFile], { stdio: ['pipe', 'pipe', 'inherit'] });
  try {
    const announced = await new Promise((resolve, reject) => {
      let buf = '', done = false;
      const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); child.stdout.removeAllListeners('data'); fn(v); };
      const timer = setTimeout(() => finish(reject, new Error('child did not announce within 10 s')), 10000);
      child.stdout.on('data', d => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { try { finish(resolve, JSON.parse(buf.slice(0, nl))); } catch (e) { finish(reject, e); } } });
      child.once('exit', c => finish(reject, new Error(`child exited ${c}`)));
    });
    rmSync(keyFile); // the key is no longer on disk: memory is the only source
    const scan = scanProcessMemory(announced.pid);
    const r = judgeExtraction(scan, announced);
    assert.equal(r.result, 'extracted', JSON.stringify({ ...r, pems: scan.pems?.length, secrets: scan.secrets?.length }));
    assert.ok(r.secretRecovered && r.keyRecovered);
    assert.ok(r.bytesScanned > 0);
  } finally {
    child.stdin.end('x');
    child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('judge: an incomplete scan never yields not-extracted', () => {
  const announced = { secretSha256: '0'.repeat(64), publicDer: '00' };
  const base = { status: 'scanned', bytesScanned: 10, pems: [], secrets: [], unreadable: 0, skippedByCap: 0 };
  assert.equal(judgeExtraction(base, announced).result, 'not-extracted');
  assert.equal(judgeExtraction({ ...base, skippedByCap: 1 }, announced).result, 'not-checked');
  assert.equal(judgeExtraction({ ...base, unreadable: 2 }, announced).result, 'not-checked');
});
