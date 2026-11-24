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
test('on unsupported platforms the lab reports not-checked, never success or failure', () => {
  if (ON_LINUX) return;
  const r = judgeExtraction(scanProcessMemory(process.pid), { secretSha256: '', publicDer: '' });
  assert.equal(r.result, 'not-checked');
});

test('host-root memory extraction recovers the secret and the private key of a software secret module (expected negative result)', { skip: ON_LINUX ? false : '/proc/<pid>/mem required (Linux); CI runs this' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'appveil-extract-'));
  const keyFile = join(dir, 'module-key.pem');
  writeFileSync(keyFile, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const child = spawn(process.execPath, [fileURLToPath(new URL('./helpers/secret-module-child.mjs', import.meta.url)), keyFile], { stdio: ['pipe', 'pipe', 'inherit'] });
  try {
    const announced = await new Promise((resolve, reject) => {
      let buf = '';
      child.stdout.on('data', d => { buf += d; if (buf.includes('\n')) resolve(JSON.parse(buf)); });
      child.on('exit', c => reject(new Error(`child exited ${c}`)));
    });
    rmSync(keyFile); // the key is no longer on disk: memory is the only source
    const scan = scanProcessMemory(announced.pid);
    const r = judgeExtraction(scan, announced);
    assert.equal(r.result, 'extracted', JSON.stringify({ ...r, pems: scan.pems?.length, secrets: scan.secrets?.length }));
    assert.ok(r.secretRecovered && r.keyRecovered);
  } finally {
    child.stdin.end('x');
    child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});
