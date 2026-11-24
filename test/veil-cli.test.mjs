import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { oracle } from '../src/reconstruction-eval.mjs';

const cli = fileURLToPath(new URL('../bin/appveil.mjs', import.meta.url));
const example = fileURLToPath(new URL('../examples/veil-ir-score.json', import.meta.url));
const run = (...argv) => spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8' });

test('CLI run-ir, compile-ir and run-bytecode round-trip the documented example', () => {
  const dir = mkdtempSync(join(tmpdir(), 'appveil-cli-'));
  try {
    for (const x of ['0', '17', '4294967295']) {
      const r = run('run-ir', example, x);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stdout.trim(), String(oracle(Number(x))));
    }
    const compiled = run('compile-ir', example, '--seed', '42');
    assert.equal(compiled.status, 0, compiled.stderr);
    assert.equal(JSON.parse(compiled.stdout).seed, 42);
    const bytecode = join(dir, 'score-42.json');
    writeFileSync(bytecode, compiled.stdout);
    const r = run('run-bytecode', bytecode, '17');
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), String(oracle(17)));
    const decoded = run('red-lab-decode', bytecode);
    assert.equal(decoded.status, 0, decoded.stderr);
    assert.ok(JSON.parse(decoded.stdout).recovered.some(x => x.operation === 'mul'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI rejects non-decimal or out-of-range uint32 input and seed with nonzero exit', () => {
  for (const bad of ['', '-1', '1.5', '1e3', '0x10', '+1', '01', ' 1', '4294967296', '99999999999']) {
    const r = run('run-ir', example, bad);
    assert.equal(r.status, 1, `input ${JSON.stringify(bad)} accepted`);
    assert.match(r.stderr, /uint32 decimal integer/);
    const s = run('compile-ir', example, '--seed', bad);
    assert.equal(s.status, 1, `seed ${JSON.stringify(bad)} accepted`);
    assert.match(s.stderr, /--seed as a uint32 decimal integer/);
  }
  const missingInput = run('run-ir', example);
  assert.equal(missingInput.status, 1);
  const missingSeed = run('compile-ir', example, '--seed');
  assert.equal(missingSeed.status, 1);
  assert.match(missingSeed.stderr, /--seed/);
});
