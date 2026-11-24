import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { build, writeBuild, verifyBuild } from '../src/build-manifest.mjs';
import { GOLDEN_CORPUS } from './golden/corpus.mjs';

const golden = JSON.parse(readFileSync(new URL('./golden/build-digests.json', import.meta.url), 'utf8'));
const src = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

test('golden digests: every corpus build is byte-identical to the committed digests (any OS / Node)', () => {
  assert.deepEqual(Object.keys(golden).sort(), GOLDEN_CORPUS.map(c => c.id).sort());
  for (const c of GOLDEN_CORPUS) {
    const { manifest } = build(src(c.file), c.options);
    assert.equal(manifest.source.sha256, golden[c.id].sourceSha256, `${c.id}: source changed (update the golden file only for intentional changes)`);
    assert.deepEqual(Object.fromEntries(Object.entries(manifest.outputs).map(([k, v]) => [k, v.sha256])), golden[c.id].outputs, `${c.id}: build output changed`);
  }
});

test('separate processes produce byte-identical build directories; verify-build detects tampering', () => {
  const cli = fileURLToPath(new URL('../bin/appveil.mjs', import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), 'appveil-repro-'));
  try {
    const ts = fileURLToPath(new URL('../examples/ts/score.ts', import.meta.url));
    for (const name of ['a', 'b']) {
      // Different environment values and working directories must not affect output.
      const r = spawnSync(process.execPath, [cli, 'build', ts, join(dir, name), '--seed', '7', '--optimize'], { encoding: 'utf8', cwd: name === 'a' ? dir : tmpdir(), env: { ...process.env, TZ: name === 'a' ? 'UTC' : 'Asia/Tokyo', LANG: name === 'a' ? 'C' : 'ja_JP.UTF-8' } });
      assert.equal(r.status, 0, r.stderr);
    }
    for (const f of ['ir.json', 'bytecode.json', 'manifest.json']) assert.deepEqual(readFileSync(join(dir, 'a', f)), readFileSync(join(dir, 'b', f)), f);
    assert.equal(verifyBuild(join(dir, 'a'), src('examples/ts/score.ts')).reproducible, true);
    writeFileSync(join(dir, 'a', 'bytecode.json'), readFileSync(join(dir, 'a', 'bytecode.json'), 'utf8').replace('"seed":7', '"seed":8'));
    const v = verifyBuild(join(dir, 'a'), src('examples/ts/score.ts'));
    assert.equal(v.reproducible, false);
    assert.ok(v.problems.some(p => /bytecode.json/.test(p)));
    assert.equal(verifyBuild(join(dir, 'b'), src('examples/ts/score.ts') + '\n').reproducible, false, 'source change must be detected');
    assert.throws(() => writeBuild(join(dir, 'b'), build(src('examples/ts/score.ts'), { kind: 'ts' })), /already exists/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('manifest contains no timestamps, paths or environment data; IR key order does not change outputs except the source digest', () => {
  const { files, manifest } = build(src('examples/veil-ir-v2-clamp.json'), { kind: 'ir', seed: 3 });
  const text = files['manifest.json'];
  assert.doesNotMatch(text, /20\d\d-\d\d-\d\d|\/Users\/|\/home\/|\\\\|hostname/i);
  const reordered = JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(src('examples/veil-ir-v2-clamp.json'))).reverse()));
  const again = build(reordered, { kind: 'ir', seed: 3 });
  assert.notEqual(again.manifest.source.sha256, manifest.source.sha256);
  assert.equal(again.manifest.outputs['ir.json'].sha256, manifest.outputs['ir.json'].sha256);
  assert.equal(again.manifest.outputs['bytecode.json'].sha256, manifest.outputs['bytecode.json'].sha256);
});
