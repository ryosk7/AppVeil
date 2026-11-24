import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tar } from './helpers/tar.mjs';
import { auditImageArchive, parseTar, normalizeMemberPath, scanImageConfig } from '../src/oci-layers.mjs';

const SECRET_VALUE = 'FAKE-VALUE-should-never-appear-0123456789';
const mapWithSource = JSON.stringify({ version: 3, sources: ['a.ts'], sourcesContent: ['export const secretLogic = 1;'] });
function image({ layers, env = [], history = [], gzip = [] }) {
  const config = Buffer.from(JSON.stringify({ config: { Env: env }, history }));
  const files = [{ name: 'config.json', data: config }];
  const names = layers.map((l, i) => {
    let blob = tar(l);
    if (gzip.includes(i)) blob = gzipSync(blob);
    const name = `blobs/sha256/layer${i}`;
    files.push({ name, data: blob });
    return name;
  });
  files.push({ name: 'manifest.json', data: JSON.stringify([{ Config: 'config.json', RepoTags: ['example/app:1'], Layers: names }]) });
  return tar(files);
}

test('reports files deleted by whiteouts and overwritten in later layers as recoverable', () => {
  const r = auditImageArchive(image({
    layers: [
      [{ name: 'app/web/assets/app.js.map', data: mapWithSource }, { name: 'app/.env', data: `TOKEN=${SECRET_VALUE}` }, { name: 'app/src/main.ts', data: 'x' }],
      [{ name: 'app/web/assets/.wh.app.js.map' }, { name: 'app/.env', data: 'X=1' }],
      [{ name: 'app/src/.wh..wh..opq' }]
    ],
    gzip: [1]
  }));
  assert.equal(r.complete, true);
  assert.deepEqual(r.layers.map(l => [l.status, l.compression]), [['scanned', 'none'], ['scanned', 'gzip'], ['scanned', 'none']]);
  const by = (rule, layer) => r.findings.find(f => f.rule === rule && f.layer === layer);
  assert.equal(by('SOURCE_MAP', 0).finalFilesystem, 'deleted');
  assert.equal(by('EMBEDDED_SOURCE_CONTENT', 0).finalFilesystem, 'deleted');
  assert.match(by('SOURCE_MAP', 0).message, /still recoverable from layer 0/);
  assert.equal(by('ENV_FILE', 0).finalFilesystem, 'overwritten');
  assert.equal(by('ENV_FILE', 1).finalFilesystem, 'present');
  assert.equal(by('TYPESCRIPT_SOURCE', 0).finalFilesystem, 'deleted');
  assert.match(by('SOURCE_MAP', 0).layerDigest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(r).includes(SECRET_VALUE), 'file contents leaked into report');
  assert.ok(!JSON.stringify(r).includes('secretLogic'), 'source-map contents leaked into report');
});

test('flags secret-like env and build-arg NAMES in config and history, never values', () => {
  const r = auditImageArchive(image({
    layers: [[{ name: 'app/index.js', data: 'x' }]],
    env: ['PATH=/usr/bin', `NPM_TOKEN=${SECRET_VALUE}`, `DB_PASSWORD=${SECRET_VALUE}`, 'NODE_ENV=production'],
    history: [{ created_by: `|2 GITHUB_TOKEN=${SECRET_VALUE} VERSION=1 /bin/sh -c npm ci` }, { created_by: 'ARG API_KEY' }, { created_by: 'ENV PORT=3000' }]
  }));
  const paths = r.findings.map(f => f.path).sort();
  assert.deepEqual(paths, ['config:Env/DB_PASSWORD', 'config:Env/NPM_TOKEN', 'config:history/0/GITHUB_TOKEN', 'config:history/1/API_KEY']);
  assert.ok(!JSON.stringify(r).includes(SECRET_VALUE));
  assert.deepEqual(scanImageConfig({ config: { Env: ['PASSAGE=1', 'BYPASS_CACHE=1', 'AUTHOR=x'] } }), []);
  // Real BuildKit history format (observed with Docker 28): `RUN |N NAME=value /bin/sh -c ...`.
  const bk = scanImageConfig({ history: [{ created_by: `RUN |1 NPM_TOKEN=${SECRET_VALUE} /bin/sh -c rm x # buildkit` }, { created_by: '/bin/sh -c #(nop)  ARG SIGNING_KEY' }] });
  assert.deepEqual(bk.map(f => f.path), ['config:history/0/NPM_TOKEN', 'config:history/1/SIGNING_KEY']);
  assert.ok(!JSON.stringify(bk).includes(SECRET_VALUE));
});

test('unsupported (zstd) layers make the report incomplete, never passed', () => {
  const archive = image({ layers: [[{ name: 'a', data: 'x' }]] });
  const zstd = Buffer.concat([Buffer.from([0x28, 0xb5, 0x2f, 0xfd]), Buffer.alloc(16)]);
  const files = [{ name: 'config.json', data: '{}' }, { name: 'l0', data: zstd }, { name: 'manifest.json', data: JSON.stringify([{ Config: 'config.json', Layers: ['l0'] }]) }];
  const r = auditImageArchive(tar(files));
  assert.equal(r.complete, false);
  assert.equal(r.layers[0].status, 'not-checked');
  assert.ok(auditImageArchive(archive).complete);
});

test('malformed and hostile archives fail closed', () => {
  assert.throws(() => normalizeMemberPath('../etc/passwd'), /Unsafe tar member path/);
  assert.throws(() => normalizeMemberPath('/etc/passwd'), /Unsafe tar member path/);
  assert.throws(() => normalizeMemberPath('a/../../b'), /Unsafe tar member path/);
  assert.equal(normalizeMemberPath('./a//b/'), 'a/b');
  assert.throws(() => parseTar(tar([{ name: 'x/../../evil', data: 'x' }])), /Unsafe/);
  const corrupt = tar([{ name: 'a', data: 'x' }]); corrupt[0] ^= 0xff;
  assert.throws(() => parseTar(corrupt), /checksum/);
  assert.throws(() => parseTar(tar([{ name: 'a', data: 'x'.repeat(600) }]).subarray(0, 700)), /Truncated/);
  assert.throws(() => parseTar(tar([{ name: 'a' }, { name: 'b' }, { name: 'c' }]), { maxEntries: 2 }), /entry limit/);
  assert.throws(() => auditImageArchive(tar([{ name: 'x', data: '1' }])), /manifest.json/);
  assert.throws(() => auditImageArchive(tar([{ name: 'manifest.json', data: '{' }])), /Malformed JSON/);
  assert.throws(() => auditImageArchive(tar([{ name: 'manifest.json', data: '[{},{}]' }])), /exactly one image/);
  assert.throws(() => auditImageArchive(tar([{ name: 'manifest.json', data: JSON.stringify([{ Config: 'c', Layers: ['missing'] }]) }, { name: 'c', data: '{}' }])), /Layer blob not found/);
  const bomb = tar([{ name: 'config.json', data: '{}' }, { name: 'l', data: gzipSync(Buffer.alloc(4096)) }, { name: 'manifest.json', data: JSON.stringify([{ Config: 'config.json', Layers: ['l'] }]) }]);
  assert.throws(() => auditImageArchive(bomb, { maxLayerBytes: 1024 }), /buffer|length|larger/i);
});

test('long names via ustar prefix are parsed', () => {
  const long = `app/web/${'d'.repeat(120)}/bundle.js.map`;
  assert.equal(parseTar(tar([{ name: long, data: '{}' }]))[0].name, long);
});

test('CLI inspect-image-archive: exit 0 clean, 2 strict violation, 1 incomplete or malformed', () => {
  const cli = fileURLToPath(new URL('../bin/appveil.mjs', import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), 'appveil-oci-'));
  try {
    const clean = join(dir, 'clean.tar'), dirty = join(dir, 'dirty.tar'), bad = join(dir, 'bad.tar'), partial = join(dir, 'partial.tar');
    writeFileSync(clean, image({ layers: [[{ name: 'app/index.js', data: 'x' }]] }));
    writeFileSync(dirty, image({ layers: [[{ name: 'app/web/a.js.map', data: mapWithSource }], [{ name: 'app/web/.wh.a.js.map' }]] }));
    writeFileSync(bad, 'not a tar');
    writeFileSync(partial, tar([{ name: 'c', data: '{}' }, { name: 'l', data: Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0, 0]) }, { name: 'manifest.json', data: JSON.stringify([{ Config: 'c', Layers: ['l'] }]) }]));
    const run = (...a) => spawnSync(process.execPath, [cli, 'inspect-image-archive', ...a], { encoding: 'utf8' });
    assert.equal(run(clean, '--strict').status, 0);
    assert.equal(run(dirty).status, 0);
    const strict = run(dirty, '--strict', '--json');
    assert.equal(strict.status, 2);
    assert.equal(JSON.parse(strict.stdout).findings.find(f => f.rule === 'EMBEDDED_SOURCE_CONTENT').finalFilesystem, 'deleted');
    assert.equal(run(bad).status, 1);
    const p = run(partial, '--strict');
    assert.equal(p.status, 1);
    assert.match(p.stderr, /incomplete/i);
    assert.equal(run(partial).status, 0, 'without --strict an incomplete scan is reported, not failed');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
