import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { readFileSync } from 'node:fs';
import { tar } from './helpers/tar.mjs';
import { verifyChart, parseImageRef } from '../src/chart-verify.mjs';

const affected = JSON.parse(readFileSync(new URL('../data/known-affected-images.json', import.meta.url), 'utf8'));
const D = c => `sha256:${c.repeat(64)}`;
function chart({ version = '1.0.0', manifestVersion = version, server = 'ghcr.io/example/app:1.0.0', docai = 'ghcr.io/example/docai:0.1.0', templateImage = 'docker.io/library/busybox:1.37.0', extra = [] } = {}) {
  return gzipSync(tar([
    { name: 'app/Chart.yaml', data: `apiVersion: v2\nname: app\nversion: ${version}\nappVersion: '${version}'\n` },
    { name: 'app/values.yaml', data: `workloads:\n  app:\n    replicaCount: 1\nimage:\n  server: ${server}\n  docai: '${docai}'\nrouter:\n  baseUrl: ''\n` },
    { name: 'app/OlaresManifest.yaml', data: `olaresManifest.version: '0.12.0'\nmetadata:\n  name: app\n  version: ${manifestVersion}\nspec:\n  versionName: '${manifestVersion}'\n` },
    { name: 'app/templates/deployment.yaml', data: `spec:\n  containers:\n    - name: init\n      image: ${templateImage}\n    - name: app\n      image: {{ .Values.image.server }}\n` },
    ...extra
  ]));
}

test('collects every image reference from values.yaml and literal template images', () => {
  const r = verifyChart(chart(), { affected });
  assert.equal(r.pass, true, JSON.stringify(r.problems));
  assert.deepEqual(r.images.map(i => [i.source, i.ref]), [
    ['values.yaml:image.server', 'ghcr.io/example/app:1.0.0'], ['values.yaml:image.docai', 'ghcr.io/example/docai:0.1.0'], ['templates/deployment.yaml', 'docker.io/library/busybox:1.37.0']
  ]);
  assert.equal(r.chart.version, '1.0.0'); assert.equal(r.olares.version, '1.0.0');
});

test('fails on known-affected tags or digests (literal or resolved), latest, unpinned under policy, and version mismatch', () => {
  const affectedDigest = affected.digests[0].digest;
  assert.match(verifyChart(chart({ server: 'ghcr.io/ryosk7/proofy:2.6.18' }), { affected }).problems[0].problem, /known-affected Proofy/);
  assert.equal(verifyChart(chart({ server: `ghcr.io/ryosk7/proofy@${affectedDigest}` }), { affected }).pass, false);
  const resolved = verifyChart(chart({ server: 'ghcr.io/ryosk7/proofy:2.6.99' }), { affected, resolve: ref => (ref.endsWith('2.6.99') ? { digest: affectedDigest } : { digest: D('a') }) });
  assert.equal(resolved.pass, false, 'a new tag pointing at an affected digest must fail');
  assert.match(verifyChart(chart({ server: 'ghcr.io/example/app:latest' }), { affected }).problems[0].problem, /mutable/);
  const unpinned = verifyChart(chart(), { affected, requireDigest: true });
  assert.equal(unpinned.pass, false);
  assert.equal(unpinned.problems.filter(p => /digest-pinned/.test(p.problem)).length, 3);
  const pinned = verifyChart(chart({ server: `ghcr.io/example/app@${D('b')}`, docai: `ghcr.io/example/docai@${D('c')}`, templateImage: `docker.io/library/busybox@${D('d')}` }), { affected, requireDigest: true });
  assert.equal(pinned.pass, true, JSON.stringify(pinned.problems));
  assert.match(verifyChart(chart({ manifestVersion: '1.0.1' }), { affected }).problems[0].problem, /version mismatch/);
  const unresolved = verifyChart(chart(), { affected, resolve: () => ({ error: 'not found' }) });
  assert.equal(unresolved.pass, false, 'an unresolvable digest is not-checked, never passed');
});

test('malformed archives fail closed', () => {
  assert.throws(() => verifyChart(Buffer.from('not gzip'), { affected }), /not gzip/);
  assert.throws(() => verifyChart(gzipSync(tar([{ name: 'app/values.yaml', data: 'image:\n  server: x:1\n' }])), { affected }), /Chart.yaml/);
  assert.throws(() => verifyChart(gzipSync(tar([{ name: '../evil', data: 'x' }])), { affected }), /Unsafe tar member path/);
  assert.throws(() => verifyChart(Buffer.alloc(17 * 1024 * 1024), { affected }), /too large/);
});

test('image reference parsing', () => {
  assert.deepEqual(parseImageRef(`ghcr.io/a/b:1.2@${D('e')}`), { ref: `ghcr.io/a/b:1.2@${D('e')}`, repository: 'ghcr.io/a/b', tag: '1.2', digest: D('e') });
  assert.deepEqual(parseImageRef('localhost:5000/a/b'), { ref: 'localhost:5000/a/b', repository: 'localhost:5000/a/b', tag: null, digest: null });
});
