import test from 'node:test';
import assert from 'node:assert/strict';
import { checkOlaresImageRef } from '../src/olares-image-check.mjs';
const values = 'workloads:\n  api: 1\nimage:\n  server: ghcr.io/example/app:2.0.0\n  docai: image:1\nother:\n  test: true\n';
test('passes on a new immutable-looking tag', () => {
  assert.equal(checkOlaresImageRef(values, { previousImage: 'ghcr.io/example/app:1.0.0' }).pass, true);
});
test('blocks unchanged older release tag', () => {
  const x = checkOlaresImageRef(values, {previousImage:'ghcr.io/example/app:2.0.0'});
  assert.equal(x.pass, false);
  assert.match(x.errors[0], /previous image/);
});
test('enforces real SHA digest shape when requested', () => {
  assert.equal(checkOlaresImageRef(values, {requireDigest:true}).pass,false);
  const digestText=values.replace('ghcr.io/example/app:2.0.0','ghcr.io/example/app@sha256:'+'a'.repeat(64));
  assert.equal(checkOlaresImageRef(digestText, {requireDigest:true}).pass,true);
});
test('rejects latest', () => {
  assert.equal(checkOlaresImageRef(values.replace('2.0.0','latest')).pass,false);
});
