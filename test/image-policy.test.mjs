import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateImagePolicy } from '../src/image-policy.mjs';
test('rejects first-party source map and source reference', () => {
  const result = evaluateImagePolicy({schemaVersion:1,findings:[
    {path:'app/web/assets/app.js.map',rule:'EMBEDDED_SOURCE_CONTENT'},
    {path:'app/apps/server/dist/main.js',rule:'SOURCEMAP_REFERENCE'},
    {path:'app/node_modules/any/package.js.map',rule:'SOURCE_MAP'}
  ]});
  assert.equal(result.pass,false);
  assert.equal(result.violations.length,2);
});
test('does not flag vendor source maps in first-party policy', () => {
  const result = evaluateImagePolicy({schemaVersion:1,findings:[
    {path:'app/node_modules/any/package.js.map',rule:'SOURCE_MAP'}
  ]});
  assert.equal(result.pass,true);
});
test('does not accept invalid reports', () => {
  assert.throws(()=>evaluateImagePolicy({findings:[]}));
});
