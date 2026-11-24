import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { auditFirstPartyExposure, evaluatePackage, findFirstPartyPackages } from '../src/package-exposure.mjs';

function fixtureRoot() {
  const root = mkdtempSync(join(tmpdir(), 'appveil-pkg-'));
  const mk = (rel, body = 'x') => { const f = join(root, rel); mkdirSync(join(f, '..'), { recursive: true }); writeFileSync(f, body); };
  // A first-party package shipping runtime js plus non-runtime artifacts.
  mk('node_modules/@ryosk7/ragturbo/dist/ai/index.js', 'export const x=1');
  mk('node_modules/@ryosk7/ragturbo/dist/ai/index.d.ts', 'export declare const x: number');
  mk('node_modules/@ryosk7/ragturbo/dist/ai/index.js.map', '{"version":3}');
  mk('node_modules/@ryosk7/ragturbo/src/ai/index.ts', 'export const x = 1');
  mk('node_modules/@ryosk7/ragturbo/python/docai/extract.py', 'def f(): pass');
  mk('node_modules/@ryosk7/ragturbo/proto/jobs.proto', 'message J {}');
  mk('node_modules/@ryosk7/ragturbo/tsconfig.json', '{}');
  // A third-party package in the same tree must be ignored.
  mk('node_modules/lodash/index.js', 'module.exports={}');
  mk('node_modules/lodash/index.d.ts', 'declare const _: any');
  // A clean first-party package (compiled js only).
  mk('node_modules/@ryosk7/clean/dist/index.js', 'export const y=2');
  return root;
}

test('flags non-runtime artifacts only in configured first-party scopes', () => {
  const root = fixtureRoot();
  try {
    const r = auditFirstPartyExposure(root, { scopes: ['@ryosk7'] });
    assert.equal(r.pass, false);
    const rt = r.packages.find(p => p.package === '@ryosk7/ragturbo');
    assert.equal(rt.jsFiles, 1);
    assert.deepEqual(rt.counts, { DECLARATION_FILE: 1, SOURCE_MAP: 1, TYPESCRIPT_SOURCE: 1, PYTHON_SOURCE: 1, PROTO_SCHEMA: 1, TS_BUILD_INFO: 1 });
    // proto and build info are reported but do not fail the default policy.
    const rules = new Set(r.violations.map(v => v.rule));
    assert.deepEqual([...rules].sort(), ['DECLARATION_FILE', 'PYTHON_SOURCE', 'SOURCE_MAP', 'TYPESCRIPT_SOURCE']);
    assert.ok(r.violations.every(v => v.package === '@ryosk7/ragturbo'), 'lodash must not be flagged');
    const clean = r.packages.find(p => p.package === '@ryosk7/clean');
    assert.deepEqual(clean.counts, {});
    assert.match(r.ceiling, /Olares administrator/);
    assert.ok(!JSON.stringify(r).includes('def f()'), 'no file contents in output');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('passes when first-party packages ship compiled js only', () => {
  const root = mkdtempSync(join(tmpdir(), 'appveil-pkg-'));
  try {
    mkdirSync(join(root, 'node_modules/@ryosk7/ragturbo/dist'), { recursive: true });
    writeFileSync(join(root, 'node_modules/@ryosk7/ragturbo/dist/index.js'), 'export const x=1');
    const r = auditFirstPartyExposure(root, { scopes: ['@ryosk7'] });
    assert.equal(r.pass, true);
    assert.deepEqual(r.violations, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('does not follow symlinks and rejects a bad scope', () => {
  const root = mkdtempSync(join(tmpdir(), 'appveil-pkg-'));
  try {
    mkdirSync(join(root, 'node_modules/@ryosk7'), { recursive: true });
    symlinkSync('/etc', join(root, 'node_modules/@ryosk7/evil'));
    assert.deepEqual(findFirstPartyPackages(root, ['@ryosk7']), []);
    assert.throws(() => auditFirstPartyExposure(root, { scopes: ['../etc'] }), /Invalid scope/);
    assert.throws(() => auditFirstPartyExposure(root, { scopes: [] }), /at least one/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('CLI: exit 2 under --strict when a first-party package leaks, 0 when clean', () => {
  const cli = fileURLToPath(new URL('../bin/appveil.mjs', import.meta.url));
  const root = fixtureRoot();
  try {
    const dirty = spawnSync(process.execPath, [cli, 'audit-package-exposure', root, '--scope', '@ryosk7', '--strict'], { encoding: 'utf8' });
    assert.equal(dirty.status, 2, dirty.stderr);
    assert.match(dirty.stdout, /FAIL/);
    const noStrict = spawnSync(process.execPath, [cli, 'audit-package-exposure', root, '--scope', '@ryosk7'], { encoding: 'utf8' });
    assert.equal(noStrict.status, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
