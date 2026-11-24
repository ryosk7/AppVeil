import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCommandLine, COMMANDS, UsageError } from '../src/cli-args.mjs';

const cli = fileURLToPath(new URL('../bin/appveil.mjs', import.meta.url));
const example = fileURLToPath(new URL('../examples/veil-ir-score.json', import.meta.url));
// PATH is emptied so no command can reach Docker, Ollama or any other external tool.
const run = (...argv) => spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8', env: { PATH: '' } });

function fixtures() {
  const dir = mkdtempSync(join(tmpdir(), 'appveil-contract-'));
  const clean = join(dir, 'clean'); mkdirSync(clean); writeFileSync(join(clean, 'index.js'), 'export const x = 1;\n');
  const dirty = join(dir, 'dirty'); mkdirSync(dirty); writeFileSync(join(dirty, 'app.ts'), 'export const x: number = 1;\n'); writeFileSync(join(dirty, '.env'), 'X=1\n');
  writeFileSync(join(dir, 'Dockerfile.clean'), 'FROM node:20-slim\nUSER node\nCMD ["node","index.js"]\n');
  writeFileSync(join(dir, 'pass-report.json'), JSON.stringify({ schemaVersion: 1, findings: [] }));
  writeFileSync(join(dir, 'fail-report.json'), JSON.stringify({ schemaVersion: 1, findings: [{ path: 'app/web/assets/app.js.map', rule: 'SOURCE_MAP' }] }));
  writeFileSync(join(dir, 'values-ok.yaml'), 'image:\n  server: ghcr.io/example/app:2.0.0\n');
  writeFileSync(join(dir, 'values-latest.yaml'), 'image:\n  server: ghcr.io/example/app:latest\n');
  writeFileSync(join(dir, 'inputs.json'), '[1,2]');
  writeFileSync(join(dir, 'predictions.json'), '[0,0]');
  writeFileSync(join(dir, 'a.js'), 'const a = 1;'); writeFileSync(join(dir, 'b.js'), 'const b = 2;');
  writeFileSync(join(dir, 'broken.json'), '{not json');
  return dir;
}

test('parser: every command rejects unknown options, extra positionals and missing values', () => {
  for (const [name, spec] of Object.entries(COMMANDS)) {
    const pos = spec.positionals.map((_, i) => `p${i}`);
    assert.throws(() => parseCommandLine([name, ...pos, '--definitely-unknown']), UsageError, `${name} unknown flag`);
    assert.throws(() => parseCommandLine([name, ...pos.slice(0, -1)]), UsageError, `${name} too few args`);
    if (!spec.variadic) assert.throws(() => parseCommandLine([name, ...pos, 'extra']), UsageError, `${name} extra arg`);
    for (const [opt, d] of Object.entries(spec.options)) {
      if (d.type === 'string') {
        assert.throws(() => parseCommandLine([name, ...pos, `--${opt}`]), UsageError, `${name} --${opt} missing value`);
        assert.throws(() => parseCommandLine([name, ...pos, `--${opt}=`]), UsageError, `${name} --${opt} empty value`);
      } else {
        assert.throws(() => parseCommandLine([name, ...pos, `--${opt}=yes`]), UsageError, `${name} boolean --${opt} with value`);
      }
    }
    assert.doesNotThrow(() => parseCommandLine([name, ...pos]), `${name} minimal valid form`);
  }
  assert.throws(() => parseCommandLine(['nope']), /Unknown command/);
  assert.throws(() => parseCommandLine(['__proto__', 'x']), /Unknown command/);
  assert.throws(() => parseCommandLine([]), /Missing command/);
});

test('CLI exit contract: 0 success, 1 usage/input/execution error, 2 policy violation', () => {
  const d = fixtures();
  try {
    const cases = [
      // [argv, expected status]
      [['--help'], 0],
      [[], 0],
      [['no-such-command', 'x'], 1],
      [['inspect', join(d, 'clean')], 0],
      [['inspect', join(d, 'clean'), '--strict'], 0],
      [['inspect', join(d, 'dirty'), '--json'], 0],
      [['inspect', join(d, 'dirty'), '--strict'], 2],
      [['inspect', join(d, 'missing')], 1],
      [['inspect', join(d, 'clean'), '--stirct'], 1],
      [['inspect', join(d, 'clean'), join(d, 'dirty')], 1],
      [['audit-dockerfile', join(d, 'Dockerfile.clean'), '--json'], 0],
      [['audit-dockerfile', join(d, 'missing')], 1],
      [['verify-image-report', join(d, 'pass-report.json')], 0],
      [['verify-image-report', join(d, 'fail-report.json')], 2],
      [['verify-image-report', join(d, 'broken.json')], 1],
      [['check-olares-image', join(d, 'values-ok.yaml')], 0],
      [['check-olares-image', join(d, 'values-latest.yaml')], 2],
      [['check-olares-image', join(d, 'values-ok.yaml'), '--previous'], 1],
      [['check-olares-image', join(d, 'values-ok.yaml'), '--previous', 'ghcr.io/example/app:2.0.0'], 2],
      [['check-olares-image', join(d, 'values-ok.yaml'), '--require-digest'], 2],
      [['evaluate-reconstruction', join(d, 'predictions.json'), join(d, 'inputs.json')], 0],
      [['evaluate-reconstruction', join(d, 'predictions.json')], 1],
      [['benchmark', join(d, 'a.js'), join(d, 'b.js'), '--marker', 'const'], 0],
      [['benchmark', join(d, 'a.js')], 1],
      [['benchmark', join(d, 'a.js'), join(d, 'b.js'), '--marker'], 1],
      [['compile-ir', example, '--seed', '7'], 0],
      [['compile-ir', example, '--seed', '-1'], 1],
      [['compile-ir', join(d, 'broken.json')], 1],
      [['run-ir', example, '17'], 0],
      [['run-ir', example, '17', '18'], 1],
      [['run-ir', example, '-1'], 1],
      [['red-lab-decode', join(d, 'broken.json')], 1],
      [['red-lab-run', 'static-decompile', '--trials', '2', '--holdout', '20'], 0],
      [['red-lab-run', 'no-such-attack'], 1],
      [['red-lab-run', 'static-decompile', '--trials', '0'], 1],
      // Docker is unreachable (empty PATH): an execution error, never success or policy.
      [['inspect-image', 'example.invalid/none:1'], 1],
      [['local-ai-trial', join(d, 'a.js'), 'model'], 1]
    ];
    for (const [argv, status] of cases) {
      const r = run(...argv);
      assert.equal(r.status, status, `appveil ${argv.join(' ')} -> ${r.status}, expected ${status}\n${r.stderr}`);
      if (status === 1 && argv.length) assert.match(r.stderr, /^AppVeil: /m, `error message for ${argv.join(' ')}`);
    }
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test('help documents the exit-status contract', () => {
  const r = run('--help');
  assert.match(r.stdout, /Exit status: 0 = success/);
  for (const name of Object.keys(COMMANDS)) assert.match(r.stdout, new RegExp(`appveil ${name} `));
});
