#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, lstatSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanTree, severityRank } from '../src/inspect.mjs';
import { auditDockerfile } from '../src/dockerfile-audit.mjs';
import { compareArtifacts } from '../src/benchmark.mjs';

const args = process.argv.slice(2);
function usage() {
  console.log('AppVeil 0.1.0 (experimental)\n\nUsage:\n  appveil inspect <directory> [--json] [--strict]\n  appveil inspect-image <image> [--json] [--strict]\n  appveil audit-dockerfile <Dockerfile> [--json] [--strict]\n  appveil benchmark <artifact1> <artifact2> [...] [--marker <literal>]\n\ninspect-image requires Docker and a locally available image; it uses docker create + docker cp, never starts the container.\nFindings are indicators, not proof that an image is secure.');
}
function run(command, argv) {
  const p = spawnSync(command, argv, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (p.error || p.status !== 0) throw new Error(`${command} failed: ${p.error?.message ?? p.stderr?.trim() ?? p.status}`);
  return p.stdout.trim();
}
function emit(findings, json, strict) {
  if (json) console.log(JSON.stringify({ schemaVersion: 1, findings }, null, 2));
  else {
    if (!findings.length) console.log('No indicators found (NOT a security guarantee).');
    for (const f of findings) console.log(`[${f.severity}] ${f.rule} ${f.path}: ${f.message}`);
    console.log(`\n${findings.length} indicator(s) found. This is not a complete security audit.`);
  }
  if (strict && findings.some(f => severityRank(f.severity) >= severityRank('high'))) process.exitCode = 2;
}
async function main() {
  if (!args.length || ['-h', '--help', 'help'].includes(args[0])) return usage();
  const [command, target] = args;
  if (!target || !['inspect', 'inspect-image', 'audit-dockerfile', 'benchmark'].includes(command)) { usage(); process.exitCode = 1; return; }
  const json = args.includes('--json'), strict = args.includes('--strict');
  if (command === 'audit-dockerfile') {
    const findings = auditDockerfile(target);
    return emit(findings, json, strict);
  }
  if (command === 'benchmark') {
    const idx = args.indexOf('--marker');
    const markers = idx >= 0 && args[idx + 1] ? [args[idx + 1]] : [];
    const paths = args.slice(1).filter(x => !x.startsWith('--') && !markers.includes(x));
    console.log(JSON.stringify(compareArtifacts(paths, markers), null, 2));
    return;
  }
  if (command === 'inspect') {
    const root = realpathSync(target);
    if (!lstatSync(root).isDirectory()) throw new Error('Target must be a directory');
    return emit(scanTree(root), json, strict);
  }
  const temp = mkdtempSync(path.join(tmpdir(), 'appveil-'));
  let container = '';
  try {
    // This never starts the image. Do not execute untrusted image programs.
    container = run('docker', ['create', target]);
    run('docker', ['cp', `${container}:/`, path.join(temp, 'rootfs')]);
    emit(scanTree(path.join(temp, 'rootfs')), json, strict);
  } finally {
    if (container) spawnSync('docker', ['rm', '-f', container], { encoding: 'utf8' });
    rmSync(temp, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(`AppVeil: ${error.message}`); process.exitCode = 1; });
