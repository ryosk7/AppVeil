#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, lstatSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanTree, severityRank } from '../src/inspect.mjs';
import { auditDockerfile } from '../src/dockerfile-audit.mjs';
import { compareArtifacts } from '../src/benchmark.mjs';
import { evaluateFiles } from '../src/reconstruction-eval.mjs';
import { evaluateImagePolicyFile } from '../src/image-policy.mjs';
import { runLocalAiTrial } from '../src/local-ai-trial.mjs';
import { checkOlaresValuesFile } from '../src/olares-image-check.mjs';
import { compileVeilIR, runVeilBytecode, evaluateVeilIR } from '../src/veil-ir.mjs';
import { recoverInstructionTraceFile } from '../src/red-lab.mjs';

const args = process.argv.slice(2);
function usage() {
  console.log('AppVeil 0.1.0 (experimental)\n\nUsage:\n  appveil inspect <directory> [--json] [--strict]\n  appveil inspect-image <image> [--json] [--strict]\n  appveil audit-dockerfile <Dockerfile> [--json] [--strict]\n  appveil benchmark <artifact1> <artifact2> [...] [--marker <literal>]\n  appveil evaluate-reconstruction <predictions.json> <inputs.json>\n  appveil verify-image-report <image-audit.json>\n  appveil local-ai-trial <synthetic-artifact> <installed-ollama-model>\n  appveil check-olares-image <values.yaml> [--previous <image-ref>] [--require-digest]\n  appveil compile-ir <ir.json> [--seed <uint32>]\n  appveil run-ir <ir.json> <uint32-input>\n  appveil run-bytecode <bytecode.json> <uint32-input>\n  appveil red-lab-decode <bytecode.json>\n\ninspect-image requires Docker and a locally available image; it uses docker create + docker cp, never starts the container.\nFindings are indicators, not proof that an image is secure.');
}
/** Strict decimal uint32 parser: rejects empty, hex, signs, exponents, fractions and out-of-range values. */
function parseUint32Decimal(text, name) {
  if (typeof text !== 'string' || !/^(0|[1-9]\d{0,9})$/.test(text)) throw new Error(`Specify ${name} as a uint32 decimal integer`);
  const value = Number(text);
  if (value > 0xffffffff) throw new Error(`Specify ${name} as a uint32 decimal integer`);
  return value;
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
  if (!target || !['inspect', 'inspect-image', 'audit-dockerfile', 'benchmark', 'evaluate-reconstruction', 'verify-image-report', 'local-ai-trial', 'check-olares-image', 'compile-ir', 'run-ir', 'run-bytecode', 'red-lab-decode'].includes(command)) { usage(); process.exitCode = 1; return; }
  const json = args.includes('--json'), strict = args.includes('--strict');
  if (command === 'red-lab-decode') {
    console.log(JSON.stringify(recoverInstructionTraceFile(target), null, 2));
    return;
  }
  if (['compile-ir', 'run-ir', 'run-bytecode'].includes(command)) {
    const parsed = JSON.parse(readFileSync(target, 'utf8'));
    if (command === 'compile-ir') {
      const idx = args.indexOf('--seed');
      const seed = idx < 0 ? 0 : parseUint32Decimal(args[idx + 1], '--seed');
      console.log(JSON.stringify(compileVeilIR(parsed, { seed }), null, 2));
    } else {
      const input = parseUint32Decimal(args[2], 'input');
      console.log(command === 'run-ir' ? evaluateVeilIR(parsed, input) : runVeilBytecode(parsed, input));
    }
    return;
  }
  if (command === 'check-olares-image') {
    const index = args.indexOf('--previous');
    if (index !== -1 && !args[index + 1]) throw new Error('Missing value for --previous');
    const result = checkOlaresValuesFile(target, {
      previousImage: index === -1 ? null : args[index + 1],
      requireDigest: args.includes('--require-digest')
    });
    console.log(JSON.stringify(result, null, 2));
    if (!result.pass) process.exitCode = 2;
    return;
  }
  if (command === 'local-ai-trial') {
    if (!args[2]) throw new Error('Specify an installed local Ollama model name');
    console.log(JSON.stringify(await runLocalAiTrial({ artifactPath: target, model: args[2] }), null, 2));
    return;
  }
  if (command === 'verify-image-report') {
    const outcome = evaluateImagePolicyFile(target);
    console.log(JSON.stringify(outcome, null, 2));
    if (!outcome.pass) process.exitCode = 2;
    return;
  }
  if (command === 'evaluate-reconstruction') {
    if (!args[2]) throw new Error('Provide both prediction and input JSON files');
    console.log(JSON.stringify(evaluateFiles(target, args[2]), null, 2));
    return;
  }
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
