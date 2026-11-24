#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync, lstatSync, rmSync, realpathSync } from 'node:fs';
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
import { auditImageArchiveFile } from '../src/oci-layers.mjs';
import { compileVeilIRToWasm, wasmDigest } from '../src/veil-wasm.mjs';
import { compileVeilIRv2, evaluateVeilIRv2, loadVeilBytecodeV2, executeVeilBytecodeV2 } from '../src/veil-ir-v2.mjs';
import { compileTypeScriptSubset } from '../src/ts-frontend.mjs';
import { optimizeVeilIRv2 } from '../src/veil-opt.mjs';
import { build, writeBuild, verifyBuild } from '../src/build-manifest.mjs';
import { runRedLab } from '../src/red-lab-run.mjs';

import { parseCommandLine, parseUint32Decimal, usageText, UsageError, EXIT } from '../src/cli-args.mjs';

const argv = process.argv.slice(2);
function usage(stream = console.log) { stream(usageText()); }
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
  if (strict && findings.some(f => severityRank(f.severity) >= severityRank('high'))) process.exitCode = EXIT.POLICY;
}
function emitLayerReport(report, json, strict) {
  if (json) console.log(JSON.stringify(report, null, 2));
  else {
    for (const l of report.layers) console.log(`layer ${l.index} ${l.digest} ${l.compression} ${l.status}${l.reason ? ` (${l.reason})` : ''}`);
    if (!report.findings.length) console.log('No indicators found (NOT a security guarantee).');
    for (const f of report.findings) console.log(`[${f.severity}] ${f.rule} ${f.layer === undefined ? '' : `layer ${f.layer} `}${f.path} (${f.finalFilesystem ?? 'config'}): ${f.message}`);
    console.log(`\n${report.findings.length} indicator(s) across ${report.layers.length} layer(s).${report.complete ? '' : ' INCOMPLETE: some layers were not checked.'} This is not a complete security audit.`);
  }
  // Under --strict an incomplete scan is an error (not checked is never passed), then high findings are a policy violation.
  if (strict && !report.complete) throw new Error('Layer scan incomplete: at least one layer was not checked');
  if (strict && report.findings.some(f => severityRank(f.severity) >= severityRank('high'))) process.exitCode = EXIT.POLICY;
}
async function main() {
  if (!argv.length || ['-h', '--help', 'help'].includes(argv[0])) return usage();
  const { command, positionals, values } = parseCommandLine(argv);
  const [target] = positionals;
  const json = values.json === true, strict = values.strict === true;
  if (command === 'build') {
    const seed = values.seed === undefined ? 0 : parseUint32Decimal(values.seed, '--seed');
    const kind = /\.ts$/i.test(target) ? 'ts' : 'ir';
    const built = build(readFileSync(target, 'utf8'), { kind, seed, optimize: values.optimize === true });
    writeBuild(positionals[1], built);
    console.log(JSON.stringify(built.manifest, null, 2));
    return;
  }
  if (command === 'verify-build') {
    const result = verifyBuild(target, readFileSync(positionals[1], 'utf8'));
    console.log(JSON.stringify(result, null, 2));
    if (!result.reproducible) process.exitCode = EXIT.POLICY;
    return;
  }
  if (command === 'compile-ts') {
    const seed = values.seed === undefined ? 0 : parseUint32Decimal(values.seed, '--seed');
    const compiled = compileTypeScriptSubset(readFileSync(target, 'utf8'));
    // --optimize runs the optimizer, which aborts unless translation validation passes.
    const opt = values.optimize ? optimizeVeilIRv2(compiled.ir) : null;
    const ir = opt ? opt.ir : compiled.ir;
    console.log(JSON.stringify(values.bytecode ? compileVeilIRv2(ir, { seed }) : { functionName: compiled.functionName, outputMap: compiled.outputMap, ir, ...(opt ? { optimization: opt.stats } : {}) }, null, 2));
    return;
  }
  if (command === 'compile-ir-wasm') {
    const bytes = compileVeilIRToWasm(JSON.parse(readFileSync(target, 'utf8')));
    writeFileSync(positionals[1], bytes, { flag: 'wx' }); // never overwrite an existing file
    console.log(JSON.stringify({ wrote: positionals[1], bytes: bytes.length, digest: wasmDigest(bytes), note: 'Wasm is decompilable; this is not a confidentiality mechanism.' }));
    return;
  }
  if (command === 'red-lab-run') {
    const num = (name, dflt) => values[name] === undefined ? dflt : parseUint32Decimal(values[name], `--${name}`);
    const report = await runRedLab({ attack: target, trials: num('trials', 20), size: num('size', 8), seed: num('seed', 1), holdoutCount: num('holdout', 1000), queries: num('queries', 0), defender: values.defender ?? 'veil-vm-v1' });
    // Per-trial results only with --full; the summary is the headline. Success here means the defense failed.
    console.log(JSON.stringify(values.full ? report : { ...report, results: undefined }, null, 2));
    return;
  }
  if (command === 'red-lab-decode') {
    console.log(JSON.stringify(recoverInstructionTraceFile(target), null, 2));
    return;
  }
  if (['compile-ir', 'run-ir', 'run-bytecode'].includes(command)) {
    // Parse numeric arguments before reading files so usage errors are reported first.
    const seed = command === 'compile-ir' ? (values.seed === undefined ? 0 : parseUint32Decimal(values.seed, '--seed')) : undefined;
    const parsed = JSON.parse(readFileSync(target, 'utf8'));
    // Version 2 documents take a JSON object of named inputs (run-ir) or a positional JSON array (run-bytecode).
    if (parsed?.schemaVersion === 2 || parsed?.version === 2) {
      if (command === 'compile-ir') { console.log(JSON.stringify(compileVeilIRv2(values.optimize ? optimizeVeilIRv2(parsed).ir : parsed, { seed }), null, 2)); return; }
      let inputs;
      try { inputs = JSON.parse(positionals[1]); } catch { throw new UsageError('v2 programs take inputs as JSON, e.g. \'{"x":1}\' (run-ir) or \'[1,true]\' (run-bytecode)'); }
      const out = command === 'run-ir' ? evaluateVeilIRv2(parsed, inputs) : executeVeilBytecodeV2(loadVeilBytecodeV2(parsed), inputs);
      console.log(JSON.stringify(out));
      return;
    }
    const input = command === 'compile-ir' ? undefined : parseUint32Decimal(positionals[1], 'input');
    if (command === 'compile-ir') { if (values.optimize) throw new UsageError('--optimize requires an IR v2 document'); console.log(JSON.stringify(compileVeilIR(parsed, { seed }), null, 2)); }
    else console.log(command === 'run-ir' ? evaluateVeilIR(parsed, input) : runVeilBytecode(parsed, input));
    return;
  }
  if (command === 'check-olares-image') {
    const result = checkOlaresValuesFile(target, {
      previousImage: values.previous ?? null,
      requireDigest: values['require-digest'] === true
    });
    console.log(JSON.stringify(result, null, 2));
    if (!result.pass) process.exitCode = EXIT.POLICY;
    return;
  }
  if (command === 'local-ai-trial') {
    console.log(JSON.stringify(await runLocalAiTrial({ artifactPath: target, model: positionals[1] }), null, 2));
    return;
  }
  if (command === 'verify-image-report') {
    const outcome = evaluateImagePolicyFile(target);
    console.log(JSON.stringify(outcome, null, 2));
    if (!outcome.pass) process.exitCode = EXIT.POLICY;
    return;
  }
  if (command === 'evaluate-reconstruction') {
    console.log(JSON.stringify(evaluateFiles(target, positionals[1]), null, 2));
    return;
  }
  if (command === 'audit-dockerfile') return emit(auditDockerfile(target), json, strict);
  if (command === 'benchmark') {
    console.log(JSON.stringify(compareArtifacts(positionals, values.marker ?? [], { notChecked: values['not-checked'] ?? [] }), null, 2));
    return;
  }
  if (command === 'inspect') {
    const root = realpathSync(target);
    if (!lstatSync(root).isDirectory()) throw new Error('Target must be a directory');
    return emit(scanTree(root), json, strict);
  }
  if (command === 'inspect-image-archive') return emitLayerReport(auditImageArchiveFile(target), json, strict);
  // inspect-image
  const temp = mkdtempSync(path.join(tmpdir(), 'appveil-'));
  let container = '';
  try {
    if (values.layers) {
      // `docker save` exports layers and config without running anything from the image.
      const archive = path.join(temp, 'image.tar');
      run('docker', ['save', '-o', archive, target]);
      return emitLayerReport(auditImageArchiveFile(archive), json, strict);
    }
    // This never starts the image. Do not execute untrusted image programs.
    container = run('docker', ['create', target]);
    run('docker', ['cp', `${container}:/`, path.join(temp, 'rootfs')]);
    emit(scanTree(path.join(temp, 'rootfs')), json, strict);
  } finally {
    if (container) spawnSync('docker', ['rm', '-f', container], { encoding: 'utf8' });
    rmSync(temp, { recursive: true, force: true });
  }
}
main().catch(error => {
  console.error(`AppVeil: ${error.message}`);
  if (error instanceof UsageError) console.error('Run `appveil --help` for usage.');
  // Never let a thrown error end in a policy exit code or success.
  process.exitCode = EXIT.ERROR;
});
