import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalJson, compileVeilIR, validateVeilIR } from './veil-ir.mjs';
import { compileVeilIRv2, validateVeilIRv2 } from './veil-ir-v2.mjs';
import { compileTypeScriptSubset } from './ts-frontend.mjs';
import { optimizeVeilIRv2 } from './veil-opt.mjs';
import { compileVeilIRToWasm } from './veil-wasm.mjs';

/**
 * Reproducible builds (issue #18). A build is a pure function of (source bytes, compiler version,
 * options). Outputs are serialized as canonical JSON (sorted keys, no whitespace) plus a trailing
 * newline; no timestamps, paths, hostnames or environment values enter any artifact or the manifest.
 */
const PKG = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
export const COMPILER = Object.freeze({ name: 'appveil', version: PKG.version });
const sha = b => createHash('sha256').update(b).digest('hex');
export const serialize = v => `${canonicalJson(v)}\n`;

/** Build from source text. kind: 'ts' | 'ir'. Returns { files: { name: Buffer|string }, manifest }. */
export function build(sourceText, { kind, seed = 0, optimize = false } = {}) {
  if (!['ts', 'ir'].includes(kind)) throw new Error('kind must be ts or ir');
  if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff) throw new TypeError('seed must be uint32');
  let ir, irVersion, extra = {};
  if (kind === 'ts') { const c = compileTypeScriptSubset(sourceText); ir = c.ir; irVersion = 2; extra = { functionName: c.functionName, outputMap: c.outputMap }; }
  else {
    const doc = JSON.parse(sourceText);
    irVersion = doc?.schemaVersion;
    if (irVersion === 1) validateVeilIR(doc); else if (irVersion === 2) validateVeilIRv2(doc); else throw new Error('Unsupported IR version');
    ir = doc;
  }
  let optimization = null;
  if (optimize) {
    if (irVersion !== 2) throw new Error('optimize requires IR v2');
    const o = optimizeVeilIRv2(ir); ir = o.ir; optimization = o.stats;
  }
  const files = {};
  files['ir.json'] = serialize(ir);
  files['bytecode.json'] = serialize(irVersion === 1 ? compileVeilIR(ir, { seed }) : compileVeilIRv2(ir, { seed }));
  if (irVersion === 1) files['module.wasm'] = Buffer.from(compileVeilIRToWasm(ir));
  const manifest = {
    schemaVersion: 1,
    compiler: COMPILER,
    source: { kind, sha256: sha(sourceText), bytes: Buffer.byteLength(sourceText) },
    options: { seed, optimize },
    irVersion,
    ...extra,
    ...(optimization ? { optimization: { sizeBefore: optimization.sizeBefore, sizeAfter: optimization.sizeAfter, validatedInputs: optimization.validatedInputs } } : {}),
    outputs: Object.fromEntries(Object.entries(files).map(([name, data]) => [name, { sha256: sha(data), bytes: Buffer.byteLength(data) }])),
    note: 'Reproducibility supports auditing; it does not provide secrecy.'
  };
  files['manifest.json'] = serialize(manifest);
  return { files, manifest };
}

/** Write a build to a NEW directory (refuses to overwrite). */
export function writeBuild(outDir, built) {
  if (existsSync(outDir)) throw new Error(`Output directory already exists: ${outDir}`);
  mkdirSync(outDir, { recursive: true });
  for (const [name, data] of Object.entries(built.files)) writeFileSync(path.join(outDir, name), data, { flag: 'wx' });
}

/** Verify a build directory against its manifest and against a fresh rebuild from `sourceText`. */
export function verifyBuild(outDir, sourceText) {
  const manifest = JSON.parse(readFileSync(path.join(outDir, 'manifest.json'), 'utf8'));
  const problems = [];
  for (const [name, { sha256 }] of Object.entries(manifest.outputs)) {
    const actual = sha(readFileSync(path.join(outDir, name)));
    if (actual !== sha256) problems.push(`${name}: digest ${actual} does not match manifest`);
  }
  if (sourceText !== undefined) {
    // A different source is a reproducibility failure, not an error: report it and skip the rebuild.
    if (sha(sourceText) !== manifest.source.sha256) problems.push('source digest does not match manifest');
    else {
      const again = build(sourceText, { kind: manifest.source.kind, ...manifest.options });
      for (const [name, data] of Object.entries(again.files)) {
        if (sha(data) !== sha(readFileSync(path.join(outDir, name)))) problems.push(`${name}: rebuild is not byte-identical`);
      }
    }
  }
  return { reproducible: problems.length === 0, problems };
}
