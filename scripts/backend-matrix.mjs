#!/usr/bin/env node
// usage: node scripts/backend-matrix.mjs [ir.json=examples/veil-ir-score.json] [--challenge-size N]
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import os from 'node:os';
import { runBackendMatrix } from '../src/backend-matrix.mjs';
import { generateChallenge } from '../src/red-lab-harness.mjs';
import { sha256Canonical } from '../src/veil-ir.mjs';
const sizeIdx = process.argv.indexOf('--challenge-size');
const ir = sizeIdx > 0 ? generateChallenge({ seed: 1, size: Number(process.argv[sizeIdx + 1]) })
  : JSON.parse(readFileSync(process.argv[2] ?? new URL('../examples/veil-ir-score.json', import.meta.url), 'utf8'));
const report = await runBackendMatrix(ir);
let commit = 'unknown'; try { commit = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim(); } catch {}
console.log(JSON.stringify({ ...report, commit, irDigest: sha256Canonical(ir), platform: `${os.platform()} ${os.release()} ${os.arch()}`, cpu: os.cpus()[0]?.model }, null, 2));
if (report.rows.some(r => r.status === 'incorrect')) process.exit(1);
