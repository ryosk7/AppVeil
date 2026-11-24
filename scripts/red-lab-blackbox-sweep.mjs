#!/usr/bin/env node
// Success-vs-budget sweep for the non-AI black-box baseline (issue #14). Synthetic challenges only.
// usage: node scripts/red-lab-blackbox-sweep.mjs [trials=30] [maxSize=8]
import { execSync } from 'node:child_process';
import os from 'node:os';
import { runRedLab } from '../src/red-lab-run.mjs';
const trials = Number(process.argv[2] ?? 30), maxSize = Number(process.argv[3] ?? 8);
const rows = [];
for (let size = 1; size <= maxSize; size++) {
  for (const queries of [8, 32, 128]) {
    const t = Date.now();
    const r = await runRedLab({ attack: 'blackbox-enum', trials, size, seed: 1, holdoutCount: 1000, queries });
    const exact = r.results.filter(x => x.exactOnHoldout).length;
    const submitted = r.results.filter(x => x.submission === 'ir').length;
    rows.push({ size, queries, trials, exact, submittedButWrong: submitted - exact, noSubmission: trials - submitted, successRate: r.summary.successRate, wilson95: r.summary.wilson95.map(v => +v.toFixed(3)), meanAccuracy: +r.summary.meanAccuracy.toFixed(3), wallMs: Date.now() - t });
    console.error(JSON.stringify(rows.at(-1)));
  }
}
let commit = 'unknown'; try { commit = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim(); } catch {}
console.log(JSON.stringify({ schemaVersion: 1, attack: 'blackbox-enum', budgets: { timeMsPerTrial: 1000, maxTerms: 20000 }, commit, node: process.version, cpu: os.cpus()[0]?.model, rows }, null, 2));
