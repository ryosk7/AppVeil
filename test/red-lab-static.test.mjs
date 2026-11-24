import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { decompileBytecodeV1, staticDecompileAttack } from '../src/red-lab-attacks.mjs';
import { runRedLab } from '../src/red-lab-run.mjs';
import { createTrial, destroyTrial } from '../src/red-lab-harness.mjs';
import { compileVeilIR, sha256Canonical } from '../src/veil-ir.mjs';

test('static decompiler recovers the exact reference tree for every seed (expected defense failure)', () => {
  const r = runRedLab({ attack: 'static-decompile', trials: 40, size: 12, seed: 7, holdoutCount: 300 });
  assert.equal(r.summary.exactRecoveries, 40);
  assert.equal(r.summary.meanAccuracy, 1);
  for (const res of r.results) { assert.equal(res.attackClass, 'static'); assert.equal(res.error, null); }
});

test('decompiled IR is structurally identical to the reference, not merely equivalent', () => {
  const t = createTrial({ challengeSeed: 99, size: 15, holdoutCount: 50 });
  try {
    const { submission } = staticDecompileAttack(t.attackerDir);
    const reference = JSON.parse(readFileSync(path.join(t.judgeDir, 'reference.json'), 'utf8'));
    assert.equal(sha256Canonical(submission.ir), sha256Canonical(reference));
  } finally { destroyTrial(t); }
});

test('decompiler fails cleanly on malformed artifacts and reports no submission', () => {
  assert.throws(() => decompileBytecodeV1({}), /Not a bytecode v1/);
  const bc = compileVeilIR({ schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression: { op: 'not', arg: { op: 'input' } } });
  assert.throws(() => decompileBytecodeV1({ ...bc, instructions: bc.instructions.slice(0, -1) }), /No ret/);
  assert.throws(() => decompileBytecodeV1({ ...bc, instructions: [[bc.opcodes.indexOf('ret'), 5]] }), /Undefined register/);
  assert.throws(() => decompileBytecodeV1({ ...bc, opcodes: bc.opcodes.map(o => (o === 'not' ? 'mystery' : o)) }), /Unknown operation/);
});
