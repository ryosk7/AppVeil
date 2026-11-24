import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evaluateVeilIR, compileVeilIR, runVeilBytecode } from '../src/veil-ir.mjs';
import { oracle } from '../src/reconstruction-eval.mjs';
const ir = JSON.parse(readFileSync(new URL('../examples/veil-ir-score.json', import.meta.url), 'utf8'));
function random(seed) { let x=seed; return () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>> 0; }; }
test('IR oracle and VM agree on edge inputs and 5000 seeded cases', () => {
  const inputs=[0,1,7,17,255,0x7fffffff,0x80000000,0xffffffff];
  const next=random(123456789);
  for(let i=0;i<5000;i++) inputs.push(next());
  for(const seed of [0,1,42,0xffffffff]) {
    const p=compileVeilIR(ir,{seed});
    for(const x of inputs) {
      assert.equal(evaluateVeilIR(ir,x),oracle(x));
      assert.equal(runVeilBytecode(p,x),oracle(x));
    }
  }
});
test('different seeds change encoding while retaining behavior', () => {
  const a=compileVeilIR(ir,{seed:1}), b=compileVeilIR(ir,{seed:999});
  assert.notDeepEqual(a.instructions,b.instructions);
  assert.equal(runVeilBytecode(a,0xdeadbeef),runVeilBytecode(b,0xdeadbeef));
});
test('invalid programs and IR fail closed', () => {
  assert.throws(()=>compileVeilIR({...ir,expression:{op:'eval',code:'process.exit()'}}),/Unsupported IR opcode/);
  assert.throws(()=>compileVeilIR({...ir,expression:{op:'const',value:-1}}),/Constant must be uint32/);
  assert.throws(()=>compileVeilIR(ir,{seed:-1}),/Seed must be uint32/);
  assert.throws(()=>runVeilBytecode({...compileVeilIR(ir),opcodes:[]},1),/Invalid opcode table/);
  assert.throws(()=>runVeilBytecode(compileVeilIR(ir),-1),/Input must be uint32/);
  // Instruction count no longer matches `registers + 1`; per-instruction checks are in veil-ir-semantics.test.mjs.
  assert.throws(()=>runVeilBytecode({...compileVeilIR(ir),instructions:[[0,999]]},1),/Invalid register or instruction count/);
});
