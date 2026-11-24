import test from 'node:test';
import assert from 'node:assert/strict';
import { compileVeilIR, evaluateVeilIR, loadVeilBytecode, executeVeilBytecode, runVeilBytecode, DEFAULT_MAX_STEPS } from '../src/veil-ir.mjs';

function xorshift(seed) { let x = seed >>> 0 || 1; return () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>>= 0; }; }
const BIN = ['add', 'sub', 'xor', 'and', 'or', 'mul', 'shl', 'shr', 'ushr'];
function randomIR(next, depth = 0) {
  const r = next() % 10;
  if (depth > 6 || r < 2) return { op: 'input' };
  if (r < 4) return { op: 'const', value: next() };
  if (r < 5) return { op: 'not', arg: randomIR(next, depth + 1) };
  return { op: BIN[next() % BIN.length], left: randomIR(next, depth + 1), right: randomIR(next, depth + 1) };
}
const wrap = expression => ({ schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression });

test('load-once execution equals the IR evaluator on 200 generated programs x 50 inputs', () => {
  const next = xorshift(0xb0b0);
  for (let p = 0; p < 200; p++) {
    const ir = wrap(randomIR(next));
    const bc = compileVeilIR(ir, { seed: next() });
    const h = loadVeilBytecode(bc);
    for (let i = 0; i < 50; i++) {
      const x = i < 4 ? [0, 1, 0x80000000, 0xffffffff][i] : next();
      const expected = evaluateVeilIR(ir, x);
      assert.equal(executeVeilBytecode(h, x), expected);
      assert.equal(runVeilBytecode(bc, x), expected);
    }
  }
});

test('verified handles cannot be forged and are unaffected by later mutation of the source', () => {
  const bc = compileVeilIR(wrap({ op: 'add', left: { op: 'input' }, right: { op: 'const', value: 1 } }), { seed: 4 });
  const h = loadVeilBytecode(bc);
  assert.ok(Object.isFrozen(h));
  assert.throws(() => executeVeilBytecode({ ...h }, 1), /Not a verified program/);
  assert.throws(() => executeVeilBytecode(bc, 1), /Not a verified program/);
  assert.throws(() => executeVeilBytecode(null, 1), /Not a verified program/);
  // Mutating the source after verification must not change the verified program.
  bc.instructions[1][2] = 1000;
  bc.opcodes.reverse();
  assert.equal(executeVeilBytecode(h, 41), 42);
  assert.throws(() => runVeilBytecode(bc, 41));
});

test('step limit fails closed and options are validated', () => {
  const bc = compileVeilIR(wrap({ op: 'add', left: { op: 'input' }, right: { op: 'const', value: 1 } }));
  const h = loadVeilBytecode(bc); // 3 executed instructions + ret = 4 steps
  assert.equal(executeVeilBytecode(h, 1, { maxSteps: 4 }), 2);
  assert.throws(() => executeVeilBytecode(h, 1, { maxSteps: 3 }), /step limit exceeded/);
  assert.throws(() => executeVeilBytecode(h, 1, { maxSteps: 1 }), /step limit exceeded/);
  assert.throws(() => runVeilBytecode(bc, 1, { maxSteps: 3 }), /step limit exceeded/);
  for (const bad of [0, -1, 1.5, NaN, Infinity, '10']) assert.throws(() => executeVeilBytecode(h, 1, { maxSteps: bad }), /maxSteps/);
  assert.equal(DEFAULT_MAX_STEPS, 1_000_000);
  for (const bad of [-1, 2 ** 32, 1.5]) assert.throws(() => executeVeilBytecode(h, bad), /Input must be uint32/);
});

test('regression (found by fuzzing, seed 22): sparse arrays are rejected, never coerced to load-input or register 0', () => {
  const bc = compileVeilIR(wrap({ op: 'mul', left: { op: 'input' }, right: { op: 'const', value: 3 } }), { seed: 5 });
  const holeyTable = structuredClone(bc);
  delete holeyTable.opcodes[holeyTable.opcodes.indexOf('mul')];
  assert.equal(holeyTable.opcodes.length, 13);
  assert.throws(() => loadVeilBytecode(holeyTable), /Invalid opcode table/);
  const holeyOperand = structuredClone(bc);
  delete holeyOperand.instructions[2][2]; // [mul, 2, <hole>, 1]
  assert.throws(() => loadVeilBytecode(holeyOperand), /Invalid instruction/);
  const holeyInstructions = structuredClone(bc);
  delete holeyInstructions.instructions[1];
  assert.throws(() => loadVeilBytecode(holeyInstructions), /Invalid register or instruction count/);
});
