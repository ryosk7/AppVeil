import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateSchema } from '../src/json-schema-lite.mjs';
import { validateVeilIR, compileVeilIR, runVeilBytecode, OPERATIONS } from '../src/veil-ir.mjs';

const load = name => JSON.parse(readFileSync(new URL(`../schemas/${name}`, import.meta.url), 'utf8'));
const IR_SCHEMA = load('veil-ir-v1.schema.json');
const BC_SCHEMA = load('veil-bytecode-v1.schema.json');
const example = JSON.parse(readFileSync(new URL('../examples/veil-ir-score.json', import.meta.url), 'utf8'));
const codeAcceptsIR = doc => { try { validateVeilIR(doc); return true; } catch { return false; } };
const codeAcceptsBC = doc => { try { runVeilBytecode(doc, 1); return true; } catch { return false; } };
const clone = v => JSON.parse(JSON.stringify(v));

function xorshift(seed) { let x = seed >>> 0 || 1; return () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>>= 0; }; }
const BIN = ['add', 'sub', 'xor', 'and', 'or', 'mul', 'shl', 'shr', 'ushr'];
function randomIR(next, depth = 0) {
  const r = next() % 10;
  if (depth > 5 || r < 2) return { op: 'input' };
  if (r < 4) return { op: 'const', value: next() };
  if (r < 5) return { op: 'not', arg: randomIR(next, depth + 1) };
  return { op: BIN[next() % BIN.length], left: randomIR(next, depth + 1), right: randomIR(next, depth + 1) };
}
const wrap = expression => ({ schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression });

test('schemas use only the supported keyword subset; unsupported keywords fail closed', () => {
  assert.equal(validateSchema(IR_SCHEMA, example).valid, true);
  assert.throws(() => validateSchema({ type: 'object', patternProperties: {} }, {}), /Unsupported schema keyword/);
  assert.throws(() => validateSchema({ $ref: 'http://example.com/x' }, {}), /Unsupported or unknown \$ref/);
});

test('every IR and bytecode the code accepts also conforms to the schema (300 generated programs)', () => {
  const next = xorshift(0xa11ce);
  for (let i = 0; i < 300; i++) {
    const ir = wrap(randomIR(next));
    assert.equal(codeAcceptsIR(ir), true);
    const irResult = validateSchema(IR_SCHEMA, ir);
    assert.equal(irResult.valid, true, irResult.errors.join('\n'));
    const bc = compileVeilIR(ir, { seed: next() });
    assert.equal(codeAcceptsBC(bc), true);
    const bcResult = validateSchema(BC_SCHEMA, bc);
    assert.equal(bcResult.valid, true, bcResult.errors.join('\n'));
    // Optional fields are optional in both.
    const { seed, irDigest, disclaimer, ...minimal } = bc;
    assert.equal(codeAcceptsBC(minimal), true);
    assert.equal(validateSchema(BC_SCHEMA, minimal).valid, true);
  }
});

test('structural IR violations are rejected by both schema and code', () => {
  const cases = {
    'unknown top-level field': d => { d.extra = 1; },
    'missing expression': d => { delete d.expression; },
    'wrong schemaVersion': d => { d.schemaVersion = 2; },
    'wrong inputType': d => { d.inputType = 'int32'; },
    'array root': () => [],
    'unknown op': d => { d.expression = { op: 'eval', code: 'x' }; },
    'negative const': d => { d.expression = { op: 'const', value: -1 }; },
    'const above uint32': d => { d.expression = { op: 'const', value: 2 ** 32 }; },
    'fractional const': d => { d.expression = { op: 'const', value: 1.5 }; },
    'string const': d => { d.expression = { op: 'const', value: '1' }; },
    'extra field on input': d => { d.expression = { op: 'input', x: 1 }; },
    'unary missing arg': d => { d.expression = { op: 'not' }; },
    'unary with left/right': d => { d.expression = { op: 'not', left: { op: 'input' }, right: { op: 'input' } }; },
    'binary missing right': d => { d.expression = { op: 'add', left: { op: 'input' } }; },
    'nested invalid node': d => { d.expression.left.left = { op: 'input', y: 2 }; }
  };
  for (const [name, mutate] of Object.entries(cases)) {
    let d = clone(example);
    d = mutate(d) ?? d;
    assert.equal(validateSchema(IR_SCHEMA, d).valid, false, `schema accepted: ${name}`);
    assert.equal(codeAcceptsIR(d), false, `code accepted: ${name}`);
  }
});

test('structural bytecode violations are rejected by both schema and code', () => {
  const base = compileVeilIR(example, { seed: 9 });
  const cases = {
    'unknown top-level field': d => { d.extra = 1; },
    'wrong format': d => { d.format = 'x'; },
    'wrong version': d => { d.version = 2; },
    'missing opcodes': d => { delete d.opcodes; },
    'short opcode table': d => { d.opcodes = d.opcodes.slice(1); },
    'duplicate opcode': d => { d.opcodes[0] = d.opcodes[1]; },
    'unknown opcode name': d => { d.opcodes[0] = 'eval'; },
    'registers zero': d => { d.registers = 0; },
    'registers too large': d => { d.registers = 257; },
    'registers fractional': d => { d.registers = 1.5; },
    'instruction not array': d => { d.instructions[0] = {}; },
    'opcode index out of range': d => { d.instructions[0][0] = 13; },
    'opcode index negative': d => { d.instructions[0][0] = -1; },
    'instruction too long': d => { d.instructions[d.instructions.length - 2].push(0, 0, 0); },
    'instruction too short': d => { d.instructions[0] = [d.instructions[0][0]]; },
    'non-integer operand': d => { d.instructions[d.instructions.length - 2][2] = 'x'; },
    'bad seed': d => { d.seed = -1; },
    'bad irDigest': d => { d.irDigest = 'XYZ'; },
    'oversized disclaimer': d => { d.disclaimer = 'x'.repeat(201); }
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const d = clone(base);
    mutate(d);
    assert.equal(validateSchema(BC_SCHEMA, d).valid, false, `schema accepted: ${name}`);
    assert.equal(codeAcceptsBC(d), false, `code accepted: ${name}`);
  }
});

test('semantic-only constraints: schema-valid but code-rejected, each documented in the schema', () => {
  // These cannot be expressed in JSON Schema. Each must be listed in x-appveil-semantic-constraints.
  const base = compileVeilIR(wrap({ op: 'add', left: { op: 'input' }, right: { op: 'const', value: 1 } }), { seed: 3 });
  const o = name => base.opcodes.indexOf(name);
  const bcCases = {
    'instructions.length === registers + 1': d => { d.registers = 2; },
    'Instruction i (except the last) writes register i (SSA)': d => { d.instructions[1][1] = 0; },
    'Operand registers reference only earlier registers': d => { d.instructions[2] = [o('add'), 2, 0, 2]; },
    'Exactly one ret, and it is the last instruction; its register is defined': d => { d.instructions[3] = [o('ret'), 3]; },
    'Operand count matches the decoded operation: load-input 0, load-const 1 (uint32), not 1, binary ops 2': d => { d.instructions[2] = [o('add'), 2, 0]; }
  };
  assert.deepEqual(Object.keys(bcCases), BC_SCHEMA['x-appveil-semantic-constraints']);
  for (const [name, mutate] of Object.entries(bcCases)) {
    const d = clone(base);
    mutate(d);
    assert.equal(validateSchema(BC_SCHEMA, d).valid, true, `schema should accept (semantic only): ${name}`);
    assert.equal(codeAcceptsBC(d), false, `code accepted: ${name}`);
  }
  let deep = { op: 'input' };
  for (let i = 0; i < 40; i++) deep = { op: 'not', arg: deep };
  const balanced = n => (n === 0 ? { op: 'input' } : { op: 'add', left: balanced(n - 1), right: balanced(n - 1) });
  const irCases = { 'At most 256 expression nodes in total': wrap(balanced(8)), 'Nesting depth at most 32': wrap(deep) };
  assert.deepEqual(Object.keys(irCases), IR_SCHEMA['x-appveil-semantic-constraints']);
  for (const [name, d] of Object.entries(irCases)) {
    assert.equal(validateSchema(IR_SCHEMA, d).valid, true, `schema should accept (semantic only): ${name}`);
    assert.equal(codeAcceptsIR(d), false, `code accepted: ${name}`);
  }
  assert.equal(OPERATIONS.length, BC_SCHEMA.properties.opcodes.minItems);
  assert.deepEqual([...BC_SCHEMA.properties.opcodes.items.enum].sort(), [...OPERATIONS].sort());
});

test('schema checker bounds: self-referential $ref loops and excessive value depth fail closed', () => {
  assert.throws(() => validateSchema({ $defs: { a: { $ref: '#/$defs/a' } }, $ref: '#/$defs/a' }, 1), /indirection limit/);
  let v = 0; for (let i = 0; i < 300; i++) v = [v];
  assert.equal(validateSchema({ $defs: { n: { oneOf: [{ type: 'integer' }, { type: 'array', items: { $ref: '#/$defs/n' } }] } }, $ref: '#/$defs/n' }, v).valid, false);
});
