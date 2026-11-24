import { createHash } from 'node:crypto';

/** Research-only expression IR for deterministic uint32 functions. No JS eval or arbitrary TS parser. */
const BINARY = new Set(['add','sub','xor','and','or','mul','shl','shr','ushr']);
const UNARY = new Set(['not']);
const WORD = n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
function assertNode(node, depth = 0, budget = { count: 0 }) {
  if (++budget.count > 256 || depth > 32) throw new Error('IR complexity limit exceeded');
  if (!node || typeof node !== 'object' || Array.isArray(node)) throw new TypeError('Expression node must be an object');
  if (node.op === 'input') {
    if (Object.keys(node).length !== 1) throw new Error('Unexpected input node field');
    return;
  }
  if (node.op === 'const') {
    if (!WORD(node.value) || Object.keys(node).length !== 2) throw new TypeError('Constant must be uint32');
    return;
  }
  if (UNARY.has(node.op)) {
    if (Object.keys(node).length !== 2 || !('arg' in node)) throw new Error('Invalid unary node');
    assertNode(node.arg, depth + 1, budget);
    return;
  }
  if (BINARY.has(node.op)) {
    if (Object.keys(node).length !== 3 || !('left' in node) || !('right' in node)) throw new Error('Invalid binary node');
    assertNode(node.left, depth + 1, budget);
    assertNode(node.right, depth + 1, budget);
    return;
  }
  throw new Error(`Unsupported IR opcode: ${String(node.op)}`);
}
const IR_KEYS = new Set(['schemaVersion', 'inputType', 'outputType', 'expression']);
const BYTECODE_REQUIRED = ['format', 'version', 'instructions', 'opcodes', 'registers'];
const BYTECODE_KEYS = new Set([...BYTECODE_REQUIRED, 'seed', 'irDigest', 'disclaimer']);
/** Reject unknown top-level fields so new format features cannot be silently ignored (fail closed). */
function assertKnownKeys(doc, allowed, what) {
  for (const k of Object.keys(doc)) if (!allowed.has(k)) throw new Error(`Unknown ${what} field: ${k}`);
}
export function validateVeilIR(ir) {
  if (!ir || typeof ir !== 'object' || Array.isArray(ir)) throw new Error('Expected version 1 uint32 Veil IR');
  assertKnownKeys(ir, IR_KEYS, 'IR');
  if (ir.schemaVersion !== 1 || ir.inputType !== 'uint32' || ir.outputType !== 'uint32' || !('expression' in ir)) throw new Error('Expected version 1 uint32 Veil IR');
  assertNode(ir.expression);
  return ir;
}
function apply(op, a, b = 0) {
  switch (op) {
    case 'add': return (a + b) >>> 0;
    case 'sub': return (a - b) >>> 0;
    case 'xor': return (a ^ b) >>> 0;
    case 'and': return (a & b) >>> 0;
    case 'or': return (a | b) >>> 0;
    case 'mul': return Math.imul(a,b) >>> 0;
    case 'shl': return (a << (b & 31)) >>> 0;
    case 'shr': return (a >> (b & 31)) >>> 0;
    case 'ushr': return a >>> (b & 31);
    case 'not': return (~a) >>> 0;
    default: throw new Error(`Unknown op: ${op}`);
  }
}
export function evaluateVeilIR(ir, input) {
  validateVeilIR(ir);
  if (!WORD(input)) throw new TypeError('Input must be uint32');
  function walk(node) {
    if (node.op === 'input') return input;
    if (node.op === 'const') return node.value;
    if (node.op === 'not') return apply(node.op, walk(node.arg));
    const a = walk(node.left), b = walk(node.right);
    return apply(node.op, a, b);
  }
  return walk(ir.expression);
}
/**
 * Canonical JSON: object keys sorted recursively, no whitespace. Digests computed over this
 * form do not depend on key order in the source file. Rejects values JSON cannot represent.
 */
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Non-finite number is not canonical JSON');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`Unsupported value in canonical JSON: ${typeof value}`);
}
export function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}
/** murmur3 fmix32 finalizer: bijective uint32 mixing so small/zero seeds do not start xorshift in a weak state. */
function fmix32(h) {
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}
export const OPERATIONS = Object.freeze(['load-input','load-const','add','sub','xor','and','or','mul','shl','shr','ushr','not','ret']);
export function opcodePermutation(seed) { return permutation(seed); }
function permutation(seed) {
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) throw new TypeError('Seed must be uint32');
  const ordered = OPERATIONS.slice();
  // xorshift32 has a fixed point at 0; mix the seed first and never start from 0.
  // Diversification only: the table ships in the artifact and is NOT secret (research/RED_LAB_BASELINE.md).
  let x = fmix32((seed ^ 0x9e3779b9) >>> 0) || 0x6d2b79f5;
  for (let i = ordered.length - 1; i > 0; i--) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    const j = x % (i + 1);
    [ordered[i], ordered[j]] = [ordered[j], ordered[i]];
  }
  return ordered;
}
export function compileVeilIR(ir, { seed = 0 } = {}) {
  validateVeilIR(ir);
  const opcodes = permutation(seed);
  const instructions = [];
  let next = 0;
  function emit(op, args) {
    const dest = next++;
    instructions.push([opcodes.indexOf(op), dest, ...args]);
    return dest;
  }
  function lower(node) {
    if (node.op === 'input') return emit('load-input', []);
    if (node.op === 'const') return emit('load-const', [node.value]);
    if (node.op === 'not') return emit('not', [lower(node.arg)]);
    const a = lower(node.left), b = lower(node.right);
    return emit(node.op, [a, b]);
  }
  const out = lower(ir.expression);
  instructions.push([opcodes.indexOf('ret'), out]);
  return { format: 'appveil-experimental-bytecode', version: 1, instructions, opcodes, registers: next, seed, irDigest: sha256Canonical(ir), disclaimer: 'Opcode permutation is NOT cryptographic secrecy or confidentiality.' };
}
export function runVeilBytecode(program, input) {
  if (!WORD(input)) throw new TypeError('Input must be uint32');
  if (!program || typeof program !== 'object' || Array.isArray(program) || program.format !== 'appveil-experimental-bytecode' || program.version !== 1) throw new Error('Invalid bytecode envelope');
  assertKnownKeys(program, BYTECODE_KEYS, 'bytecode');
  if ('seed' in program && !WORD(program.seed)) throw new Error('Invalid bytecode seed');
  if ('irDigest' in program && (typeof program.irDigest !== 'string' || !/^[0-9a-f]{64}$/.test(program.irDigest))) throw new Error('Invalid bytecode irDigest');
  if ('disclaimer' in program && (typeof program.disclaimer !== 'string' || program.disclaimer.length > 200)) throw new Error('Invalid bytecode disclaimer');
  if (!Array.isArray(program.opcodes) || program.opcodes.length !== OPERATIONS.length || new Set(program.opcodes).size !== OPERATIONS.length || program.opcodes.some(op => !OPERATIONS.includes(op))) throw new Error('Invalid opcode table');
  if (!Number.isInteger(program.registers) || program.registers < 1 || program.registers > 256 || !Array.isArray(program.instructions) || program.instructions.length !== program.registers + 1) throw new Error('Invalid register or instruction count');
  const regs = [];
  for (let i = 0; i < program.instructions.length; i++) {
    const inst = program.instructions[i];
    if (!Array.isArray(inst) || !Number.isInteger(inst[0]) || inst[0] < 0 || inst[0] >= program.opcodes.length) throw new Error('Invalid instruction');
    const [opcode, dst, ...args] = inst;
    const op = program.opcodes[opcode];
    if (op === 'ret') {
      if (i !== program.instructions.length - 1 || args.length || !Number.isInteger(dst) || dst < 0 || dst >= regs.length) throw new Error('Invalid return instruction');
      return regs[dst];
    }
    if (i === program.instructions.length - 1 || dst !== i) throw new Error('Noncanonical or missing return');
    let val;
    if (op === 'load-input') { if (args.length) throw new Error('Invalid input instruction'); val = input; }
    else if (op === 'load-const') { if (args.length !== 1 || !WORD(args[0])) throw new Error('Invalid constant'); val = args[0]; }
    else {
      const unary = op === 'not';
      if (args.length !== (unary ? 1 : 2) || args.some(r => !Number.isInteger(r) || r < 0 || r >= i)) throw new Error('Invalid register operand');
      val = apply(op, regs[args[0]], unary ? 0 : regs[args[1]]);
    }
    regs.push(val);
  }
  throw new Error('Missing return instruction');
}
