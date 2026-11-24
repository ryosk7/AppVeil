import { readFileSync } from 'node:fs';
import path from 'node:path';

/**
 * Red Lab baseline attackers (research). Each attacker gets only what its attack class allows and
 * returns a DATA submission for the judge: { kind: 'ir', ir } or { kind: 'none', reason }.
 * They are written from the attacker's point of view: no defender compiler, loader or source is used.
 * Success means the defense FAILED against a trivial attacker; that is the expected result for v1.
 */

const BINARY = new Set(['add', 'sub', 'xor', 'and', 'or', 'mul', 'shl', 'shr', 'ushr']);

/**
 * Static attack (issue #12): decompile bytecode v1 to an expression tree. The artifact ships its own
 * opcode table, so every instruction's meaning is read directly; SSA registers are inlined back into a
 * tree. Works for every seed because the permutation is not secret.
 */
export function decompileBytecodeV1(artifact, { maxNodes = 4096 } = {}) {
  if (artifact?.format !== 'appveil-experimental-bytecode' || artifact.version !== 1) throw new Error('Not a bytecode v1 artifact');
  const { opcodes, instructions } = artifact;
  if (!Array.isArray(opcodes) || !Array.isArray(instructions)) throw new Error('Malformed artifact');
  const regs = [];
  let nodes = 0;
  const count = n => { if (++nodes > maxNodes) throw new Error('Decompiled tree too large'); return n; };
  const reg = r => { if (!Number.isInteger(r) || !(r in regs)) throw new Error(`Undefined register ${r}`); return structuredClone(regs[r]); };
  for (const inst of instructions) {
    if (!Array.isArray(inst)) throw new Error('Malformed instruction');
    const [code, dst, ...args] = inst;
    const op = opcodes[code];
    if (op === 'ret') return { schemaVersion: 1, inputType: 'uint32', outputType: 'uint32', expression: reg(dst) };
    let node;
    if (op === 'load-input') node = { op: 'input' };
    else if (op === 'load-const') node = { op: 'const', value: args[0] };
    else if (op === 'not') node = { op: 'not', arg: reg(args[0]) };
    else if (BINARY.has(op)) node = { op, left: reg(args[0]), right: reg(args[1]) };
    else throw new Error(`Unknown operation ${String(op)}`);
    regs[dst] = count(node);
  }
  throw new Error('No ret instruction');
}

/** Static attacker over a trial workspace: reads only attackerDir/artifact.json. */
export function staticDecompileAttack(attackerDir) {
  const t0 = process.hrtime.bigint();
  try {
    const artifact = JSON.parse(readFileSync(path.join(attackerDir, 'artifact.json'), 'utf8'));
    const ir = decompileBytecodeV1(artifact);
    return { submission: { kind: 'ir', ir }, used: { timeMs: Number(process.hrtime.bigint() - t0) / 1e6 } };
  } catch (e) {
    return { submission: { kind: 'none', reason: e.message }, used: { timeMs: Number(process.hrtime.bigint() - t0) / 1e6 } };
  }
}
