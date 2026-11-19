import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

/**
 * Static attack baseline. Decodes shipped opcode tables without running the artifact.
 * If this succeeds, VM opcode permutation is trivially reversible.
 */
export function recoverInstructionTrace(program) {
  if (!program || program.format !== 'appveil-experimental-bytecode' ||
      program.version !== 1 || !Array.isArray(program.opcodes) ||
      !Array.isArray(program.instructions)) throw new Error('Unsupported VM program');
  const trace = program.instructions.map((inst, index) => {
    if (!Array.isArray(inst) || !Number.isInteger(inst[0]) ||
        inst[0] < 0 || inst[0] >= program.opcodes.length) throw new Error('Invalid instruction');
    return { index, operation: program.opcodes[inst[0]], operands: inst.slice(1) };
  });
  return {
    schemaVersion: 1,
    attack: 'visible-opcode-map-static-decoding',
    recovered: trace,
    decodedInstructions: trace.length,
    securityFinding: 'Shipped opcode table reveals all instruction mnemonics. Permutation alone provides no meaningful confidentiality.',
    artifactSha256: createHash('sha256').update(JSON.stringify(program)).digest('hex')
  };
}
export function recoverInstructionTraceFile(filename) {
  return recoverInstructionTrace(JSON.parse(readFileSync(filename, 'utf8')));
}
