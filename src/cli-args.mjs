import { parseArgs } from 'node:util';

/**
 * AppVeil CLI exit-status contract (documented in README and --help):
 *   0  success, and no documented policy violation
 *   1  usage error, malformed input, or execution error (including missing tools)
 *   2  documented policy violation (for example --strict high findings, or an image policy FAIL)
 */
export const EXIT = Object.freeze({ OK: 0, ERROR: 1, POLICY: 2 });

export class UsageError extends Error {}

const json = { type: 'boolean' }, strict = { type: 'boolean' };
/** Per-command positional arity and accepted options. Anything else is a usage error. */
export const COMMANDS = Object.freeze({
  'inspect': { positionals: ['directory'], options: { json, strict } },
  'inspect-image': { positionals: ['image'], options: { json, strict, layers: { type: 'boolean' } } },
  'inspect-image-archive': { positionals: ['image.tar'], options: { json, strict } },
  'audit-dockerfile': { positionals: ['Dockerfile'], options: { json, strict } },
  'benchmark': { positionals: ['artifact1', 'artifact2'], variadic: true, options: { marker: { type: 'string', multiple: true }, 'not-checked': { type: 'string', multiple: true } } },
  'evaluate-reconstruction': { positionals: ['predictions.json', 'inputs.json'], options: {} },
  'verify-image-report': { positionals: ['image-audit.json'], options: {} },
  'local-ai-trial': { positionals: ['synthetic-artifact', 'installed-ollama-model'], options: {} },
  'check-olares-image': { positionals: ['values.yaml'], options: { previous: { type: 'string' }, 'require-digest': { type: 'boolean' } } },
  'compile-ir': { positionals: ['ir.json'], options: { seed: { type: 'string' } } },
  'run-ir': { positionals: ['ir.json', 'uint32-input'], options: {} },
  'run-bytecode': { positionals: ['bytecode.json', 'uint32-input'], options: {} },
  'red-lab-decode': { positionals: ['bytecode.json'], options: {} },
  'red-lab-run': { positionals: ['attack'], options: { trials: { type: 'string' }, size: { type: 'string' }, seed: { type: 'string' }, holdout: { type: 'string' }, queries: { type: 'string' }, full: { type: 'boolean' } } }
});

/** Parse argv strictly. Returns { command, positionals, values } or throws UsageError. */
export function parseCommandLine(argv) {
  const [command, ...rest] = argv;
  const spec = Object.hasOwn(COMMANDS, command ?? '') ? COMMANDS[command] : null;
  if (!spec) throw new UsageError(command ? `Unknown command: ${command}` : 'Missing command');
  let parsed;
  try {
    parsed = parseArgs({ args: rest, options: spec.options, strict: true, allowPositionals: true });
  } catch (error) {
    throw new UsageError(`${command}: ${error.message}`);
  }
  const { positionals, values } = parsed;
  const min = spec.positionals.length;
  if (positionals.length < min || (!spec.variadic && positionals.length > min)) {
    throw new UsageError(`${command}: expected ${spec.variadic ? `at least ${min}` : min} argument(s) <${spec.positionals.join('> <')}>, got ${positionals.length}`);
  }
  for (const [name, value] of Object.entries(values)) {
    for (const v of [value].flat()) if (v === '') throw new UsageError(`${command}: --${name} must not be empty`);
  }
  return { command, positionals, values };
}

/** Strict decimal uint32 parser: rejects empty, hex, signs, exponents, fractions, leading zeros and out-of-range values. */
export function parseUint32Decimal(text, name) {
  if (typeof text !== 'string' || !/^(0|[1-9]\d{0,9})$/.test(text) || Number(text) > 0xffffffff) {
    throw new UsageError(`Specify ${name} as a uint32 decimal integer`);
  }
  return Number(text);
}

export function usageText() {
  const lines = Object.entries(COMMANDS).map(([name, spec]) => {
    const pos = spec.positionals.map(p => `<${p}>`).join(' ') + (spec.variadic ? ' [...]' : '');
    const opts = Object.entries(spec.options).map(([o, d]) => d.type === 'boolean' ? `[--${o}]` : `[--${o} <value>]${d.multiple ? '...' : ''}`).join(' ');
    return `  appveil ${name} ${pos}${opts ? ' ' + opts : ''}`;
  });
  return [
    'AppVeil 0.1.0 (experimental)', '', 'Usage:', ...lines, '',
    'Exit status: 0 = success / no policy violation, 1 = usage, input or execution error, 2 = documented policy violation.',
    'Unknown options, missing option values and wrong argument counts are usage errors (exit 1).', '',
    'inspect-image requires Docker and a locally available image; it uses docker create + docker cp, never starts the container.',
    'Findings are indicators, not proof that an image is secure.'
  ].join('\n');
}
