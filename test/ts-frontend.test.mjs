import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { compileTypeScriptSubset, stripTypesForTesting, TsSubsetError } from '../src/ts-frontend.mjs';
import { evaluateVeilIRv2, compileVeilIRv2, loadVeilBytecodeV2, executeVeilBytecodeV2 } from '../src/veil-ir-v2.mjs';
import { refEvalV2, rngV2, randomV2, randomInputs } from './helpers/veil-v2-ref.mjs';
import { v2ToTs } from './helpers/v2-to-ts.mjs';

// Differential oracle: execute the type-stripped TS in this test process (never during compilation).
const dir = mkdtempSync(join(tmpdir(), 'appveil-ts-'));
let counter = 0;
async function asJs(source) {
  const file = join(dir, `m${counter++}.mjs`);
  writeFileSync(file, stripTypesForTesting(source));
  return (await import(pathToFileURL(file).href)).f ?? Object.values(await import(pathToFileURL(file).href))[0];
}
test.after(() => rmSync(dir, { recursive: true, force: true }));

function irOutputs(compiled, inputs) {
  const out = evaluateVeilIRv2(compiled.ir, inputs);
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [compiled.outputMap[k], v]));
}

test('example module: IR, VM and the TypeScript itself agree', async () => {
  const src = readFileSync(new URL('../examples/ts/score.ts', import.meta.url), 'utf8');
  const c = compileTypeScriptSubset(src);
  assert.equal(c.functionName, 'score');
  const js = await asJs(src);
  const h = loadVeilBytecodeV2(compileVeilIRv2(c.ir));
  const next = rngV2(0x75);
  for (let k = 0; k < 300; k++) {
    const x = k < 4 ? [0, 1, 0x80000000, 0xffffffff][k] : next(), strict = !!(k & 1);
    const expected = js(x, strict);
    assert.deepEqual(irOutputs(c, { x, strict }), expected);
    const vm = executeVeilBytecodeV2(h, [x, strict]);
    assert.deepEqual(Object.fromEntries(Object.entries(vm).map(([kk, v]) => [c.outputMap[kk], v])), expected);
  }
});

test('round trip: 200 random IR v2 programs -> TypeScript -> frontend -> IR agree with the reference and with JS execution', async () => {
  const next = rngV2(0x7577);
  for (let p = 0; p < 200; p++) {
    const doc = randomV2(next, { maxStmts: 5 });
    const ts = v2ToTs(doc);
    const c = compileTypeScriptSubset(ts);
    const js = await asJs(ts);
    for (let k = 0; k < 8; k++) {
      const inp = randomInputs(doc, next);
      const want = refEvalV2(doc, inp);
      assert.deepEqual(js(...doc.inputs.map(q => inp[q.name])), want, `JS p=${p}`);
      assert.deepEqual(irOutputs(c, inp), want, `IR p=${p}\n${ts}`);
    }
  }
});

test('rejects constructs outside the subset with source-located diagnostics', () => {
  const fn = body => `export function f(x: number, b: boolean): number {\n${body}\n}`;
  const cases = [
    ['  return x + 1;', /2:12: '\+' produces int32.*>>> 0/],
    ['  return x * 3;', /'\*' loses precision.*Math\.imul/],
    ['  return Math.imul(x, 3);', /must be wrapped/],
    ['  return ~x;', /\(~x\) >>> 0/],
    ['  return x / 2;', /no division/],
    ['  return Math.floor(x);', /Only Math.imul/],
    ['  return process.exit(1);', /Property access is not supported|Calls are not supported/],
    ['  return eval(x);', /'eval' is not supported/],
    ['  while (b) { }\n  return x;', /'while' is not supported/],
    ['  let y = 0;\n  for (let i = 0; i < x; i++) { y = (y + 1) >>> 0; }\n  return y;', /Loop bound must be an integer literal/],
    ['  let y = 0;\n  for (let i = 0; i < 2000; i++) { y = (y + 1) >>> 0; }\n  return y;', /Loop bound must be in \[1, 1024\]/],
    ['  const y = 1;\n  y = 2;\n  return y;', /Cannot assign to const/],
    ['  return z;', /Unknown identifier 'z'/],
    ['  return "s";', /String literals are not supported/],
    ['  return 1.5;', /Only integer literals/],
    ['  return -1;', /Unary '-' is not supported/],
    ['  return 4294967296;', /\[0, 2\^32\)/],
    ['  return b ? x : b;', /same type/],
    ['  return x == 1 ? 1 : 0;', /strict equality/],
    ['  x += 1;\n  return x;', /Compound assignment/],
    ['  const y = x;\n  const y = x;\n  return y;', /already declared/],
    ['  return b;', /must be number/]
  ];
  for (const [body, re] of cases) {
    assert.throws(() => compileTypeScriptSubset(fn(body)), err => err instanceof TsSubsetError && re.test(err.message), body);
  }
  assert.throws(() => compileTypeScriptSubset('function f(): number { return 1; }'), /Expected 'export'/);
  assert.throws(() => compileTypeScriptSubset(fn('  return x;') + '\nexport function g(): number { return 1; }'), /Only one exported function/);
  assert.throws(() => compileTypeScriptSubset('export function f(x: string): number { return 1; }'), /Only 'number'/);
  assert.throws(() => compileTypeScriptSubset('x'.repeat(300 * 1024)), /larger than/);
});

test('sequential loop assignments become a correct simultaneous update', async () => {
  const src = `export function f(n: number): number {
  let a = 0;
  let b = 1;
  for (let i = 0; i < 20; i++) {
    const_ = 0;
  }
  return a;
}`;
  assert.throws(() => compileTypeScriptSubset(src), /must be an outer 'let'/);
  const fib = `export function f(n: number): number {
  let a = 0;
  let b = 1;
  for (let i = 0; i < 20; i++) {
    b = (a + b) >>> 0;
    a = (b - a) >>> 0;
  }
  return a;
}`;
  const c = compileTypeScriptSubset(fib);
  assert.equal(evaluateVeilIRv2(c.ir, { n: 0 })[Object.keys(c.outputMap)[0]], (await asJs(fib))(0));
  assert.equal((await asJs(fib))(0), 6765);
});
