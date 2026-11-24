// Child-process timer for one backend, so JIT feedback from other backends cannot bias the result.
// argv: <kind: js|veil-vm|wasm> <artifact path> <inputs.bin path>
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { loadVeilBytecode, executeVeilBytecode } from './veil-ir.mjs';
const [kind, artifact, inputsFile] = process.argv.slice(2);
const xs = new Uint32Array(readFileSync(inputsFile).buffer.slice(0));
let fn;
if (kind === 'js') fn = (await import(pathToFileURL(artifact).href)).f;
else if (kind === 'veil-vm') { const h = loadVeilBytecode(JSON.parse(readFileSync(artifact, 'utf8'))); fn = x => executeVeilBytecode(h, x); }
else if (kind === 'wasm') { const { f } = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(artifact)), {}).exports; fn = x => f(x | 0) >>> 0; }
else throw new Error(`unknown kind ${kind}`);
let sink = 0;
for (let w = 0; w < 3; w++) for (let i = 0; i < xs.length; i++) sink ^= fn(xs[i]);
const samples = [];
for (let r = 0; r < 7; r++) { const t = process.hrtime.bigint(); for (let i = 0; i < xs.length; i++) sink ^= fn(xs[i]); samples.push(Number(process.hrtime.bigint() - t) / xs.length); }
samples.sort((a, b) => a - b);
console.log(JSON.stringify({ nsPerCall: samples[3], sink: sink >>> 0 }));
