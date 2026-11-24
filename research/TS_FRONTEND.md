# Restricted TypeScript frontend (research prototype, issue #16)

`appveil compile-ts <module.ts> [--bytecode] [--seed <uint32>]` compiles **one exported function**, written in a strict subset of TypeScript, into Veil IR v2 (`research/VEIL_IR_V2.md`), or into bytecode v2 with `--bytecode`. The source is **parsed, never executed**, and the frontend has no dependencies (an in-repo tokenizer and recursive-descent parser). The TypeScript compiler API was not used: it would be the repository's first runtime dependency, and the subset is small enough to parse directly.

## Subset (chosen so plain JS semantics equal IR semantics)

| Allowed | IR |
| --- | --- |
| Parameters `name: number` (uint32) or `name: boolean` | inputs |
| Return type `number`, `boolean`, or `{ a: number; b: boolean }` with `return { a: ..., b: ... }` | outputs |
| `const x = e;` and `let x = e;` (no shadowing; `let` may be reassigned) | SSA `let`, renamed per assignment |
| `(a + b) >>> 0`, `(a - b) >>> 0`, `(a << b) >>> 0`, `(a >> b) >>> 0`, `(a & b) >>> 0`, `(a \| b) >>> 0`, `(a ^ b) >>> 0`, `(~a) >>> 0`, `Math.imul(a, b) >>> 0`, `a >>> b` | `add sub shl shr and or xor not mul ushr` |
| `===` `!==` `<` `<=` `>` `>=` on numbers; `===` `!==` `&&` `\|\|` `!` on booleans | `eq ne ltu leu` (with `>`/`>=` swapped), `and or not` |
| `c ? a : b`, and `if (c) { x = ...; } else { ... }` containing only assignments | `select` (assignments merged per variable) |
| `for (let i = 0; i < N; i++) { assignments / if }` with a literal `N` ≤ 1024 | bounded `loop`; JS's sequential assignments become a simultaneous update by substitution |
| Integer literals 0..2^32−1 (decimal, hex, binary, octal, `_` separators), `true`, `false` | constants |

**Why the `>>> 0` rule:** in JavaScript, `a + b`, `a * b` and `a & b` either do not wrap at 2^32 or produce signed int32. Requiring the explicit uint32 wrapper makes the TypeScript, run as-is, compute exactly what the IR computes. The test suite checks this by running the type-stripped source. Unwrapped forms are rejected with a diagnostic that shows the fix.

**Rejected, each with a `line:col` diagnostic:** other types, strings, floats, unary `-`/`+`, `/ % **`, `==`/`!=`, compound assignment, calls other than `Math.imul`, property access, globals and ambient APIs (`process`, `eval`, ...), `while`/`do`/`switch`/`class`/`new`/`function`/closures, non-literal or oversized loop bounds, assigning to `const` or to parameters, declarations inside loops or `if`, more than one exported function, and sources over 256 KiB.

## Verification evidence (`test/ts-frontend.test.mjs`)

- `examples/ts/score.ts`: the IR interpreter, the VM v2 and the **TypeScript itself** (type-stripped and executed in the test harness) agree on 300 inputs.
- **Round trip:** 200 random IR v2 programs are printed as subset TypeScript (`test/helpers/v2-to-ts.mjs`) and compiled back. On 8 inputs each, the new IR agrees with the independent reference, and the JavaScript run of that TypeScript also agrees.
- There is a test for every rejected construct class above, and a Fibonacci loop that checks the sequential-to-simultaneous conversion.

## Not guaranteed

Compiling TypeScript to IR does not protect it: every Red Lab attack recovers the IR (`research/RED_LAB_BASELINE.md`). The subset is intentionally small. Supporting more TypeScript requires preserving semantics exactly, with this same kind of differential evidence.
