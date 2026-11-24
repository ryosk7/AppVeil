# Veil IR v2 — normative specification (research prototype, issue #15)

**Status: prototype. Not a security mechanism.** All Red Lab results for v1 (`research/RED_LAB_BASELINE.md`) apply: the opcode table ships with the artifact, and execution can be traced.

Schemas: [`schemas/veil-ir-v2.schema.json`](../schemas/veil-ir-v2.schema.json) and [`schemas/veil-bytecode-v2.schema.json`](../schemas/veil-bytecode-v2.schema.json). v1 documents (`schemaVersion: 1`) remain valid and unchanged, and `upgradeV1ToV2` lifts them to one input `x` and one output `y`.

## Program

```json
{ "schemaVersion": 2,
  "inputs":  [{ "name": "x", "type": "u32" }, { "name": "strict", "type": "bool" }],
  "outputs": [{ "name": "score", "type": "u32" }],
  "body": [ { "let": "name", "expr": <expr> } | { "loop": { "count": N, "vars": {...}, "update": {...} } } ] }
```

- **Types:** `u32` (0..2^32−1, arithmetic mod 2^32) and `bool`. There are no implicit conversions.
- **SSA:** every name (inputs, `let` names, loop variables) is assigned exactly once and must be defined before it is used. Names match `^[a-z_][a-z0-9_]{0,31}$`.
- **Expressions:**

| Node | Typing | Semantics |
| --- | --- | --- |
| `var` | type of the name | value |
| `const` `{type, value}` | `u32` or `bool` | literal |
| `add sub mul shl shr ushr` | u32 × u32 → u32 | as in v1 (`shr` is the arithmetic shift of the int32 view; shift counts are taken mod 32) |
| `and or xor` | T × T → T, for T in {u32, bool} | bitwise for u32, logical for bool |
| `not` | T → T | bitwise complement for u32, negation for bool |
| `eq ne` | T × T → bool | equality |
| `ltu leu` | u32 × u32 → bool | unsigned comparison |
| `select {cond, then, else}` | bool × T × T → T | `cond ? then : else`. Both branches are evaluated, so there are no side effects to skip. |

- **Bounded loops:** `count` is a constant integer in [1, 1024]. `vars` gives each loop variable's initial value, evaluated in the outer scope. `update` must assign exactly the same variables with the same types. Updates are **simultaneous**: every right-hand side reads the previous iteration's values. Loops cannot be nested, because loops are statements and an update is an expression. After the loop, its variables hold their final values in the enclosing scope.
- **Static bound:** the sum of expression sizes (each loop's per-iteration size times its count) must be at most 65,536. Every accepted program therefore terminates within a step count known statically. Other limits: 16 inputs, 16 outputs, 256 statements, 4,096 expression nodes, depth 32.

## Bytecode v2 and VM v2

`compileVeilIRv2` unrolls loops into straight-line SSA register code. Operations: `load-input k`, `load-const c`, `load-bool 0|1`, the v1 operations, `bnot`, `eq`, `ne`, `ltu`, `leu`, `select c a b`, and `ret r1..rm`, which returns one register per output. Bool values are 0 or 1 registers. `loadVeilBytecodeV2` verifies the program once:
- the envelope, and that the opcode table is a permutation
- dense arrays
- SSA and that operands refer only to earlier registers
- operand counts
- register kinds: a bool is never fed to a u32-only operation, and a `select` condition is a bool
- that the return kinds match the declared outputs

It returns an opaque handle. `executeVeilBytecodeV2` takes positional inputs and enforces `maxSteps`.

## Verification evidence

`test/veil-ir-v2.test.mjs`:
- On 400 random well-typed programs × 10 inputs (lets, loops, selects, comparisons, bool logic, several inputs and outputs), the interpreter, the compiler plus VM, and an independent BigInt reference (`test/helpers/veil-v2-ref.mjs`) all agree.
- 100 random v1 programs give the same results after the v1→v2 upgrade.
- 21 kinds of invalid program are rejected by the validator, among them unbounded loops, type errors, SSA violations and exceeding the step bound.
- 9 kinds of malformed bytecode are rejected by the VM, among them kind confusion and sparse tables.
- Every program the code accepts also conforms to both schemas.

## Not yet done

There is no Wasm backend for v2. Optimizations with translation validation are issue #17 and SMT equivalence is #19. The TypeScript frontend (#16) targets this IR.
