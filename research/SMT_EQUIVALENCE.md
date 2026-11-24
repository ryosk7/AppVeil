# Bounded SMT equivalence checking (issue #19)

`src/veil-smt.mjs` encodes Veil IR v1 or v2 programs as SMT-LIB 2 over 32-bit bit-vectors (`QF_BV`). Loops are unrolled; they are bounded by IR v2's static step limit. Two programs with the same interface are **equivalent on all inputs** if and only if the solver answers `unsat` to "some output differs".

```sh
node bin/appveil.mjs check-equivalence a.json b.json [--timeout 60]   # 0 equivalent, 2 counterexample, 1 not-checked
node bin/appveil.mjs compile-ts module.ts --optimize --prove          # abort unless the optimization is proven
```

- **Encoding:** `add/sub/mul` map to `bvadd/bvsub/bvmul`. Shifts mask the count with `#x1f`, and `shr` is `bvashr`. Comparisons map to `=`, `bvult` and `bvule`. Bool and bit-vector forms of `and`/`or`/`xor`/`not` are chosen by type. `select` is `ite`.
- **Fail closed:** without a solver, or on a solver timeout or `unknown`, the result is **`not-checked`, never `equivalent`**. `--prove` turns anything short of a proof into a compile error. A counterexample always aborts, and it is returned as concrete inputs.
- **Solver:** `z3` on `PATH`, or `APPVEIL_Z3=/path/to/z3`. It runs locally; nothing is sent anywhere. CI installs z3 and sets `APPVEIL_REQUIRE_SMT=1`, so skipped proofs fail the build.

## Evidence (`test/veil-smt.test.mjs`; locally Z3 5.4.1 from the `z3-solver` wheel, in CI Ubuntu's `z3`)

| Check | Result |
| --- | --- |
| Optimizer output vs input, 60 random IR v2 programs | all **proven equivalent** |
| Injected miscompilations (a difference only at x = 0x9e3779b9) | a counterexample every time, and the reported input reproduces the difference under the interpreter |
| **Backend translation validation:** source IR vs the IR decompiled from (a) compiled bytecode and (b) the compiled Wasm module, 40 random programs | all **proven equivalent**. This shows the backends compile correctly for every 32-bit input, assuming the decompilers are faithful (they are independent code). |
| A hard instance, where the difference requires inverting a 4-round multiplicative hash | times out and is reported as `not-checked`, as intended |

## Limits

- Proofs cover the semantics of the IR, the optimizer and the backends' output. They say nothing about confidentiality.
- Multiplication-heavy programs can exceed the timeout. They are then reported as `not-checked`, and the differential validation (#17) still applies.
- Proving "decompile(compile(ir)) ≡ ir" relies on the decompilers in `src/red-lab-attacks.mjs` and `src/red-lab-wasm-attacks.mjs`. That makes it translation validation of the pair, not a verified compiler.
