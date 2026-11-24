# IR v2 optimizer with translation validation (issue #17)

`src/veil-opt.mjs`, also available as `--optimize` on `compile-ts` and on `compile-ir` for v2 documents.

## Passes (run to a fixpoint, at most 8 rounds)

1. **Constant folding** of every operator over constant operands.
2. **Algebraic identities** that are exact under uint32 and bool semantics:
   - `x+0`, `x|0`, `x^0`, `x−0`, `x*1`, `x&0xffffffff` → `x`
   - `x*0`, `x&0`, `x−x`, `x^x` → `0`
   - shifts by a multiple of 32 → `x`, since shift counts are taken mod 32
   - `not(not x)` → `x`
   - `select` with a constant condition or identical branches → that branch
   - bool `and`/`or` with constants
   - `x==x`, `x<=x` → `true`; `x!=x`, `x<x` → `false`
3. **Copy and constant propagation:** lets that reduce to a variable or a constant are substituted. Inside a loop's update expressions, the loop's own variables are never substituted, because they denote per-iteration values.
4. **CSE:** a subexpression identical to an earlier top-level `let` is replaced by that name. SSA names are unique, so this is sound.
5. **DCE:** lets and loops that cannot reach an output are removed.

## Translation validation (fail closed)

After optimization, `translationValidate` checks that the interface is unchanged, then compares original and optimized results on 2,000 inputs: boundary values (0, 1, 2, 31, 32, 2^31−1, 2^31, 2^32−2, 2^32−1) combined across inputs, plus seeded random values. **Any mismatch aborts compilation**, and the optimized program is never emitted. This is differential evidence, not a proof. Bounded SMT equivalence is issue #19.

The validator caught a real bug while this pass was being written. The shift rule "count ≡ 0 mod 32 ⇒ identity" had also been applied to `sub`, turning `x − 32` into `x`. Validation stopped compilation on the very first regression test, and the case is now a named regression test. The tests also inject deliberately wrong passes (operand swap, an error only at the boundary value 2^31, an interface change) and confirm that each is rejected.

## Measured effect

- 1,000 random IR v2 programs (generator `test/helpers/veil-v2-ref.mjs`, seed 0x5747): 925 shrank. Total size fell from 109,612 to 66,520 nodes, a **39.3%** reduction, with a median after/before ratio of 0.658. Size counts each loop's per-iteration nodes times its trip count. No program grew; the tests assert this.
- `examples/ts/score.ts`: 110 → 109 nodes. Hand-written code has little to fold.

## Not guaranteed

Optimization is not obfuscation, and it neither adds nor removes confidentiality. A program that passes validation is correct on the sampled inputs, and on all inputs only once SMT checking (#19) succeeds.
