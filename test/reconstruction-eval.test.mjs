import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePredictions, oracle } from '../src/reconstruction-eval.mjs';

test('matches correct synthetic oracle predictions', () => {
 const inputs = [0, 1, 17, 4294967295];
 const result = evaluatePredictions(inputs.map(oracle), inputs);
 assert.equal(result.accuracy, 1);
 assert.equal(result.matches, 4);
});
test('scores mismatched output without executing attacker code', () => {
 const result = evaluatePredictions([0,0], [0,1]);
 assert.equal(result.matches, 0);
});
test('rejects malformed prediction arrays', () => {
 assert.throws(() => evaluatePredictions([1], [1,2]));
});
