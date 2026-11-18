import { readFileSync } from 'node:fs';

// Evaluates output predictions, NEVER executes submitted AI-generated programs.
// Synthetic open-source reference function for experimental mechanics only.
export function oracle(x) {
  if (!Number.isInteger(x) || x < 0 || x > 0xffffffff) throw new TypeError('Input must be uint32');
  return (Math.imul(x, 17) + 31 ^ (x >>> 3)) >>> 0;
}
export function evaluatePredictions(predictions, inputs) {
  if (!Array.isArray(predictions) || !Array.isArray(inputs) || predictions.length !== inputs.length)
    throw new Error('Predictions and inputs must be arrays of identical length');
  let matches = 0;
  const results = inputs.map((x, i) => {
    const expected = oracle(x);
    const predicted = predictions[i];
    const correct = Number.isInteger(predicted) && predicted === expected;
    if (correct) matches++;
    return { input: x, correct };
  });
  return { schemaVersion: 1, total: inputs.length, matches, accuracy: inputs.length ? matches / inputs.length : null, results, warning: 'Synthetic functional imitation test only. Not proof of confidentiality or resistance to AI.' };
}
export function evaluateFiles(predictionFile, testFile) {
  const predictions = JSON.parse(readFileSync(predictionFile, 'utf8'));
  const inputs = JSON.parse(readFileSync(testFile, 'utf8'));
  return evaluatePredictions(predictions, inputs);
}
