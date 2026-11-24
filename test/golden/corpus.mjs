// Fixed corpus for reproducible-build golden digests (issue #18).
export const GOLDEN_CORPUS = [
  { id: 'v1-score-seed0', file: 'examples/veil-ir-score.json', options: { kind: 'ir', seed: 0 } },
  { id: 'v1-score-seed42', file: 'examples/veil-ir-score.json', options: { kind: 'ir', seed: 42 } },
  { id: 'v2-clamp-seed3', file: 'examples/veil-ir-v2-clamp.json', options: { kind: 'ir', seed: 3 } },
  { id: 'v2-clamp-opt', file: 'examples/veil-ir-v2-clamp.json', options: { kind: 'ir', seed: 3, optimize: true } },
  { id: 'ts-score-seed7', file: 'examples/ts/score.ts', options: { kind: 'ts', seed: 7 } },
  { id: 'ts-score-opt', file: 'examples/ts/score.ts', options: { kind: 'ts', seed: 7, optimize: true } }
];
