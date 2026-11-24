// Restricted-TypeScript subset example (see research/TS_FRONTEND.md).
export function score(x: number, strict: boolean): { score: number; over: boolean } {
  let acc = x;
  for (let i = 0; i < 4; i++) {
    acc = (Math.imul(acc, 2654435761) >>> 0 ^ acc >>> 15) >>> 0;
    if (i === 2) {
      acc = (acc + 1) >>> 0;
    }
  }
  const limit = strict ? 1000 : 100000;
  const low = acc >>> 12;
  const over = low > limit;
  return { score: over ? limit : low, over: over };
}
