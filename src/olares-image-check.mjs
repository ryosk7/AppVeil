import { readFileSync } from 'node:fs';

function extractImageRef(contents) {
  const lines = contents.split(/\r?\n/);
  const imageStart = lines.findIndex(l => /^image:\s*(?:#.*)?$/.test(l));
  if (imageStart === -1) throw new Error('Could not find top-level image: section');
  for (let i = imageStart + 1; i < lines.length; i++) {
    const line = lines[i];
    if (/^[^\s#][^:]*:/.test(line)) break;
    const match = /^\s{2,}server:\s*['"]?([^\s#'"]+)/.exec(line);
    if (match) return match[1];
  }
  throw new Error('Missing image.server under image:');
}
export function checkOlaresImageRef(valuesText, { previousImage = null, requireDigest = false } = {}) {
  const image = extractImageRef(valuesText);
  const digest = /@sha256:[a-f0-9]{64}$/i.test(image);
  const pinnedTag = /:[^/:@]+$/.test(image) && !/:latest$/.test(image);
  const errors = [];
  if (!digest && !pinnedTag) errors.push('The image must have an explicit non-latest version tag or immutable SHA-256 digest');
  if (previousImage && image === previousImage) errors.push('The Chart still references the previous image: publish and reference a new verified release');
  if (requireDigest && !digest) errors.push('A digest-pinned image is required by the chosen policy');
  return { schemaVersion: 1, image, digestPinned: digest, previousImage: previousImage ?? null, pass: errors.length === 0, errors, note: 'Validates OAC image reference metadata only; does not establish the image was built from the current source, scanned, signed or deployed.' };
}
export function checkOlaresValuesFile(filename, options = {}) {
  return checkOlaresImageRef(readFileSync(filename, 'utf8'), options);
}
