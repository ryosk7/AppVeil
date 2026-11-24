/**
 * Minimal JSON Schema (draft 2020-12) checker for the keyword subset used by AppVeil's own schemas.
 * It is NOT a general validator: unsupported keywords throw, so a schema cannot silently lose a
 * constraint. Recursion depth and error count are bounded.
 */
const SUPPORTED = new Set(['$schema', '$id', 'title', 'description', '$defs', '$ref', 'type', 'const', 'enum',
  'properties', 'required', 'additionalProperties', 'items', 'prefixItems', 'minItems', 'maxItems', 'uniqueItems',
  'minimum', 'maximum', 'pattern', 'maxLength', 'oneOf', 'propertyNames', 'minProperties', 'maxProperties']);
const typeOf = v => v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v;
const deepEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export function validateSchema(schema, value, { maxDepth = 256 } = {}) {
  const errors = [];
  function resolve(ref) {
    const m = /^#\/\$defs\/([A-Za-z0-9_-]+)$/.exec(ref);
    if (!m || !schema.$defs || !Object.hasOwn(schema.$defs, m[1])) throw new Error(`Unsupported or unknown $ref: ${ref}`);
    return schema.$defs[m[1]];
  }
  // `depth` counts value nesting; `hops` counts schema indirections ($ref/oneOf) at the same value,
  // so a self-referential schema cannot loop forever.
  function check(s, v, path, depth, hops = 0) {
    if (depth > maxDepth) { errors.push(`${path}: maximum value depth exceeded`); return; }
    if (hops > 32) throw new Error(`Schema indirection limit exceeded at ${path || '/'}`);
    for (const k of Object.keys(s)) if (!SUPPORTED.has(k) && !k.startsWith('x-')) throw new Error(`Unsupported schema keyword: ${k}`);
    if (s.$ref) return check(resolve(s.$ref), v, path, depth, hops + 1);
    const t = typeOf(v);
    if (s.type && !(s.type === t || (s.type === 'number' && t === 'integer'))) return errors.push(`${path}: expected ${s.type}, got ${t}`);
    if ('const' in s && !deepEqual(s.const, v)) errors.push(`${path}: expected const ${JSON.stringify(s.const)}`);
    if (s.enum && !s.enum.some(e => deepEqual(e, v))) errors.push(`${path}: not in enum`);
    if (t === 'integer' || t === 'number') {
      if ('minimum' in s && v < s.minimum) errors.push(`${path}: below minimum ${s.minimum}`);
      if ('maximum' in s && v > s.maximum) errors.push(`${path}: above maximum ${s.maximum}`);
    }
    if (t === 'string') {
      if ('maxLength' in s && [...v].length > s.maxLength) errors.push(`${path}: longer than ${s.maxLength}`);
      if (s.pattern && !new RegExp(s.pattern, 'u').test(v)) errors.push(`${path}: does not match pattern`);
    }
    if (t === 'object') {
      for (const r of s.required ?? []) if (!Object.hasOwn(v, r)) errors.push(`${path}: missing required ${r}`);
      for (const [k, sub] of Object.entries(s.properties ?? {})) if (Object.hasOwn(v, k)) check(sub, v[k], `${path}/${k}`, depth + 1);
      const extra = Object.keys(v).filter(k => !Object.hasOwn(s.properties ?? {}, k));
      if (s.additionalProperties === false) for (const k of extra) errors.push(`${path}: unexpected property ${k}`);
      else if (s.additionalProperties && typeof s.additionalProperties === 'object') for (const k of extra) check(s.additionalProperties, v[k], `${path}/${k}`, depth + 1);
      if (s.propertyNames) for (const k of Object.keys(v)) check(s.propertyNames, k, `${path}/<key ${k}>`, depth + 1);
      if ('minProperties' in s && Object.keys(v).length < s.minProperties) errors.push(`${path}: fewer than ${s.minProperties} properties`);
      if ('maxProperties' in s && Object.keys(v).length > s.maxProperties) errors.push(`${path}: more than ${s.maxProperties} properties`);
    }
    if (t === 'array') {
      if ('minItems' in s && v.length < s.minItems) errors.push(`${path}: fewer than ${s.minItems} items`);
      if ('maxItems' in s && v.length > s.maxItems) errors.push(`${path}: more than ${s.maxItems} items`);
      if (s.uniqueItems && new Set(v.map(x => JSON.stringify(x))).size !== v.length) errors.push(`${path}: items not unique`);
      const prefix = s.prefixItems ?? [];
      v.forEach((item, i) => {
        const sub = i < prefix.length ? prefix[i] : s.items;
        if (sub) check(sub, item, `${path}/${i}`, depth + 1);
      });
    }
    if (s.oneOf) {
      const before = errors.length;
      let matches = 0;
      for (const alt of s.oneOf) {
        const saved = errors.length;
        check(alt, v, path, depth, hops + 1);
        if (errors.length === saved) matches++;
        errors.length = saved;
      }
      errors.length = before;
      if (matches !== 1) errors.push(`${path}: matched ${matches} of oneOf alternatives (expected exactly 1)`);
    }
  }
  check(schema, value, '', 0);
  return { valid: errors.length === 0, errors: errors.slice(0, 50) };
}
