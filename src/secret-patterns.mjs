/**
 * High-signal credential patterns. Findings carry path, rule ID, line numbers and a count, never
 * the matched value or surrounding text. Pattern matching misses unknown formats and obfuscated
 * secrets; an empty result is not proof that no secret is present.
 */
export const SECRET_FILE_LIMIT = 1024 * 1024;

// Values that are obviously placeholders or documentation examples are not reported.
const PLACEHOLDER = /^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|<[^>]*>|x+|\*+|\.{3,}|changeme|change_me|example|placeholder|dummy|test|null|none|undefined|true|false|your[-_].*|.*EXAMPLE)$/i;

// Values that read a secret from elsewhere rather than embedding it.
const REFERENCE = /^(?:process\.env|import\.meta|os\.environ|env\.|getenv|config\.|secrets\.|vault:|arn:aws:secretsmanager)/i;
// Minified-JS member expressions such as `t.accessToken` or `this.password`: identifiers without digits.
const IDENTIFIER_NO_DIGIT = /^[A-Za-z_$][A-Za-z_$]*(?:\.[A-Za-z_$][A-Za-z_$]*)*(?:\(\))?$/;

export const SECRET_RULES = Object.freeze([
  { id: 'SECRET_PRIVATE_KEY_BLOCK', severity: 'critical', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, message: 'PEM/OpenSSH/PGP private key block' },
  { id: 'SECRET_GITHUB_TOKEN', severity: 'critical', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g, message: 'GitHub token' },
  { id: 'SECRET_AWS_ACCESS_KEY_ID', severity: 'high', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, value: m => m, message: 'AWS access key ID' },
  { id: 'SECRET_SLACK_TOKEN', severity: 'high', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, message: 'Slack token' },
  { id: 'SECRET_NPM_TOKEN', severity: 'critical', re: /\bnpm_[A-Za-z0-9]{36}\b/g, message: 'npm access token' },
  { id: 'SECRET_STRIPE_LIVE_KEY', severity: 'critical', re: /\b[sr]k_live_[A-Za-z0-9]{20,}\b/g, message: 'Stripe live secret key' },
  {
    id: 'SECRET_ASSIGNMENT', severity: 'high',
    // KEY=value / KEY: value / "key": "value" where the key name looks secret-bearing.
    re: /(?:^|[\s{,;])["']?([A-Za-z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?([^\s"'`,;}{]{8,})/gim,
    value: (_, __, v) => v,
    message: 'Secret-like key assigned a literal value'
  }
]);

const lineOf = (text, index) => { let n = 1; for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++; return n; };
export function looksBinary(bytes) {
  const n = Math.min(bytes.length, 8192);
  for (let i = 0; i < n; i++) if (bytes[i] === 0) return true;
  return false;
}

/** Scan one file's bytes. Returns at most one finding per rule, with up to 10 line numbers. */
export function scanSecrets(rel, bytes) {
  if (bytes.length > SECRET_FILE_LIMIT || looksBinary(bytes)) return [];
  const text = bytes.toString('utf8');
  const findings = [];
  for (const rule of SECRET_RULES) {
    const lines = [];
    let count = 0;
    for (const m of text.matchAll(rule.re)) {
      const value = rule.value ? rule.value(...m) : m[0];
      if (rule.id === 'SECRET_ASSIGNMENT' && (PLACEHOLDER.test(value) || REFERENCE.test(value) || IDENTIFIER_NO_DIGIT.test(value))) continue;
      if (rule.id === 'SECRET_AWS_ACCESS_KEY_ID' && PLACEHOLDER.test(value)) continue;
      count++;
      // Some patterns start with a leading separator (possibly a newline); report the line of the token itself.
      if (lines.length < 10) lines.push(lineOf(text, m.index + (m[0].length - m[0].replace(/^[\s{,;]+/, '').length)));
    }
    if (count) findings.push({ rule: rule.id, severity: rule.severity, path: rel, lines, count, message: `${rule.message} (value omitted)` });
  }
  return findings;
}
