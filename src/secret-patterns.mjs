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
  { id: 'SECRET_AWS_ACCESS_KEY_ID', severity: 'high', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, message: 'AWS access key ID' },
  { id: 'SECRET_SLACK_TOKEN', severity: 'high', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, message: 'Slack token' },
  { id: 'SECRET_NPM_TOKEN', severity: 'critical', re: /\bnpm_[A-Za-z0-9]{36}\b/g, message: 'npm access token' },
  { id: 'SECRET_STRIPE_LIVE_KEY', severity: 'critical', re: /\b[sr]k_live_[A-Za-z0-9]{20,}\b/g, message: 'Stripe live secret key' },
  {
    id: 'SECRET_ASSIGNMENT', severity: 'high',
    // KEY=value / KEY: value / "key": "value". Key and value are refined by isSecretKey/isSecretLiteral.
    // Whitespace around the separator stays on one line, so `key:\n  other: x` cannot pair a key with the next line.
    re: /(?:^|[\s{,;(])["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?[ \t]*[:=][ \t]*(["'`]?)([^\s"'`,;}{:]{8,})(["'`]?)/gm,
    message: 'Secret-like key assigned a literal value'
  }
]);

// The key's LAST word must name a secret (`dbPassword`, `API_KEY`, `client_secret`), so words that merely
// contain one (`tokens`, `Tokenizer`, `maxTokens`, `privateKeyEncoding`) do not match.
const SECRET_LAST_WORD = new Set(['secret', 'token', 'password', 'passwd', 'pwd', 'credential', 'credentials', 'apikey', 'privatekey', 'accesskey', 'secretkey']);
const KEY_QUALIFIERS = new Set(['api', 'private', 'access', 'secret', 'signing', 'encryption', 'client', 'master']);
export function isSecretKey(key) {
  const words = key.split(/[._-]+|(?<=[a-z0-9])(?=[A-Z])/).filter(Boolean).map(w => w.toLowerCase());
  if (!words.length) return false;
  const last = words[words.length - 1], prev = words[words.length - 2];
  return SECRET_LAST_WORD.has(last) || (last === 'key' && KEY_QUALIFIERS.has(prev));
}
// Characters a literal secret can contain. Code (`a.b()`, `x[0]`, `$(cmd)`, `<T>`, `!a`) is excluded.
const SECRET_LITERAL = /^[A-Za-z0-9+/=_\-.~@#%^&*]{8,}$/;
const CODE_FILE = /\.(?:[cm]?js|jsx|[cm]?tsx?)$/i;
// Lowercase kebab-case words without digits (`same-origin`, `no-referrer`) are enum values, not secrets.
const KEBAB_WORDS = /^[a-z]+(?:-[a-z]+)+$/;
export function isSecretLiteral(value, { quoted, closed, codeFile }) {
  if (!SECRET_LITERAL.test(value)) return false;
  if (PLACEHOLDER.test(value) || REFERENCE.test(value) || IDENTIFIER_NO_DIGIT.test(value) || KEBAB_WORDS.test(value) || value.startsWith('/')) return false;
  // In source code only an actual string literal counts; unquoted text is an expression.
  if (codeFile && !(quoted && closed)) return false;
  if (quoted && !closed) return false;
  return true;
}

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
      if (rule.id === 'SECRET_ASSIGNMENT') {
        const [, key, open, value, close] = m;
        if (!isSecretKey(key) || !isSecretLiteral(value, { quoted: !!open, closed: !!open && close === open, codeFile: CODE_FILE.test(rel) })) continue;
      }
      if (rule.id === 'SECRET_AWS_ACCESS_KEY_ID' && PLACEHOLDER.test(m[0])) continue;
      count++;
      // Some patterns start with a leading separator (possibly a newline); report the line of the token itself.
      if (lines.length < 10) lines.push(lineOf(text, m.index + (m[0].length - m[0].replace(/^[\s{,;]+/, '').length)));
    }
    if (count) findings.push({ rule: rule.id, severity: rule.severity, path: rel, lines, count, message: `${rule.message} (value omitted)` });
  }
  return findings;
}
