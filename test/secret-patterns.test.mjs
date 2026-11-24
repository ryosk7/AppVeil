import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanSecrets, SECRET_FILE_LIMIT } from '../src/secret-patterns.mjs';
import { scanTree } from '../src/inspect.mjs';

// All values below are synthetic and invalid. They are assembled at runtime so this file itself does
// not contain contiguous token-shaped strings.
const rep = (c, n) => c.repeat(n);
const FAKE = {
  pem: ['-----BEGIN', 'RSA PRIVATE KEY-----'].join(' ') + '\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n',
  openssh: ['-----BEGIN', 'OPENSSH PRIVATE KEY-----'].join(' ') + '\nb3BlbnNzaA==\n',
  github: 'gh' + 'p_' + rep('A1b2', 9),
  githubPat: 'github' + '_pat_' + rep('a1B2_', 16) + 'xy',
  aws: 'AK' + 'IA' + 'Q3EGRZ7NZ5K2XJ4W',
  slack: 'xo' + 'xb-' + '1234567890-abcdefghij',
  npm: 'np' + 'm_' + rep('a1B2', 9),
  stripe: 'sk' + '_live_' + rep('9z', 12)
};
const one = (text, rule, file = 'f.txt') => scanSecrets(file, Buffer.from(text)).filter(f => f.rule === rule);

test('detects each high-signal pattern with line numbers and never emits the value', () => {
  const cases = [
    [FAKE.pem, 'SECRET_PRIVATE_KEY_BLOCK'], [FAKE.openssh, 'SECRET_PRIVATE_KEY_BLOCK'],
    [`token = "${FAKE.github}"`, 'SECRET_GITHUB_TOKEN'], [FAKE.githubPat, 'SECRET_GITHUB_TOKEN'],
    [`aws=${FAKE.aws}`, 'SECRET_AWS_ACCESS_KEY_ID'], [FAKE.slack, 'SECRET_SLACK_TOKEN'],
    [`//registry.npmjs.org/:_authToken=${FAKE.npm}`, 'SECRET_NPM_TOKEN'], [FAKE.stripe, 'SECRET_STRIPE_LIVE_KEY'],
    ['DB_PASSWORD=s3cr3t-Passw0rd-42', 'SECRET_ASSIGNMENT'], ['"apiKey": "k9F2mQ8xL4pR7tW1"', 'SECRET_ASSIGNMENT'],
    ['client_secret: Zx81Qp0LmN4v', 'SECRET_ASSIGNMENT']
  ];
  for (const [text, rule] of cases) {
    const found = one(`line one\n${text}\n`, rule);
    assert.equal(found.length, 1, `${rule} not detected in ${JSON.stringify(text.slice(0, 20))}`);
    assert.equal(found[0].lines[0], 2);
    const json = JSON.stringify(scanSecrets('f.txt', Buffer.from(text)));
    for (const v of Object.values(FAKE)) assert.ok(!json.includes(v.slice(4, 20)), 'value leaked');
    assert.ok(!json.includes('s3cr3t') && !json.includes('k9F2mQ8x') && !json.includes('Zx81Qp0'), 'value leaked');
  }
});

test('benign look-alikes are not flagged', () => {
  const benign = [
    ['-----BEGIN', 'PUBLIC KEY-----'].join(' '), ['-----BEGIN', 'CERTIFICATE-----'].join(' '),
    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', 'password=changeme', 'API_KEY=${API_KEY}', 'TOKEN=<your-token-here>',
    'SECRET=xxxxxxxxxxxx', 'password: process.env.DB_PASSWORD', 'token=os.environ', 'const t={accessToken:e.accessToken,password:this.password};',
    'placeholder:"Enter password"', 'passwordMinLength=12', 'ghp_short', 'GITHUB_TOKEN: secrets.GITHUB_TOKEN',
    'tokenizer = new Tokenizer()',
    // Observed false-positive shapes from vendor and first-party code in real images (values synthetic).
    'const r={tokens:countTokens(text),maxTokens:DEFAULT_MAX_TOKENS};', 'privateKeyEncoding: {type:"pkcs8"}', 'this.tokenizer.state = TokenizerState.DATA_STATE',
    'input_tokens_details: Usage.InputTokensDetails', 'token: tokens[0]', 'password: z.string()', 'apiKey: options.apiKey', 'passwd=$(getpass)',
    'Password: [success=1 default=ignore]', 'confirmPassword: e.target.value', 'const token = "short"',
    'fetch(u,{credentials:"same-origin"})', "app.use(jwt({ secret: 'my-to-be-secret' }))", 'PWD="/Users/someone"'
  ];
  // Unquoted expressions are benign in source code (but would be candidate values in config files).
  for (const file of ['f.js', 'f.d.ts', 'f.mts', 'f.cts']) assert.deepEqual(scanSecrets(file, Buffer.from('credential: ApiKeyCredential1;')), [], file);
  for (const text of benign) for (const file of ['f.js', 'f.d.ts', 'f.mts', 'f.cts', 'f.conf']) assert.deepEqual(scanSecrets(file, Buffer.from(text)), [], `false positive in ${file}: ${text}`);
});

test('in source code only quoted string literals count; config files allow unquoted values', () => {
  assert.equal(one('const apiKey = "k9F2mQ8xL4pR7tW1";', 'SECRET_ASSIGNMENT', 'a.js').length, 1);
  assert.equal(one("export const DB_PASSWORD = 's3cr3t-Passw0rd-42';", 'SECRET_ASSIGNMENT', 'a.ts').length, 1);
  assert.equal(one('const apiKey = k9F2mQ8xL4pR7tW1;', 'SECRET_ASSIGNMENT', 'a.js').length, 0);
  assert.equal(one('apiKey: k9F2mQ8xL4pR7tW1', 'SECRET_ASSIGNMENT', 'config.yaml').length, 1);
  assert.equal(one('API_KEY=k9F2mQ8xL4pR7tW1', 'SECRET_ASSIGNMENT', '.env').length, 1);
  assert.equal(one('db:\n  password: Hx7Kq2mZ9pLw\n', 'SECRET_ASSIGNMENT', 'c.yaml').length, 1, 'nested YAML key');
  assert.equal(one('const apiKey = "k9F2mQ8x L4pR7tW1";', 'SECRET_ASSIGNMENT', 'a.js').length, 0, 'unterminated literal');
});

test('counts repeated matches, caps line list, skips binary and oversized files', () => {
  const text = Array.from({ length: 15 }, (_, i) => `K${i}_TOKEN=Abcdef${i}1234567`).join('\n');
  const [f] = one(text, 'SECRET_ASSIGNMENT');
  assert.equal(f.count, 15);
  assert.equal(f.lines.length, 10);
  assert.deepEqual(scanSecrets('bin', Buffer.concat([Buffer.from([0]), Buffer.from(FAKE.github)])), []);
  assert.deepEqual(scanSecrets('big', Buffer.alloc(SECRET_FILE_LIMIT + 1, 0x41)), []);
});

test('scanTree reports secrets in any text file and fails closed when the content budget is exhausted', () => {
  const root = mkdtempSync(join(tmpdir(), 'appveil-secret-'));
  try {
    mkdirSync(join(root, 'app'));
    writeFileSync(join(root, 'app', 'config.yaml'), `db:\n  password: Hx7Kq2mZ9pLw\n`);
    writeFileSync(join(root, 'app', 'deploy.key.txt'), FAKE.pem);
    writeFileSync(join(root, 'app', 'readme.md'), 'nothing here');
    const rules = scanTree(root).map(f => `${f.rule}:${f.path}`);
    assert.ok(rules.includes('SECRET_ASSIGNMENT:app/config.yaml'));
    assert.ok(rules.includes('SECRET_PRIVATE_KEY_BLOCK:app/deploy.key.txt'));
    assert.ok(!JSON.stringify(scanTree(root)).includes('Hx7Kq2mZ9pLw'));
    const limited = scanTree(root, { maxContentBytes: 10 });
    assert.ok(limited.some(f => f.rule === 'CONTENT_SCAN_INCOMPLETE' && f.severity === 'high'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
