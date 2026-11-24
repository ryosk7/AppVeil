// Synthetic "secret module" for the key-extraction lab (issue #24). Holds ONLY synthetic test data.
// It loads its private key from a PEM file (as typical software does) and keeps a synthetic secret in
// memory, then announces its PID, public key and SHA-256 of the secret (never the secret itself).
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, createHash, randomBytes } from 'node:crypto';
// `node --test` also loads files under test/; without a key path this file does nothing.
if (!process.argv[2]) process.exit(0);
const pem = readFileSync(process.argv[2], 'utf8');
const key = createPrivateKey(pem);
const secret = Buffer.from(`APPVEIL-SYNTHETIC-SECRET-${randomBytes(16).toString('hex')}`);
const publicDer = createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('hex');
process.stdout.write(`${JSON.stringify({ pid: process.pid, publicDer, secretSha256: createHash('sha256').update(secret).digest('hex') })}\n`);
// Keep references alive (as a long-running module would) until told to exit.
setInterval(() => { if (secret.length === 0 || !pem) process.exit(2); }, 1000);
process.stdin.on('data', () => process.exit(0));
