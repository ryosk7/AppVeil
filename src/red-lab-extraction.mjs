import { readFileSync, openSync, readSync, closeSync } from 'node:fs';
import { createPrivateKey, createPublicKey, createHash, sign, verify } from 'node:crypto';

/**
 * Red Lab key/material extraction (issue #24). Reads a SOFTWARE-only secret module's memory via
 * /proc/<pid>/mem (Linux) and searches for key material and secrets. The access used is ptrace-level
 * (PTRACE_MODE_ATTACH): in the test, an unprivileged parent against its own child; root is assumed to
 * have at least this access. Expected outcome: extraction succeeds (a negative SECURITY result).
 * Run only against synthetic test processes in an isolated environment, never against real secrets.
 */
const PEM = /-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]{40,4000}-----END PRIVATE KEY-----/g;
const SECRET = /APPVEIL-SYNTHETIC-SECRET-[0-9a-f]{32}/g;

export function supported() {
  if (process.platform !== 'linux') return false;
  try { readFileSync('/proc/self/maps', 'utf8'); return true; } catch { return false; }
}

/** Scan readable+writable private mappings of `pid`. Returns found PEM keys and synthetic secrets. */
export function scanProcessMemory(pid, { maxRegionBytes = 256 * 1024 * 1024, maxTotalBytes = 2 * 1024 ** 3 } = {}) {
  if (!supported()) return { status: 'not-checked', reason: '/proc/<pid>/mem is not available on this platform' };
  const maps = readFileSync(`/proc/${pid}/maps`, 'utf8').split('\n').filter(Boolean);
  const fd = openSync(`/proc/${pid}/mem`, 'r');
  const pems = new Set(), secrets = new Set();
  let scanned = 0, regions = 0, unreadable = 0, skippedByCap = 0;
  try {
    for (const line of maps) {
      const [range, perms] = line.split(/\s+/);
      if (!perms.startsWith('rw')) continue;
      const [a, b] = range.split('-').map(h => BigInt(`0x${h}`));
      const len = Number(b - a);
      // Regions skipped because of caps are counted: a scan cut short must not read as "not extracted".
      if (len > maxRegionBytes || scanned + len > maxTotalBytes) { skippedByCap++; continue; }
      const buf = Buffer.alloc(len);
      try { readSync(fd, buf, 0, len, a); } catch { unreadable++; continue; }
      regions++; scanned += len;
      const text = buf.toString('latin1');
      for (const m of text.matchAll(PEM)) pems.add(m[0]);
      for (const m of text.matchAll(SECRET)) secrets.add(m[0]);
    }
  } finally { closeSync(fd); }
  return { status: 'scanned', regions, unreadable, skippedByCap, bytesScanned: scanned, pems: [...pems], secrets: [...secrets] };
}

/**
 * Judge an extraction against what the target announced (public key, SHA-256 of the secret).
 * Success = the attacker holds the exact secret AND a private key that can sign as the module.
 */
export function judgeExtraction(scan, announced) {
  if (scan.status !== 'scanned') return { result: 'not-checked', reason: scan.reason };
  const secretRecovered = scan.secrets.some(s => createHash('sha256').update(s).digest('hex') === announced.secretSha256);
  let keyRecovered = false;
  for (const pem of scan.pems) {
    try {
      const k = createPrivateKey(pem);
      if (createPublicKey(k).export({ type: 'spki', format: 'der' }).toString('hex') !== announced.publicDer) continue;
      // Prove impersonation: a signature by the extracted key verifies under the module's public key.
      const msg = Buffer.from('red-lab impersonation proof');
      keyRecovered = verify(null, msg, createPublicKey({ key: Buffer.from(announced.publicDer, 'hex'), format: 'der', type: 'spki' }), sign(null, msg, k));
      if (keyRecovered) break;
    } catch { /* fragment, not a key */ }
  }
  const complete = scan.unreadable === 0 && scan.skippedByCap === 0;
  let result = secretRecovered && keyRecovered ? 'extracted' : secretRecovered || keyRecovered ? 'partial' : 'not-extracted';
  // An incomplete scan cannot support "not-extracted": the material may sit in a region not read.
  if (result !== 'extracted' && !complete) result = 'not-checked';
  return { result, secretRecovered, keyRecovered, bytesScanned: scan.bytesScanned, unreadableRegions: scan.unreadable, skippedRegions: scan.skippedByCap, scanComplete: complete };
}
