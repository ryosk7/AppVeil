import { readFileSync } from 'node:fs';

export function auditDockerfileText(source) {
  const lines = source.replace(/\\\n/g, ' ').split(/\r?\n/);
  const stages = [];
  let stage = null;
  for (const [idx, line] of lines.entries()) {
    const clean = line.trim();
    if (!clean || clean.startsWith('#')) continue;
    const from = /^FROM\s+\S+(?:\s+AS\s+(\S+))?/i.exec(clean);
    if (from) { stage = { name: from[1] || `stage-${stages.length}`, steps: [] }; stages.push(stage); continue; }
    if (stage) stage.steps.push({ line: idx + 1, text: clean });
  }
  if (!stages.length) return [{ severity: 'high', rule: 'NO_FROM', line: 0, message: 'No Dockerfile FROM instruction found' }];
  const final = stages.at(-1);
  const findings = [];
  for (const step of final.steps) {
    const s = step.text;
    if (/^COPY\s/i.test(s)) {
      if (/\s\.npmrc(?:\s|$)/i.test(s) || /\/\.npmrc(?:\s|$)/i.test(s))
        findings.push({ severity: 'medium', rule: 'NPMRC_IN_RUNTIME', line: step.line, message: 'Final image copies .npmrc; confirm no credentials or unnecessary registry config' });
      if (/^COPY\s+(?:--[^\s]+\s+)*\.\s+\.?\/?\s*$/i.test(s))
        findings.push({ severity: 'high', rule: 'COPY_ALL_IN_RUNTIME', line: step.line, message: 'Final image copies the whole build context' });
      if (/\bsrc\b/.test(s) && !/--from\s*=/.test(s))
        findings.push({ severity: 'medium', rule: 'SOURCE_IN_RUNTIME', line: step.line, message: 'Final image may copy source directory' });
    }
    if (/^ENV\s+.*(?:TOKEN|PASSWORD|SECRET|KEY)\s*=/i.test(s))
      findings.push({ severity: 'high', rule: 'POSSIBLE_SECRET_ENV', line: step.line, message: 'Inspect runtime ENV for embedded secrets' });
  }
  if (!final.steps.some(step => /^USER\s+(?!0(?:\s|$)|root(?:\s|$))/i.test(step.text)))
    findings.push({ severity: 'medium', rule: 'ROOT_RUNTIME', line: 0, message: 'Final stage has no explicit non-root USER' });
  return findings;
}
export function auditDockerfile(filename) { return auditDockerfileText(readFileSync(filename, 'utf8')); }
