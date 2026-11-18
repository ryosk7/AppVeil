# AppVeil threat model (draft)

## Scope
AppVeil is an experimental, open-source toolkit for identifying accidental code/material leakage from self-hosted application images, especially Olares deployments. The scanner is a hygiene check, not a confidentiality boundary.

### Adversary
Assume an Olares One owner can administer the host as root, export container filesystems, inspect process memory, modify Node.js code, and use AI-based decompilers or functional reconstruction tools.

### What AppVeil v0.1.0 does
- Scans directory trees for TypeScript sources, source maps, .env files, potential keys and .npmrc.
- Detects sourceMappingURL references in small JS files.
- Can extract an existing Docker image filesystem without starting its process and inspect it.
- Returns exit status 2 with --strict when high/critical findings exist.

### What it does NOT do
- It does not conceal JavaScript, protect running process memory, detect all leaked secrets, perform static data-flow analysis, validate licenses, or enforce copyright.
- It cannot prevent inspection by the root owner of a standard Olares One.
- It cannot prove safety when no findings are detected.
- It does not certify hardware-based confidentiality.

### Research questions
1. Verify Olares One firmware, TPM, secure boot and runtime capabilities on real hardware.
2. Measure reverse-engineering effort for minified JS, Wasm, native binaries, and protection methods under a fixed AI-enabled adversary model.
3. Research isolation using additional on-premises hardware where required, without claiming standard-device guarantees.
4. Reuse Olares OAC/Market/Merchant instead of recreating their interfaces.
5. Verify private GHCR image pulls and license VC integration before advertising support.

Never embed production credentials in images. Treat all image content as accessible to the image recipient.
