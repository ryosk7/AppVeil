# Survey: on-premises isolated hardware candidates (Track C, issue #23)

**Status: literature survey. Every candidate is *not tested* by AppVeil.** Sources were consulted 2026-11-25. Vendor scope statements are quoted where marked with quotation marks, and paraphrased elsewhere. An independent review (PR #55) corrected the first version; see the end of this document.

## The constraint that dominates everything

In AppVeil's threat model, **the customer owns and physically controls the Olares host** (`agent.md` §1). An on-premises device is in the attacker's hands. A boundary has to resist not only host root but, at some cost, its **physical owner**. Remote cloud TEEs are excluded by the local-execution requirement.

Threat levels: **R** = host root, **F** = firmware or hypervisor, **S** = microarchitectural side channels and interface attacks, **P** = physical (bus interposers, DIMM or SPD tampering, probing, fault injection).

| Candidate | What runs inside | R | F | S | P (physical owner) | Integration with Olares (reuse OAC/Market) |
| --- | --- | --- | --- | --- | --- | --- |
| **Olares One CPU as shipped** | — | ✗ | ✗ | ✗ | ✗ | Native. **No TEE (no SGX/TDX); no TME either**, as delivered. Whether the CPU or the BIOS is the cause was not determined ([Olares One evidence](../docs/OLARES_ONE_HW_EVIDENCE_2026-11-24.md), issue #20). SGX is listed as deprecated on 11th/12th-gen Core processors [1], and Intel's current SGX support list contains only Xeon families [2]. |
| **TPM 2.0** (present on Olares One) | key sealing to PCRs, small crypto operations; no application code | ✗ once a key is unsealed into host memory | partial: measured boot only, and on Olares One Secure Boot is off, lockdown is `none` and IMA holds one measurement (#20) | n/a | **✗**: on a discrete TPM, a bus sniffer recovers unsealed secrets in transit, and reset or interposer attacks can replay PCRs; firmware TPMs have fallen to fault injection, e.g. faulTPM against AMD fTPM [17]. On Olares One, firmware vs discrete TPM was not determined (#20) | Boot integrity and anti-rollback only. **Not runtime secrecy** (`docs/CONFIDENTIAL_RUNTIME.md`). |
| **Server CPU TEEs: Intel TDX** (introduced on 4th Gen Xeon for select cloud providers; generally available to OEMs from 5th Gen Xeon [3][4]; check SKU and BIOS support in ARK) and **AMD SEV-SNP** (EPYC 7003 and later [5][6]) | whole confidential VMs | ✓ by design; recurring firmware and hypervisor CVEs break it in practice, e.g. RMP bypasses [7] and RMPocalypse [18] | same as R | partial: CacheWarp (CVE-2023-20592) [19] and other interface or side-channel attacks continue | **✗: vendors place physical attacks out of scope.** AMD: "physical vector attacks are out of scope for AMD SEV-SNP" [10]. Demonstrated attacks: BadRAM (about $10, SPD reprogramming, SEV-SNP including forged attestation) [20]; Battering RAM (under $50, DDR4: Scalable SGX, SEV-SNP) and WireTap (about $1,000, DDR4: SGX including attestation keys) [8][9]; TEE.fail (under $1,000, DDR5: SGX, TDX, SEV-SNP including attestation keys) [11] | A separate server outside Olares One, called by Olares charts over the network. Large cost and integration effort; needs its own attestation verifier (#21). |
| **GPU confidential computing** (NVIDIA H100 and later in CC mode, with a CPU CVM) [12][13] | GPU kernels plus the CVM | inherits the CPU TEE | inherits | partial | ✗: TEE.fail's extracted CPU attestation keys can compromise NVIDIA GPU CC [11]; on-package HBM is not encrypted [13] | Only relevant together with a server CPU TEE. |
| **Secure element / smartcard** (Java Card; e.g. NXP JCOP 5.1, CC EAL5 augmented [14]; protection profile [15]) | small applets in a restricted Java subset on a resource-constrained device | ✓ for key secrecy; **✗ for use control** (see below) | ✓ | certified against side channels in the evaluated configuration (AVA_VAN), but attacks on certified smartcards are still published | **the strongest of the candidates** (tamper response, certified physical resistance), but not unbreakable | Feasible as a USB or PCIe peripheral. **Compute is tiny.** |
| **USB HSM** (e.g. YubiHSM 2, FIPS 140-3 Level 3, NIST CMVP #5302 [16]) | fixed crypto operations (sign, decrypt, wrap); **no custom code** | ✓ key secrecy / ✗ use control | ✓ | **not covered by the certificate** ("Non-Invasive Security: N/A") [16] | Level 3 physical tamper evidence and resistance | Protects keys, not computation. |
| **Programmable HSMs / secure coprocessors** (e.g. Entrust nShield CodeSafe [21]; IBM 4769, FIPS 140-2 Level 4 [22]) | customer code inside the HSM boundary | ✓ key secrecy / ✗ use control | ✓ | certificate-dependent | strongest physical resistance among programmable options (Level 4 tamper response) | Small and expensive; a vendor SDK and an appliance model. The certificate status must be checked: #4553 has a sunset date. |
| Other options noted but not rated | Intel TXT/DRTM (`smx` is present on Olares One) gives measured launch, not secrecy. Arm TrustZone and CCA have little relevance on-prem on x86 and are weak against physical attacks. FPGA bitstream encryption (Starbleed broke Xilinx 7-series). A vendor-sealed, tamper-responsive appliance. | | | | | |

## Findings

1. **No surveyed option gives general application logic confidentiality against a motivated physical owner.** CPU TEEs explicitly exclude physical attackers, and attacks costing $10 to $1,000 defeat them in practice [8][9][10][11][20]. That is exactly AppVeil's threat model.
2. **What hardware can realistically protect on-premises is small:** key secrecy (HSM or TPM, with the caveats above), and *tiny* functions in a secure element or a programmable HSM. **Host root controls every I/O to such a device.** It can use the device as an oracle (sign, decrypt, evaluate) and can patch host code to skip or ignore the device's answer. A license check on a secure element therefore does not stop the host application from being patched. Only functions **whose output is itself the protected value**, not a gate, benefit. Any design must shrink the secret down to such a function. That is a research question for Tracks A/B, and black-box imitation (#14) still applies to whatever the function computes.
3. **Server TEEs are *designed* to protect against host root and firmware without physical access.** Firmware and hypervisor CVEs have repeatedly broken that in practice [7][18]. And if the customer owns that server, it is in their physical hands too: against the stated adversary a server TEE gives nothing, only protection from non-physical insiders. Adopting one is a **downgraded threat model** and must be stated as such, never as "protected from the customer".
4. Everything above is **not tested**. Before any support claim: obtain the hardware, verify attestation end to end, run the key-extraction lab (#24) against it, and record negative results.

## Sources

1. [Wikipedia: Software Guard Extensions (deprecation on 11th/12th-gen Core)](https://en.wikipedia.org/wiki/Software_Guard_Extensions)
2. [Intel: Processors supporting Intel SGX (Xeon families only)](https://intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions-processors.html)
3. [Intel support article 000091103: TDX processor support](https://www.intel.com/content/www/us/en/support/articles/000091103.html)
4. [Intel newsroom: 5th Gen Xeon; TDX generally available to OEMs and CSPs](https://www.intel.com/content/www/us/en/newsroom/news/5th-gen-xeon-data-center-news.html)
5. [AMD: SEV-SNP attestation overview (supported since 3rd Gen EPYC)](https://www.amd.com/content/dam/amd/en/documents/developer/lss-snp-attestation.pdf)
6. [Lenovo Press: Enabling AMD SEV-SNP (EPYC 7003 and later)](https://lenovopress.lenovo.com/lp1893-enabling-amd-sev-snp-on-thinksystem-servers)
7. [AMD-SB-3037: SEV firmware vulnerabilities (RMP protection bypass by a malicious hypervisor)](https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3037.html)
8. [Intel: statement on encrypted memory frameworks (Battering RAM, WireTap)](https://www.intel.com/content/www/us/en/developer/articles/news/more-information-encrypted-memory-frameworks.html)
9. [Kaspersky: WireTap and Battering RAM (DDR4)](https://www.kaspersky.com/blog/wiretap-battering-ram-tee-attacks/54598/)
10. [AMD-SB-3040: DDR5 bus interposition (TEE.fail); physical vectors out of scope](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3040.html)
11. [The Hacker News: TEE.fail (DDR5; SGX, TDX, SEV-SNP; attestation keys; NVIDIA GPU CC)](https://thehackernews.com/2025/10/new-teefail-side-channel-attack.html)
12. [NVIDIA attestation documentation](https://docs.nvidia.com/attestation/)
13. [NVIDIA: Confidential computing on H100 GPUs](https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/)
14. [NXP JCOP 5.1 Security Target Lite (CC EAL5 augmented)](https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/[ST-LITE]%20SecurityTarget-Lite_JCOP5.1_v2.2.pdf)
15. [Oracle: Java Card Protection Profile](https://oracle.com/technetwork/java/embedded/javacard/documentation/pp-jcs-392791.pdf)
16. [NIST CMVP certificate #5302 (YubiHSM 2 FIPS 140-3 Level 3)](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5302)
17. [faulTPM: exposing AMD fTPMs' deepest secrets (arXiv 2304.14717)](https://arxiv.org/abs/2304.14717)
18. [AMD-SB-3020: RMPocalypse (CVE-2025-0033)](https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3020.html)
19. [CacheWarp (CVE-2023-20592)](https://cachewarpattack.com/)
20. [BadRAM (IEEE S&P 2025; CVE-2024-21944)](https://badram.eu/)
21. [Entrust nShield CodeSafe](https://www.entrust.com/products/hsm/codesafe)
22. [IBM 4769 PCIe cryptographic coprocessor](https://www.ibm.com/security/cryptocards/pciecc/overview) and [NIST CMVP #4553](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4553)

## Independent review (PR #55)

An AI reviewer agent, independent of the implementing session, checked all 16 original citations and returned "approve with fixes". Corrected here:
- the TPM physical rating was too generous
- AMD-SB-3037 was mis-cited as side-channel evidence; it covers firmware and hypervisor bypasses
- BadRAM was missing
- TDX on-prem availability was overstated
- the 2025 interposer attacks were merged, although their scopes differ
- the HSM and secure-element oracle and bypass problem was missing
- YubiHSM side-channel coverage was overstated, and the cited link returned 404
- programmable HSMs were missing
- the GPU claim and the SGX deprecation claim cited sources that do not support them
- "EAL6+" was unsupported by the cited sources
- Finding 3 overstated what server TEEs protect
- TME is not a TEE
- "quoted" claims were in fact paraphrased

Sources [17]–[22] were added from the review. They were not all re-fetched by the author: verify before relying on them.
