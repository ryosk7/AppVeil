# Survey: on-premises isolated hardware candidates (Track C, issue #23)

**Status: literature survey. Every candidate is *not tested* by AppVeil. Independent review is required.** Sources were consulted 2026-11-25 and are cited below; vendor scope statements are quoted as found.

## The constraint that dominates everything

In AppVeil's threat model, **the customer owns and physically controls the Olares host** (`agent.md` §1). An on-premises device is in the attacker's hands. A boundary therefore has to resist not only host root but, at some cost, its **physical owner**. Remote cloud TEEs are excluded by the local-execution requirement.

Threat levels: **R** = host root, **F** = firmware or hypervisor, **S** = microarchitectural side channels, **P** = physical (bus interposers, probing, fault injection).

| Candidate | What runs inside | R | F | S | P (physical owner) | Integration with Olares (reuse OAC/Market) |
| --- | --- | --- | --- | --- | --- | --- |
| **Olares One CPU as shipped** | — | ✗ | ✗ | ✗ | ✗ | Native. **No TEE: no SGX/TDX/TME** ([#20](../docs/OLARES_ONE_HW_EVIDENCE_2026-11-24.md)). SGX has also been deprecated on Intel client (Core) processors since the 11th/12th generation [1][2]. |
| **TPM 2.0** (present on Olares One) | key sealing to PCRs, small crypto operations; no application code | ✗ once a key is unsealed into host memory | partial (measured boot) | n/a | partial (discrete vs firmware TPM not determined, #20) | Usable for boot integrity and anti-rollback only. **Not runtime secrecy** (`docs/CONFIDENTIAL_RUNTIME.md`). |
| **Server CPU TEEs: Intel TDX** (4th/5th Gen Xeon Scalable and later) [3][4]; **AMD SEV-SNP** (EPYC 7003 and later) [5][6] | whole confidential VMs | ✓ (by design) | ✓ (by design) | partial (an ongoing stream of advisories, e.g. [7]) | **✗: vendors place physical attacks out of scope.** DDR4/DDR5 bus-interposer attacks costing under $50 to about $1,000 broke SGX, SEV-SNP and TDX in 2025 (Battering RAM, WireTap, TEE.fail), including **forged attestation** [8][9][10][11] | A separate server outside Olares One; Olares charts would call it over the network. Large cost and integration effort; would need its own attestation verifier (#21). |
| **GPU confidential computing** (NVIDIA H100 and later in CC mode, with a CPU CVM) [12][13] | GPU kernels plus the CVM | inherits the CPU TEE | inherits | partial | ✗: TEE.fail extracted CPU attestation keys that undermine GPU CC [10] | Only relevant together with a server CPU TEE. |
| **Secure element / smartcard** (Java Card, CC EAL5+/EAL6+) [14][15] | small applets in a restricted Java subset on a single resource-constrained device | ✓ (keys and applet state never leave the chip) | ✓ | designed against it (certified) | **strongest of the candidates** (tamper response, certified physical resistance), but not unbreakable | Feasible as a USB or PCIe peripheral. **Compute is tiny**: only a very small secret function or license logic could live there, not application logic. |
| **USB HSM** (e.g. YubiHSM 2, FIPS 140-3 Level 3, cert #5302) [16] | fixed crypto operations (sign, decrypt, wrap); **no custom code** | ✓ for keys | ✓ | certified scope | Level 3 physical tamper evidence and resistance | Protects keys (signing, license tokens), not computation. |

## Findings

1. **No surveyed option gives general application logic confidentiality against a motivated physical owner.** CPU TEEs explicitly exclude physical attackers, and cheap interposers defeat them in practice [8][9][10][11]. That case is exactly AppVeil's threat model.
2. **What hardware can realistically protect on-premises is small:** keys (HSM or TPM, with the caveats above) and *tiny* secret functions in a secure element. Any design must shrink the secret down to something that fits there. That is a research question for Track A/B: splitting a program so that only a small critical function needs protection. Black-box imitation (#14) still applies to whatever such a function computes.
3. **Server TEEs still raise the cost of an attack:** they protect against host root and firmware without physical access. Even that would need new hardware outside Olares One, a real attestation verifier (#21), the authenticated IPC (#22), and an honest statement that physical owners are out of scope. Under `agent.md` that is a downgraded threat model, and it must be stated as such, never as "protected from the customer".
4. Everything above is **not tested**. Before any support claim: obtain the hardware, verify attestation end to end, run the key-extraction lab (#24) against it, and record negative results.

## Sources

1. [Wikipedia: Software Guard Extensions (deprecation on 11th/12th-gen Core)](https://en.wikipedia.org/wiki/Software_Guard_Extensions)
2. [Intel: Processors supporting Intel SGX](https://intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions-processors.html)
3. [Intel support article 000091103: Intel TDX processor support](https://www.intel.com/content/www/us/en/support/articles/000091103.html)
4. [Intel newsroom: 5th Gen Xeon, TDX generally available](https://www.intel.com/content/www/us/en/newsroom/news/5th-gen-xeon-data-center-news.html)
5. [AMD: SEV-SNP attestation overview (supported since 3rd Gen EPYC)](https://www.amd.com/content/dam/amd/en/documents/developer/lss-snp-attestation.pdf)
6. [Lenovo Press: Enabling AMD SEV-SNP (EPYC 7003 and later)](https://lenovopress.lenovo.com/lp1893-enabling-amd-sev-snp-on-thinksystem-servers)
7. [AMD-SB-3037: AMD SEV vulnerabilities](https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3037.html)
8. [Intel: More information on encrypted memory frameworks (Battering RAM / WireTap response)](https://www.intel.com/content/www/us/en/developer/articles/news/more-information-encrypted-memory-frameworks.html)
9. [Kaspersky: WireTap and Battering RAM attacks on TEEs](https://www.kaspersky.com/blog/wiretap-battering-ram-tee-attacks/54598/)
10. [AMD-SB-3040: DDR5 memory bus interposition (TEE.fail); physical vectors out of scope](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3040.html)
11. [The Hacker News: TEE.fail breaks TDX and SEV-SNP via DDR5](https://thehackernews.com/2025/10/new-teefail-side-channel-attack.html)
12. [NVIDIA attestation documentation](https://docs.nvidia.com/attestation/)
13. [NVIDIA: Confidential computing on H100 GPUs](https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/)
14. [NXP JCOP 5.1 Security Target Lite (CC EAL5+)](https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/[ST-LITE]%20SecurityTarget-Lite_JCOP5.1_v2.2.pdf)
15. [Oracle: Java Card Protection Profile](https://oracle.com/technetwork/java/embedded/javacard/documentation/pp-jcs-392791.pdf)
16. [Yubico: YubiHSM 2 introduction (FIPS 140-3 Level 3)](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-introduction.html)
