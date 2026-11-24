# Olares One hardware security capability evidence (2026-11-24)

Issue #20. Collected **read-only** on the user's own Olares One with `scripts/collect-hw-evidence.sh`, at 2026-11-24T15:20Z over SSH. No configuration was changed. Serial numbers, UUIDs, MAC addresses and the kernel command line were not collected. Uptime at collection: 13 days.

| Item | Observed | Source |
| --- | --- | --- |
| CPU | Intel Core Ultra 9 275HX, 24 cores, 1 thread per core | `lscpu` |
| OS / kernel | Ubuntu 24.04.3 LTS, 6.14.0-37-generic, Olares 1.12.7 | `/etc/os-release`, `uname -r` |
| Firmware | vendor "CWL", BIOS 1.01 dated 12/04/2025; booted via UEFI | `dmidecode -s`, `/sys/firmware/efi` |
| SGX | **absent**: no `sgx`/`sgx_lc`/`sgx2` CPU flags, no `/dev/sgx_enclave` | `/proc/cpuinfo`, `/dev` |
| TDX | **absent**: no `tdx_host_platform` or `tdx_guest` flag | `/proc/cpuinfo` |
| AMD SME/SEV | absent (Intel CPU) | `/proc/cpuinfo` |
| TME (memory encryption) | **absent** flag | `/proc/cpuinfo` |
| VT-x / SMX (TXT) | `vmx` present, `smx` present | `/proc/cpuinfo` |
| TPM | **TPM 2.0 present** (`/dev/tpm0`, `/dev/tpmrm0`, ACPI HID `MSFT0101`); a boot event log exists (root-readable) | `/sys/class/tpm`, securityfs |
| TPM implementation (firmware TPM vs discrete) | **not checked**: `tpm2-tools` is not installed, and the generic HID does not tell them apart | — |
| Secure Boot | **disabled** | EFI variable `SecureBoot` |
| Kernel lockdown | LSM loaded but mode **`[none]`** | `/sys/kernel/security/lockdown` |
| IMA | LSM loaded, **1 measurement** (boot aggregate only), so no runtime measurement policy | securityfs |
| IOMMU | 2 DMAR units present; default domain type of group 0 is **`identity`** (passthrough) | `/sys/class/iommu`, `/sys/kernel/iommu_groups` |
| Kernel build config | **not checked**: `/boot/config-*` is not installed | — |

## What this does and does not establish

- **No hardware TEE is available to applications on this device.** SGX and TDX are not exposed. This evidence cannot tell whether the cause is the CPU model or the firmware configuration; either way, the device as delivered provides neither. AppVeil's confidential execution mode (`docs/CONFIDENTIAL_RUNTIME.md`, option C) is therefore **unsupported on Olares One** and must fail closed there.
- **The TPM does not provide runtime secrecy from root.** A TPM 2.0 can seal keys to measured-boot PCR values. On this host, however, Secure Boot is off, lockdown is `none`, IMA measures nothing at runtime, and the IOMMU defaults to passthrough. Once a sealed key is released into the OS, root can read it from process memory. Measured boot is not runtime confidentiality.
- **Not tested:** TPM vendor and firmware version, Intel TXT/Boot Guard configuration, BIOS options for SGX or TME (no physical or BIOS access was used), and physical attacks.
- A repeat run of `scripts/collect-hw-evidence.sh` after any firmware or OS update is required before these statements are relied on again.
