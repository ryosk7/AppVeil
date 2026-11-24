#!/usr/bin/env bash
# Read-only hardware security capability collection for an Olares host (issue #20).
# Makes NO configuration changes. Prints no serial numbers, UUIDs, MAC addresses or kernel command line.
# Run on the host: bash collect-hw-evidence.sh   (sudo -n is used only for dmidecode and root-only reads)
set -u
say() { printf '%s: %s\n' "$1" "$2"; }
say collected_utc "$(date -u +%Y-%m-%dT%H:%MZ)"
say kernel "$(uname -r)"; . /etc/os-release 2>/dev/null && say os "$PRETTY_NAME"
say cpu "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p')"
for f in sgx sgx_lc sgx2 tdx_host_platform tdx_guest sme sev sev_es sev_snp tme vmx smx hypervisor; do
  grep -qw "$f" /proc/cpuinfo && say "cpuflag_$f" present || say "cpuflag_$f" absent
done
[ -e /dev/sgx_enclave ] && say sgx_device present || say sgx_device absent
for k in system-manufacturer system-product-name bios-vendor bios-version bios-release-date; do
  say "dmi_$k" "$(sudo -n dmidecode -s "$k" 2>/dev/null | head -1 || echo not-checked)"
done
[ -d /sys/firmware/efi ] && say boot uefi || say boot legacy
if command -v mokutil >/dev/null; then say secure_boot "$(mokutil --sb-state 2>&1 | head -1)"; else
  v=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)
  [ -n "$v" ] && say secure_boot_var "$(od -An -t u1 -j4 -N1 "$v" | tr -d ' ')" || say secure_boot not-checked
fi
if [ -e /sys/class/tpm/tpm0 ]; then
  say tpm_major "$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo not-checked)"
  say tpm_acpi_hid "$(cat /sys/class/tpm/tpm0/device/hid 2>/dev/null || basename "$(readlink -f /sys/class/tpm/tpm0/device)")"
else say tpm absent; fi
sudo -n test -r /sys/kernel/security/tpm0/binary_bios_measurements && say tpm_event_log present || say tpm_event_log absent-or-not-readable
say lockdown "$(cat /sys/kernel/security/lockdown 2>/dev/null || echo not-checked)"
say lsm "$(cat /sys/kernel/security/lsm 2>/dev/null || echo not-checked)"
say ima_measurements "$(sudo -n cat /sys/kernel/security/ima/ascii_runtime_measurements 2>/dev/null | wc -l || echo not-checked)"
say iommu_units "$(ls /sys/class/iommu 2>/dev/null | tr '\n' ' ')"
say iommu_group0_type "$(cat /sys/kernel/iommu_groups/0/type 2>/dev/null || echo not-checked)"
[ -r "/boot/config-$(uname -r)" ] && for k in CONFIG_X86_SGX CONFIG_INTEL_TDX_HOST CONFIG_IMA; do say "$k" "$(grep -E "^$k=|^# $k is not set" "/boot/config-$(uname -r)" | head -1)"; done || say kernel_config not-checked
