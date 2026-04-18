#!/usr/bin/env bash
# scripts/dev_hugepages.sh — dev-VM hugepages bring-up helper
#
# Ensures 512 × 2 MB hugepages are configured on the dev VM. Idempotent:
# if already 512, exit 0 with a message. Otherwise allocates via
# /sys/.../nr_hugepages (sudo required) and verifies the kernel actually
# gave us the requested count (reboot fallback if fragmentation denies).
#
# CLAUDE.md baseline: "Hugepages: 512 × 2 MB, uio/vfio модули загружены".
# DPDK default mount is /dev/hugepages (hugetlbfs). We mount it if
# absent but do NOT touch IOMMU, kernel modules, or ownership —
# out of scope.

set -euo pipefail

readonly TARGET_PAGES=512
readonly NR_PATH='/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
readonly FREE_PATH='/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages'
readonly MOUNT_POINT='/dev/hugepages'

if [[ ! -r "$NR_PATH" ]]; then
  echo "dev_hugepages.sh: $NR_PATH missing — is this a Linux host with 2MB huge pages?" >&2
  exit 1
fi

current_total=$(cat "$NR_PATH")
current_free=$(cat "$FREE_PATH" 2>/dev/null || echo 0)

echo "dev_hugepages.sh: current state -> total=$current_total free=$current_free (target=$TARGET_PAGES × 2MB)"

if [[ "$current_total" -ge "$TARGET_PAGES" ]]; then
  echo "dev_hugepages.sh: already at or above target ($current_total >= $TARGET_PAGES), no allocation needed"
else
  echo "dev_hugepages.sh: allocating $TARGET_PAGES × 2MB pages via $NR_PATH"
  echo "$TARGET_PAGES" | sudo tee "$NR_PATH" > /dev/null
  new_total=$(cat "$NR_PATH")
  if [[ "$new_total" -lt "$TARGET_PAGES" ]]; then
    echo "dev_hugepages.sh: kernel only granted $new_total / $TARGET_PAGES pages" >&2
    echo "dev_hugepages.sh: likely memory fragmentation; reboot the VM and retry" >&2
    exit 1
  fi
  echo "dev_hugepages.sh: allocation OK (total=$new_total)"
fi

# Mount /dev/hugepages if absent. DPDK's default 2MB mount point.
if mountpoint -q "$MOUNT_POINT"; then
  echo "dev_hugepages.sh: $MOUNT_POINT already mounted"
else
  echo "dev_hugepages.sh: mounting hugetlbfs at $MOUNT_POINT"
  sudo mkdir -p "$MOUNT_POINT"
  sudo mount -t hugetlbfs -o pagesize=2M none "$MOUNT_POINT"
fi

final_total=$(cat "$NR_PATH")
final_free=$(cat "$FREE_PATH" 2>/dev/null || echo 0)

echo "dev_hugepages.sh: final state -> total=$final_total free=$final_free mount=$MOUNT_POINT"
echo "dev_hugepages.sh: OK"
