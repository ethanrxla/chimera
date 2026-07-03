#!/usr/bin/env bash
set -euo pipefail

SHADOWED_TOOLS=(
  qemu-system-x86_64
  qemu-img
  qemu-io
  qemu-nbd
  qemu-storage-daemon
  qemu-pr-helper
)

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

missing=0
for tool in qemu-system-x86_64 qemu-img; do
  if [[ ! -x "/usr/bin/$tool" ]]; then
    echo "Missing packaged QEMU tool: /usr/bin/$tool" >&2
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo "Install missing packages with: sudo apt install qemu-system-x86 qemu-utils" >&2
  exit 1
fi

for tool in "${SHADOWED_TOOLS[@]}"; do
  shadow="/usr/local/bin/$tool"
  backup="/usr/local/bin/$tool.disabled-for-libvirt"

  if [[ -e "$shadow" && ! -e "$backup" ]]; then
    mv "$shadow" "$backup"
    echo "Moved $shadow to $backup"
  elif [[ -e "$shadow" && -e "$backup" ]]; then
    echo "Both $shadow and $backup exist; refusing to overwrite backup." >&2
    exit 1
  else
    echo "No shadow QEMU tool found at $shadow"
  fi
done

systemctl restart libvirtd

echo
echo "Checking x86_64/Q35 KVM capabilities..."
virsh -c qemu:///system domcapabilities --virttype kvm --arch x86_64 --machine q35 >/dev/null
echo "OK: libvirt can use x86_64 KVM with q35."
