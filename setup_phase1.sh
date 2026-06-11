#!/bin/bash
# LearnedCache setup — Part 1 of 2: install the cache-ext kernel, then reboot.
#
# Run this from the repo root on a fresh machine. It compiles/installs the
# custom cache-ext kernel, selects it for the next boot, and reboots. There is
# NO cron/automation: after the machine comes back up on the cache-ext kernel,
# finish setup by running ./setup_phase2.sh manually.
set -eu -o pipefail

BASE_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$BASE_DIR"

if uname -r | grep -q "cache-ext"; then
    echo "Already running the cache-ext kernel ($(uname -r))."
    echo "Phase 1 (kernel install) is unnecessary — run ./setup_phase2.sh instead."
    exit 0
fi

echo "==> Phase 1: installing cache-ext kernel..."
./install_kernel.sh

echo "==> Selecting cache-ext kernel for next boot..."
sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.6.8-cache-ext+"

echo ""
echo "Kernel installed. The machine will now reboot into the cache-ext kernel."
echo "After it comes back up, finish setup by running:"
echo "  cd $BASE_DIR && ./setup_phase2.sh"
echo ""
sudo reboot now
