#!/bin/bash
# Automated getting-started setup for LearnedCache.
# Run this script from the repo root. It detects whether you are on the
# cache-ext kernel and either installs the kernel + reboots (phase 1) or
# runs the remaining install steps (phase 2).
set -eu -o pipefail

SCRIPT_PATH=$(realpath "$0")
BASE_DIR=$(dirname "$SCRIPT_PATH")
cd "$BASE_DIR"

# --- Phase 2: already on the cache-ext kernel ---
if uname -r | grep -q "cache-ext"; then
    echo "==> Detected cache-ext kernel. Running post-reboot setup..."

    # Self-cleanup: remove any @reboot cron entry that references this script.
    if crontab -l 2>/dev/null | grep -F "$SCRIPT_PATH" > /dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -v -F "$SCRIPT_PATH" | crontab -
        echo "Removed @reboot cron entry."
    fi

    echo "==> Installing misc packages..."
    ./install_misc.sh

    echo "==> Downloading LevelDB database..."
    ./download_dbs.sh

    echo "==> Building LevelDB..."
    ./install_leveldb.sh

    echo "==> Building My-YCSB..."
    ./install_ycsb.sh

    echo "==> Building BPF policies..."
    ./build_policies.sh

    echo ""
    echo "Setup complete. Run benchmarks with:"
    echo "  lc-eval/ycsb/run.sh <leveldb_db_path> [--model-file <model.json>] [--cgroup-memory 10G]"
    exit 0
fi

# --- Phase 1: not on cache-ext kernel ---
echo "==> Phase 1: installing cache-ext kernel..."
./install_kernel.sh

# Schedule this script to continue after reboot.
(crontab -l 2>/dev/null || true; echo "@reboot $SCRIPT_PATH") | crontab -
echo "Scheduled @reboot cron job to continue setup after reboot."

echo "==> Rebooting into cache-ext kernel..."
sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.6.8-cache-ext+"
sudo reboot now
