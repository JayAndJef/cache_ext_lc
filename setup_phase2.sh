#!/bin/bash
# LearnedCache setup — Part 2 of 2: post-reboot install steps.
#
# Run this manually after ./setup_phase1.sh has rebooted you into the cache-ext
# kernel. It hard-fails if you are not on that kernel. No cron/automation is
# involved — this is a plain script you invoke yourself.
set -eu -o pipefail

BASE_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$BASE_DIR"

if ! uname -r | grep -q "cache-ext"; then
    echo "ERROR: not running the cache-ext kernel (uname -r = $(uname -r))." >&2
    echo "Run ./setup_phase1.sh first and reboot into the cache-ext kernel," >&2
    echo "then re-run ./setup_phase2.sh." >&2
    exit 1
fi

echo "==> Detected cache-ext kernel ($(uname -r)). Running post-reboot setup..."

echo "==> Installing misc packages..."
./install_misc.sh

echo "==> Downloading LevelDB database..."
./download_dbs.sh

echo "==> Downloading Twitter trace artifacts..."
./download_twitter_dbs.sh

echo "==> Building LevelDB..."
./install_leveldb.sh

echo "==> Building My-YCSB..."
./install_ycsb.sh

echo "==> Building BPF policies..."
./build_policies.sh

echo ""
echo "Setup complete."
echo "Collect tracer training data with:"
echo "  lc-eval/ycsb/collect_traces.sh <leveldb_db_path>"
echo "  lc-eval/twitter/collect_traces.sh"
echo "Run evaluations with (see lc-eval/ycsb/README.md for the full pipeline):"
echo "  lc-eval/ycsb/run_model_eval.sh <leveldb_db_path> --stage 1"
echo "  lc-eval/twitter/run.sh [--model-file <model.json>] [--clusters \"17 18 24 34 52\"]"
