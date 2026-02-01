#!/bin/bash
# MGLRU-LC tracer collection script
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/lc-bench"
POLICY_PATH="$BASE_DIR/policies"
WATCH_DIR=$(realpath "$BASE_DIR/linux")
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and cache_ext with mglru_lc
echo "Running mglru_lc benchmark..."
python3 "$BENCH_PATH/bench_mglru_lc.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_mglru_lc.out" \
	--results-file "$RESULTS_PATH/mglru_lc_results.json" \
	--watch-dir "$WATCH_DIR" \
	--iterations "$ITERATIONS"

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# MGLRU baseline
# TODO: Remove --policy-loader requirement when using --default-only
echo "Running baseline MGLRU..."
python3 "$BENCH_PATH/bench_mglru_lc.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_mglru_lc.out" \
	--results-file "$RESULTS_PATH/mglru_lc_results_mglru.json" \
	--watch-dir "$WATCH_DIR" \
	--iterations "$ITERATIONS" \
	--default-only

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "MGLRU-LC benchmark completed. Results saved to $RESULTS_PATH."
