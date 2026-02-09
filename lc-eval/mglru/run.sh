#!/bin/bash
# MGLRU-LC tracer collection script
set -eu -o pipefail

# Check for workload file argument
if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <workload_file>"
	echo "Example: $0 /path/to/workload.f"
	exit 1
fi

WORKLOAD_FILE="$1"

if [ ! -f "$WORKLOAD_FILE" ]; then
	echo "Error: Workload file not found: $WORKLOAD_FILE"
	exit 1
fi

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/lc-bench"
POLICY_PATH="$BASE_DIR/policies"
WATCH_DIR="/tmp" # must match filebench workload directory
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=1

mkdir -p "$RESULTS_PATH"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Run mglru_lc with the workload
echo "Running mglru_lc with workload: $WORKLOAD_FILE"
python3 "$BENCH_PATH/bench_mglru_lc.py" \
	--cpu 4 \
	--policy-loader "$POLICY_PATH/cache_ext_mglru_lc.out" \
	--results-file "$RESULTS_PATH/mglru_lc_results.json" \
	--watch-dir "$WATCH_DIR" \
	--filebench-workload "$WORKLOAD_FILE" \
	--iterations "$ITERATIONS" \
	--ext-only

echo "MGLRU-LC trace collection completed."
echo "Results saved to $RESULTS_PATH/mglru_lc_results.json"
echo "Trace data sent to host machine via syslog (192.168.33.1:514)"
