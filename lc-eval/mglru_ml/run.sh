#!/bin/bash
# MGLRU-LC tracer collection script
set -eu -o pipefail

# Check for workload  + model file argument
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "Usage: $0 <workload_file> <model_file> [cgroup_memory]"
	echo "Example: $0 /path/to/workload.f /path/to/model.json 1G"
	echo "  cgroup_memory: Optional memory limit (e.g., 512M, 1G, 2G). Default: 1G"
	exit 1
fi

WORKLOAD_FILE="$1"

if [ ! -f "$WORKLOAD_FILE" ]; then
	echo "Error: Workload file not found: $WORKLOAD_FILE"
	exit 1
fi

MODEL_FILE="$2"
if [ ! -f "$MODEL_FILE" ]; then
	echo "Error: Model file not found: $MODEL_FILE"
	exit 1
fi

# Optional cgroup memory parameter (default: 1G)
CGROUP_MEMORY="${3:-1G}"

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
echo "Running mglru_ml with workload: $WORKLOAD_FILE model: $MODEL_FILE memory: $CGROUP_MEMORY"
python3 "$BENCH_PATH/bench_mglru_ml.py" \
	--cpu 4 \
	--policy-loader "$POLICY_PATH/cache_ext_mglru_ml.out" \
	--results-file "$RESULTS_PATH/mglru_lc_results.json" \
	--model-file "$MODEL_FILE" \
	--watch-dir "$WATCH_DIR" \
	--filebench-workload "$WORKLOAD_FILE" \
	--iterations "$ITERATIONS" \
	--cgroup-memory "$CGROUP_MEMORY" \
	--ext-only

echo "MGLRU-LC trace collection completed."
echo "Results saved to $RESULTS_PATH/mglru_lc_results.json"

echo "Cleaning up cache_ext processes..."
ps aux | grep "sudo.*cache_ext.*\.out" | grep -v grep | awk '{print $2}' | while read pid; do
	echo "  Killing process $pid"
	sudo kill -15 "$pid" 2>/dev/null || true
done
echo "Cleanup complete."
