#!/bin/bash
# YCSB+LevelDB tracer data collection.
#
# Runs ONLY the cache_ext_fifo_lc tracer (the policy that emits training logs),
# skipping the no-trace baseline pass via --cache-ext-only. The multi-policy
# evaluation sweep lives in run_model_eval.sh / run_ml_sampling_eval.sh.
#
# MGLRU is disabled for the duration (the cache_ext eviction log stays empty
# while MGLRU is enabled) and ALWAYS restored on exit. Binary trace logs land in
# /mydata/cache_ext_logs/<benchmark>/iter_<N>/ — parse with
# policies/read_binary_logs.py.
set -eu -o pipefail

usage() {
	echo "Usage: $0 <leveldb_db_path> [--benchmarks <csv>] [--iterations <n>] [--cgroup-memory <size>]"
	echo ""
	echo "  leveldb_db_path   path to the original (read-only) LevelDB database"
	echo "  --benchmarks      comma-separated workloads (default: ycsb_a..f)"
	echo "  --iterations      iterations per workload (default: 1)"
	echo "  --cgroup-memory   memory limit for cgroup (e.g. 4G, 10G). Default: 10G"
	echo ""
	echo "Example:  $0 /mydata/leveldb"
	exit 1
}

if [ "$#" -lt 1 ]; then usage; fi

DB_PATH="$1"
shift

BENCHMARKS="ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f"
ITERATIONS=1
CGROUP_MEMORY="10G"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--benchmarks)   BENCHMARKS="$2";    shift 2 ;;
		--iterations)   ITERATIONS="$2";    shift 2 ;;
		--cgroup-memory) CGROUP_MEMORY="$2"; shift 2 ;;
		*) echo "Unknown argument: $1"; usage ;;
	esac
done

if [ ! -d "$DB_PATH" ]; then
	echo "Error: LevelDB database directory not found: $DB_PATH"
	exit 1
fi

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath "$0")
BASE_DIR=$(realpath "$(dirname "$SCRIPT_PATH")/../../")
BENCH_PATH="$BASE_DIR/lc-bench"
POLICY_PATH="$BASE_DIR/policies"
YCSB_PATH="$BASE_DIR/My-YCSB"
RESULTS_PATH="$BASE_DIR/results"

mkdir -p "$RESULTS_PATH"

# Ensure the LevelDB YCSB driver is built (build only run_leveldb; the other
# backends need uninstalled dev libs and would fail the default `make` target).
# YCSB runs need the master branch: the twitter scripts leave the submodule on
# leveldb-latency, whose binary silently reports all latencies as zero. -f
# discards the in-tree config YAML edits the harness makes at runtime.
if [ "$(cd "$YCSB_PATH" && git rev-parse --abbrev-ref HEAD)" != "master" ]; then
	echo "==> Switching My-YCSB to master branch and rebuilding..."
	(cd "$YCSB_PATH" && git checkout -f master)
	(cd "$YCSB_PATH/build" && cmake .. && make clean && make -j run_leveldb)
elif [ ! -x "$YCSB_PATH/build/run_leveldb" ]; then
	echo "==> Building My-YCSB run_leveldb..."
	(cd "$YCSB_PATH/build" && cmake .. && make -j run_leveldb)
fi

# Always restore MGLRU, even on failure/interrupt.
restore_mglru() {
	echo "==> Restoring MGLRU..."
	"$BASE_DIR/utils/enable-mglru.sh" || true
	echo "lru_gen enabled now: $(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null)"
}
trap restore_mglru EXIT

echo "==> Clearing any prior tracer logs (avoid mixing runs into training data)..."
sudo rm -rf /mydata/cache_ext_logs/*

echo "==> Disabling MGLRU..."
"$BASE_DIR/utils/disable-mglru.sh"
echo "lru_gen enabled now: $(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null)"

echo "==> Collecting traces for: $BENCHMARKS ($ITERATIONS iteration(s))"
python3 "$BENCH_PATH/bench_leveldb.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_fifo_lc.out" \
	--results-file "$RESULTS_PATH/ycsb_results_tracer.json" \
	--leveldb-db "$DB_PATH" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--fadvise-hints "" \
	--iterations "$ITERATIONS" \
	--cgroup-memory "$CGROUP_MEMORY" \
	--cache-ext-only \
	--benchmark "$BENCHMARKS"

echo "==> Tracer collection complete. Log sizes:"
du -sh /mydata/cache_ext_logs/* 2>/dev/null
echo "Parse with: policies/read_binary_logs.py"
