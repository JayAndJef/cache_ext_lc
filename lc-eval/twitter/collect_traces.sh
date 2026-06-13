#!/bin/bash
# Twitter-trace tracer data collection.
#
# Runs ONLY the cache_ext_fifo_lc tracer (the policy that emits training logs),
# skipping the no-trace baseline pass via --cache-ext-only. This is the lean
# counterpart to run.sh, which runs the full multi-policy evaluation sweep.
# Twitter counterpart of lc-eval/ycsb/collect_traces.sh.
#
# MGLRU is disabled for the duration (the cache_ext eviction log stays empty
# while MGLRU is enabled) and ALWAYS restored on exit. Binary trace logs land in
# /mydata/cache_ext_logs/twitter_cluster<N>_bench/iter_<N>/ — parse with
# policies/read_binary_logs.py.
set -eu -o pipefail

usage() {
	echo "Usage: $0 [--clusters \"17 18 24 34 52\"] [--iterations <n>] [--cgroup-size-pct <n>]"
	echo ""
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --iterations       iterations per cluster (default: 1)"
	echo "  --cgroup-size-pct  cgroup memory as percent of cluster DB size (default: 10,"
	echo "                     matching the eval setup so training data sees the same pressure)"
	echo ""
	echo "Expects /mydata/leveldb_twitter_cluster<N>_db and /mydata/twitter-traces"
	echo "(see download_twitter_dbs.sh)."
	exit 1
}

CLUSTERS="17 18 24 34 52"
ITERATIONS=1
CGROUP_SIZE_PCT=10

while [ "$#" -gt 0 ]; do
	case "$1" in
		--clusters)        CLUSTERS="$2";        shift 2 ;;
		--iterations)      ITERATIONS="$2";      shift 2 ;;
		--cgroup-size-pct) CGROUP_SIZE_PCT="$2"; shift 2 ;;
		*) echo "Unknown argument: $1"; usage ;;
	esac
done

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
DB_DIRS=$(realpath "$BASE_DIR/../")
RESULTS_PATH="$BASE_DIR/results"

for CLUSTER in $CLUSTERS; do
	if [ ! -d "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" ]; then
		echo "Error: cluster $CLUSTER database not found at $DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db"
		echo "Run ./download_twitter_dbs.sh first."
		exit 1
	fi
done

mkdir -p "$RESULTS_PATH"

# Twitter runs use the leveldb-latency branch of My-YCSB (see run.sh). Rebuild
# only when the checkout has to change; -f discards the in-tree config YAML
# edits the harness makes at runtime.
if [ "$(cd "$YCSB_PATH" && git rev-parse --abbrev-ref HEAD)" != "leveldb-latency" ]; then
	echo "==> Switching My-YCSB to leveldb-latency branch and rebuilding..."
	(cd "$YCSB_PATH" && git checkout -f leveldb-latency)
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

for CLUSTER in $CLUSTERS; do
	echo "==> Collecting traces for cluster ${CLUSTER} ($ITERATIONS iteration(s))"
	python3 "$BENCH_PATH/bench_twitter_trace.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/cache_ext_fifo_lc.out" \
		--results-file "$RESULTS_PATH/twitter_results_${CLUSTER}_tracer.json" \
		--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--twitter-traces-dir "$DB_DIRS/twitter-traces" \
		--iterations "$ITERATIONS" \
		--cgroup-size-pct "$CGROUP_SIZE_PCT" \
		--cache-ext-only \
		--benchmark "twitter_cluster${CLUSTER}_bench"
done

echo "==> Tracer collection complete. Log sizes:"
du -sh /mydata/cache_ext_logs/* 2>/dev/null
echo "Parse with: policies/read_binary_logs.py"
