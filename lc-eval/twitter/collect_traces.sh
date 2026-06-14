#!/bin/bash
# Twitter-trace tracer data collection.
#
# Runs ONLY the cache_ext_fifo_lc tracer (the policy that emits training logs),
# skipping the no-trace baseline pass via --cache-ext-only. This is the lean
# counterpart to the benchmarking scripts (run_heuristic_eval.sh +
# run_ml_sampling_eval.sh), which run the full multi-policy evaluation sweep.
# Twitter counterpart of lc-eval/ycsb/collect_traces.sh.
#
# MGLRU is disabled for the duration (the cache_ext eviction log stays empty
# while MGLRU is enabled) and ALWAYS restored on exit. Binary trace logs land in
# /mydata/cache_ext_logs/twitter_cluster<N>_bench/iter_<N>/.
set -eu -o pipefail

usage() {
	echo "Usage: $0 [--clusters \"17 18 24 34 52\"] [--iterations <n>]"
	echo ""
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --iterations       iterations per cluster (default: 1)"
	echo ""
	echo "Per-cluster cgroup sizing (size-pct + floor-mib) lives in cgroup_sizes.sh,"
	echo "shared with run_heuristic_eval.sh and run_ml_sampling_eval.sh so the training"
	echo "data sees the SAME memory pressure as the eval (train/serve parity). Lower a"
	echo "small cluster's floor there (e.g. 18, whose DB is ~151 MiB) so it actually"
	echo "evicts instead of caching its whole DB."
	echo ""
	echo "Expects /mydata/leveldb_twitter_cluster<N>_db and /mydata/twitter-traces"
	echo "(see download_twitter_dbs.sh)."
	exit 1
}

CLUSTERS="17 18 24 34 52"
ITERATIONS=1

while [ "$#" -gt 0 ]; do
	case "$1" in
		--clusters)   CLUSTERS="$2";   shift 2 ;;
		--iterations) ITERATIONS="$2"; shift 2 ;;
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

# Per-cluster cgroup sizing (shared with run_heuristic_eval.sh + run_ml_sampling_eval.sh).
source "$(dirname "$SCRIPT_PATH")/cgroup_sizes.sh"

for CLUSTER in $CLUSTERS; do
	if [ ! -d "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" ]; then
		echo "Error: cluster $CLUSTER database not found at $DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db"
		echo "Run ./download_twitter_dbs.sh first."
		exit 1
	fi
done

# Every requested cluster must have a cgroup-sizing entry (fail before setup).
require_cluster_cgroups $CLUSTERS

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
	read -r SIZE_PCT FLOOR_MIB <<< "${CGROUP_BY_CLUSTER[$CLUSTER]}"
	python3 "$BENCH_PATH/bench_twitter_trace.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/cache_ext_fifo_lc.out" \
		--results-file "$RESULTS_PATH/twitter_results_tracer.json" \
		--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--twitter-traces-dir "$DB_DIRS/twitter-traces" \
		--iterations "$ITERATIONS" \
		--cgroup-size-pct "$SIZE_PCT" \
		--cgroup-floor-mib "$FLOOR_MIB" \
		--cache-ext-only \
		--benchmark "twitter_cluster${CLUSTER}_bench"
done

echo "==> Tracer collection complete. Log sizes:"
du -sh /mydata/cache_ext_logs/* 2>/dev/null
