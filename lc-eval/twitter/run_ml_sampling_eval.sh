#!/bin/bash
# Evaluate cache_ext_ml_sampling (sampled model-ranked eviction) on the Twitter
# clusters with matched per-cluster models, for ONE oversampling factor.
# Twitter counterpart of lc-eval/ycsb/run_ml_sampling_eval.sh.
#
# PREFER reproduce_eval.sh as the entrypoint: the oversampling factor is NOT in
# the bench config dict, so each factor must go to its own results file or they
# checkpoint-collide. reproduce_eval.sh derives the file from the factor in a
# single loop so they can't drift. Standalone, this script defaults the results
# file to twitter_eval_ml<F>.json (derived from --sample-size) for the same
# reason; pass --results-file only to override.
#
# Differences from the ycsb script: loops clusters (per-cluster DB + matched
# model) not workloads, sizes the cgroup at --cgroup-size-pct of each DB instead
# of a fixed --cgroup-memory, and builds My-YCSB's leveldb-latency branch
# (throughput-only). MGLRU is disabled for the duration and ALWAYS restored.
set -eu -o pipefail

usage() {
	echo "Usage: $0 --sample-size <F> [--results-file <path>] [--log-suffix <s>] \\"
	echo "          [--model-dir <dir>] [--clusters \"17 18 24 34 52\"] [--iterations <n>] [--cgroup-size-pct <n>]"
	echo ""
	echo "  --sample-size      oversampling factor forwarded to the loader (--sample_size); required"
	echo "  --results-file     results JSON (default: results/twitter_eval_ml<F>.json)"
	echo "  --log-suffix       suffix for the archived per-cluster loader.log (default: _<F>)"
	echo "  --model-dir        dir with twitter_cluster<N>_bench/model_weights.json (default: /mydata/models-jun-11)"
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --iterations       iterations per cluster (default: 3)"
	echo "  --cgroup-size-pct  cgroup memory as percent of cluster DB size (default: 10)"
	exit 1
}

MODEL_DIR="${MODEL_DIR:-/mydata/models-jun-11}"
CLUSTERS="17 18 24 34 52"
ITERATIONS=3
CGROUP_SIZE_PCT=10
SAMPLE_SIZE=""
RES_OVERRIDE=""
LOG_SUFFIX=""

while [ "$#" -gt 0 ]; do
	case "$1" in
		--sample-size)     SAMPLE_SIZE="$2";     shift 2 ;;
		--results-file)    RES_OVERRIDE="$2";    shift 2 ;;
		--log-suffix)      LOG_SUFFIX="$2";      shift 2 ;;
		--model-dir)       MODEL_DIR="$2";       shift 2 ;;
		--clusters)        CLUSTERS="$2";        shift 2 ;;
		--iterations)      ITERATIONS="$2";      shift 2 ;;
		--cgroup-size-pct) CGROUP_SIZE_PCT="$2"; shift 2 ;;
		*) echo "Unknown argument: $1"; usage ;;
	esac
done

if [ -z "$SAMPLE_SIZE" ]; then
	echo "Error: --sample-size is required."
	usage
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
DB_DIRS=$(realpath "$BASE_DIR/../")
RESULTS_PATH="$BASE_DIR/results"

RES="${RES_OVERRIDE:-$RESULTS_PATH/twitter_eval_ml${SAMPLE_SIZE}.json}"
LOG_SUFFIX="${LOG_SUFFIX:-_$SAMPLE_SIZE}"
LOADER_LOG_DIR="$RESULTS_PATH/loader_logs"

# Cluster DBs + matched models present?
for CLUSTER in $CLUSTERS; do
	if [ ! -d "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" ]; then
		echo "Error: cluster $CLUSTER database not found at $DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db"
		echo "Run ./download_twitter_dbs.sh first."
		exit 1
	fi
	if [ ! -f "$MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json" ]; then
		echo "Error: missing model $MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json"
		exit 1
	fi
done

mkdir -p "$RESULTS_PATH" "$LOADER_LOG_DIR"
sudo rm -f /tmp/loader.log

# Build My-YCSB on the leveldb-latency branch (throughput-only). Rebuild only
# when the checkout has to change; reproduce_eval.sh already does this, so this
# is a no-op when invoked through it.
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

echo "==> Disabling MGLRU..."
"$BASE_DIR/utils/disable-mglru.sh"
echo "lru_gen enabled now: $(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null)"

for CLUSTER in $CLUSTERS; do
	echo "==> [cluster $CLUSTER] cache_ext_ml_sampling (model: twitter_cluster${CLUSTER}_bench, sample_size: $SAMPLE_SIZE)"
	python3 "$BENCH_PATH/bench_twitter_trace.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/cache_ext_ml_sampling.out" \
		--results-file "$RES" \
		--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--twitter-traces-dir "$DB_DIRS/twitter-traces" \
		--iterations "$ITERATIONS" \
		--cgroup-size-pct "$CGROUP_SIZE_PCT" \
		--cache-ext-only \
		--benchmark "twitter_cluster${CLUSTER}_bench" \
		--model-file "$MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json" \
		--policy-extra-args "--sample_size $SAMPLE_SIZE"
	cp /tmp/loader.log "$LOADER_LOG_DIR/ml_sampling${LOG_SUFFIX}_twitter_cluster${CLUSTER}.log" 2>/dev/null || true
done

echo "==> ml_sampling eval complete (factor ${SAMPLE_SIZE}x). Results: $RES"
