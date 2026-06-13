#!/bin/bash
# Twitter-trace benchmark: runs all cache_ext policies plus LC tracer and
# (optionally) ML policy on the paper's five Twitter cache clusters.
#
# Full multi-policy sweep, structured like the lc-eval/ycsb eval scripts
# (which call bench_leveldb.py per policy). Twitter-specific differences:
#   - per-cluster DBs (leveldb_twitter_cluster<N>_db), so we loop clusters and
#     write one results file per cluster instead of a single shared file
#   - cgroup is sized per cluster at --cgroup-size-pct of the DB (paper: 10%),
#     not a fixed --cgroup-memory
#   - My-YCSB is built from the leveldb-latency branch (latency tracking
#     disabled: the per-op latency arrays would dwarf the tiny 70-470 MiB
#     cgroups), so Twitter results are throughput-only
set -eu -o pipefail

usage() {
	echo "Usage: $0 [--model-file <path>] [--clusters \"17 18 24 34 52\"] [--iterations <n>] [--cgroup-size-pct <n>]"
	echo ""
	echo "  --model-file       path to model weights JSON; required to include cache_ext_fifo_ml_protect"
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --iterations       iterations per policy/cluster (default: 3)"
	echo "  --cgroup-size-pct  cgroup memory as percent of cluster DB size (default: 10)"
	echo ""
	echo "Expects /mydata/leveldb_twitter_cluster<N>_db and /mydata/twitter-traces"
	echo "(see download_twitter_dbs.sh)."
	exit 1
}

MODEL_FILE=""
CLUSTERS="17 18 24 34 52"
ITERATIONS=3
CGROUP_SIZE_PCT=10

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-file)      MODEL_FILE="$2";       shift 2 ;;
		--clusters)        CLUSTERS="$2";         shift 2 ;;
		--iterations)      ITERATIONS="$2";       shift 2 ;;
		--cgroup-size-pct) CGROUP_SIZE_PCT="$2";  shift 2 ;;
		*) echo "Unknown argument: $1"; usage ;;
	esac
done

if [ -n "$MODEL_FILE" ] && [ ! -f "$MODEL_FILE" ]; then
	echo "Error: Model file not found: $MODEL_FILE"
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

POLICIES=(
	"cache_ext_lhd"
	"cache_ext_s3fifo"
	"cache_ext_sampling"
	"cache_ext_fifo"
	"cache_ext_mru"
	"cache_ext_mglru"
	"cache_ext_fifo_lc"
)

if [ -n "$MODEL_FILE" ]; then
	POLICIES+=("cache_ext_fifo_ml_protect")
fi

mkdir -p "$RESULTS_PATH"

# Build My-YCSB on the leveldb-latency branch. -f discards the in-tree config
# YAML edits the harness makes at runtime, which would otherwise block the
# branch switch.
cd "$YCSB_PATH"
git checkout -f leveldb-latency
cd build
make clean
make -j run_leveldb
cd "$BASE_DIR"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

for POLICY in "${POLICIES[@]}"; do
	for CLUSTER in $CLUSTERS; do
		echo "Running policy: ${POLICY} on cluster ${CLUSTER}"

		POLICY_ARGS=()
		if [ "$POLICY" = "cache_ext_fifo_ml_protect" ]; then
			POLICY_ARGS=("--model-file" "$MODEL_FILE")
		fi

		python3 "$BENCH_PATH/bench_twitter_trace.py" \
			--cpu 8 \
			--policy-loader "$POLICY_PATH/${POLICY}.out" \
			--results-file "$RESULTS_PATH/twitter_results_${CLUSTER}.json" \
			--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
			--bench-binary-dir "$YCSB_PATH/build" \
			--twitter-traces-dir "$DB_DIRS/twitter-traces" \
			--iterations "$ITERATIONS" \
			--cgroup-size-pct "$CGROUP_SIZE_PCT" \
			--benchmark "twitter_cluster${CLUSTER}_bench" \
			"${POLICY_ARGS[@]}"
	done
done

# Enable MGLRU for baseline comparison
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

for CLUSTER in $CLUSTERS; do
	echo "Running baseline MGLRU on cluster ${CLUSTER}"
	python3 "$BENCH_PATH/bench_twitter_trace.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/cache_ext_fifo_lc.out" \
		--results-file "$RESULTS_PATH/twitter_results_${CLUSTER}_mglru.json" \
		--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--twitter-traces-dir "$DB_DIRS/twitter-traces" \
		--iterations "$ITERATIONS" \
		--cgroup-size-pct "$CGROUP_SIZE_PCT" \
		--benchmark "twitter_cluster${CLUSTER}_bench" \
		--default-only
done

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "Twitter benchmark completed. Results saved to $RESULTS_PATH."
