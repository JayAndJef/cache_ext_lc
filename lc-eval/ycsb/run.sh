#!/bin/bash
# YCSB+LevelDB benchmark: runs all cache_ext policies plus LC tracer and (optionally) ML policy
set -eu -o pipefail

usage() {
	echo "Usage: $0 <leveldb_db_path> [--model-file <path>] [--cgroup-memory <size>]"
	echo ""
	echo "  leveldb_db_path   path to the original (read-only) LevelDB database"
	echo "  --model-file      path to model weights JSON; required to include cache_ext_fifo_ml"
	echo "  --cgroup-memory   memory limit for cgroup (e.g. 4G, 10G). Default: 10G"
	echo ""
	echo "Example (tracer only):  $0 /mydata/leveldb"
	echo "Example (with ML):      $0 /mydata/leveldb --model-file model.json --cgroup-memory 10G"
	exit 1
}

if [ "$#" -lt 1 ]; then usage; fi

DB_PATH="$1"
shift

MODEL_FILE=""
CGROUP_MEMORY="10G"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-file)
			MODEL_FILE="$2"
			shift 2
			;;
		--cgroup-memory)
			CGROUP_MEMORY="$2"
			shift 2
			;;
		*)
			echo "Unknown argument: $1"
			usage
			;;
	esac
done

if [ ! -d "$DB_PATH" ]; then
	echo "Error: LevelDB database directory not found: $DB_PATH"
	exit 1
fi

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
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3
BENCHMARKS="ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f,uniform,uniform_read_write"

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
	POLICIES+=("cache_ext_fifo_ml")
fi

mkdir -p "$RESULTS_PATH"

# Build My-YCSB
cd "$YCSB_PATH/build"
git checkout master
make clean
make -j run_leveldb
cd -

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

for POLICY in "${POLICIES[@]}"; do
	echo "Running policy: ${POLICY}"

	POLICY_ARGS=()
	if [ "$POLICY" = "cache_ext_fifo_ml" ]; then
		POLICY_ARGS=("--model-file" "$MODEL_FILE")
	fi

	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RESULTS_PATH/ycsb_results.json" \
		--leveldb-db "$DB_PATH" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--cgroup-memory "$CGROUP_MEMORY" \
		--benchmark "$BENCHMARKS" \
		"${POLICY_ARGS[@]}"
done

# Enable MGLRU for baseline comparison
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

echo "Running baseline MGLRU"
python3 "$BENCH_PATH/bench_leveldb.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_fifo_lc.out" \
	--results-file "$RESULTS_PATH/ycsb_results_mglru.json" \
	--leveldb-db "$DB_PATH" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--fadvise-hints "" \
	--iterations "$ITERATIONS" \
	--cgroup-memory "$CGROUP_MEMORY" \
	--benchmark "$BENCHMARKS" \
	--default-only

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "YCSB benchmark completed. Results saved to $RESULTS_PATH."
