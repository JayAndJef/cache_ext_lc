#!/bin/bash
# Evaluate cache_ext_ml_sampling (sampled model-ranked eviction) on all 6 YCSB
# workloads with matched per-workload models, appending to the same results
# file as the main eval (different policy_loader name -> no checkpoint
# collision). Archives each run's loader.log for attach evidence.
set -eu -o pipefail

DB_PATH="${1:-/mydata/leveldb}"
CGROUP_MEMORY="${2:-10G}"
# Optional: separate results file + loader-log suffix per sample size (the
# bench config dicts don't record it, so different factors must live in
# different files or they checkpoint-collide).
RES_OVERRIDE="${3:-}"
LOG_SUFFIX="${4:-}"
# Optional oversampling factor, forwarded to the loader (--sample_size).
SAMPLE_SIZE="${5:-}"

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	exit 1
fi

SCRIPT_PATH=$(realpath "$0")
BASE_DIR=$(realpath "$(dirname "$SCRIPT_PATH")/../../")
MODEL_DIR="/mydata/models-jun-11"
RES="${RES_OVERRIDE:-$BASE_DIR/results/ycsb_eval_results.json}"
LOADER_LOG_DIR="$BASE_DIR/results/loader_logs"

mkdir -p "$LOADER_LOG_DIR"
sudo rm -f /tmp/loader.log

restore_mglru() {
	echo "==> Restoring MGLRU..."
	"$BASE_DIR/utils/enable-mglru.sh" || true
	echo "lru_gen enabled now: $(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null)"
}
trap restore_mglru EXIT

echo "==> Disabling MGLRU..."
"$BASE_DIR/utils/disable-mglru.sh"
echo "lru_gen enabled now: $(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null)"

EXTRA_ARGS=()
if [ -n "$SAMPLE_SIZE" ]; then
	EXTRA_ARGS=(--policy-extra-args "--sample_size $SAMPLE_SIZE")
fi

for W in a b c d e f; do
	echo "==> [ycsb_$W] policy: cache_ext_ml_sampling (model: ycsb_$W, sample_size: ${SAMPLE_SIZE:-default})"
	python3 "$BASE_DIR/lc-bench/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$BASE_DIR/policies/cache_ext_ml_sampling.out" \
		--results-file "$RES" \
		--leveldb-db "$DB_PATH" \
		--bench-binary-dir "$BASE_DIR/My-YCSB/build" \
		--fadvise-hints "" \
		--iterations 1 \
		--cgroup-memory "$CGROUP_MEMORY" \
		--cache-ext-only \
		--benchmark "ycsb_$W" \
		--model-file "$MODEL_DIR/ycsb_$W/model_weights.json" \
		"${EXTRA_ARGS[@]}"
	cp /tmp/loader.log "$LOADER_LOG_DIR/ml_sampling${LOG_SUFFIX}_ycsb_$W.log" 2>/dev/null || true
done

echo "==> ml_sampling eval complete."
