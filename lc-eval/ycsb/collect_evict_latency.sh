#!/bin/bash
# Collect raw per-call eviction-decision latency samples for every policy.
#
# Each instrumented evict_folios emits one "evict_lat_ns=<delta>" bpf_printk
# per invocation; this script captures /sys/kernel/tracing/trace_pipe to a
# per-policy .trace file while a short ycsb_a run (45 s warmup + 120 s timed)
# drives eviction pressure. One policy attached at a time -> attribution by
# filename. Parse with summarize_evict_latency.py.
set -eu -o pipefail

DB_PATH="${1:-/mydata/leveldb}"
CGROUP_MEMORY="${2:-10G}"

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	exit 1
fi

SCRIPT_PATH=$(realpath "$0")
BASE_DIR=$(realpath "$(dirname "$SCRIPT_PATH")/../../")
MODEL_FILE="/mydata/models-jun-11/ycsb_a/model_weights.json"
OUT_DIR="$BASE_DIR/results/evict_latency"
TRACE_PIPE="/sys/kernel/tracing/trace_pipe"

mkdir -p "$OUT_DIR"
sudo rm -f /tmp/loader.log

# Optional: ONLY="ml20 ml30" ./collect_evict_latency.sh  -> run a subset.
ONLY="${ONLY:-}"

stop_trace_cat() {
	# Anchored: trace_pipe is single-reader and a stale cat black-holes all
	# samples; -f with a loose pattern would match our own cmdline.
	sudo pkill -f '^cat /sys/kernel/tracing/trace_pipe$' 2>/dev/null || true
}

cleanup() {
	stop_trace_cat
	echo "==> Restoring MGLRU..."
	"$BASE_DIR/utils/enable-mglru.sh" || true
	echo "lru_gen enabled now: $(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null)"
}
trap cleanup EXIT

echo "==> Disabling MGLRU..."
"$BASE_DIR/utils/disable-mglru.sh"

run_config() { # run_config <tag> <loader> [extra bench args...]
	local TAG="$1" LOADER="$2"
	shift 2
	if [ -n "$ONLY" ] && ! echo " $ONLY " | grep -q " $TAG "; then
		echo "==> [$TAG] skipped (not in ONLY)"
		return 0
	fi
	echo "==> [$TAG] $LOADER"
	stop_trace_cat
	sudo sh -c "echo > /sys/kernel/tracing/trace"
	sudo sh -c "exec cat $TRACE_PIPE > $OUT_DIR/$TAG.trace" &
	sleep 1
	if ! sudo pgrep -f '^cat /sys/kernel/tracing/trace_pipe$' > /dev/null; then
		echo "ERROR: trace_pipe reader failed to start (busy?)" >&2
		exit 1
	fi
	# Per-tag results file: sample_size is not in the bench config dict, so a
	# shared file would checkpoint-skip every factor after the first.
	python3 "$BASE_DIR/lc-bench/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$BASE_DIR/policies/$LOADER" \
		--results-file "$OUT_DIR/bench_results_$TAG.json" \
		--leveldb-db "$DB_PATH" \
		--bench-binary-dir "$BASE_DIR/My-YCSB/build" \
		--fadvise-hints "" \
		--iterations 1 \
		--cgroup-memory "$CGROUP_MEMORY" \
		--cache-ext-only \
		--runtime-seconds 120 \
		--benchmark ycsb_a \
		"$@"
	stop_trace_cat
	local N
	N=$(grep -c 'evict_lat_ns=' "$OUT_DIR/$TAG.trace" 2>/dev/null || echo 0)
	echo "==> [$TAG] captured $N eviction samples"
	if [ "$N" -eq 0 ]; then
		echo "WARNING: [$TAG] zero samples captured!" >&2
	fi
}

run_config mru       cache_ext_mru.out
run_config fifo      cache_ext_fifo.out
run_config s3fifo    cache_ext_s3fifo.out
run_config lhd       cache_ext_lhd.out
run_config sampling  cache_ext_sampling.out
for F in 10 20 30 40; do
	run_config "ml$F" cache_ext_ml_sampling.out \
		--model-file "$MODEL_FILE" \
		--policy-extra-args "--sample_size $F"
done
run_config mlprotect cache_ext_fifo_ml_protect.out --model-file "$MODEL_FILE"

echo "==> Done. Summarize with: python3 lc-eval/ycsb/summarize_evict_latency.py"
