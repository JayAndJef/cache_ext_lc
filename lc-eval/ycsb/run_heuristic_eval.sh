#!/bin/bash
# YCSB+LevelDB evaluation of the heuristic (no-model) policies: the upstream
# cache_ext baselines plus the two Linux kernel-reclaim baselines.
#
# This script needs NO model directory -- the model policies (ml_protect and the
# ml_sampling sweep) live entirely in run_ml_sampling_eval.sh. Splitting along
# "needs a model or not" keeps each script's inputs honest. Mirrors the Twitter
# counterpart lc-eval/twitter/run_heuristic_eval.sh, minus the per-cluster cgroup
# sizing (ycsb uses a fixed 10G):
#   - 5 classical cache_ext policies (mru, fifo, s3fifo, lhd, sampling). fifo_lc
#     (now collect_traces.sh's job) and the BPF-mglru reimpl (not in the figure)
#     are dropped.
#   - one DB shared by all 6 workloads, so no model is needed and each policy
#     runs all workloads in a single batched bench call over ALL_BENCHMARKS (the
#     framework still resets DB/cgroup/policy per workload-config).
#   - fixed 10G cgroup (--cgroup-memory), not a per-workload table.
#   - My-YCSB built from the master branch (per-op latency enabled).
#
# Results: results/ycsb_eval_results.json  (5 classical cache_ext policies)
#          results/ycsb_eval_lru.json       (Linux-LRU baseline, MGLRU off)
#          results/ycsb_eval_mglru.json     (kernel-MGLRU baseline, MGLRU on)
# MGLRU is disabled during the cache_ext + Linux-LRU runs and ALWAYS restored to
# enabled on exit (machine default).
set -eu -o pipefail

usage() {
	echo "Usage: $0 <leveldb_db_path> [--iterations <n>] [--resume]"
	echo ""
	echo "  --iterations       iterations per policy/workload (default: 1)"
	echo "  --resume           allow existing results files (completed configs checkpoint-skip)"
	echo ""
	echo "Runs all 6 YCSB workloads against the 5 classical cache_ext policies,"
	echo "then the Linux-LRU and kernel-MGLRU baseline passes. No model directory"
	echo "required -- the model policies live in run_ml_sampling_eval.sh. Usually"
	echo "invoked via reproduce_eval.sh."
	exit 1
}

if [ "$#" -lt 1 ]; then usage; fi

DB_PATH="$1"
shift

ITERATIONS=1
RESUME=0
CGROUP_MEMORY="10G"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--iterations) ITERATIONS="$2"; shift 2 ;;
		--resume)     RESUME=1;        shift   ;;
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

RES="$RESULTS_PATH/ycsb_eval_results.json"
RES_LRU="$RESULTS_PATH/ycsb_eval_lru.json"
RES_MGLRU="$RESULTS_PATH/ycsb_eval_mglru.json"

# Baseline cache_ext policies, in reference-figure order. cache_ext_sampling is
# the figure's "LFU (cache_ext)" (bpf_lfu_score_fn). fifo_lc (tracer-log disk
# blowup, now collect_traces.sh's job) and the BPF mglru reimpl (not in the
# figure) are dropped.
POLICIES=(
	"cache_ext_mru"
	"cache_ext_fifo"
	"cache_ext_s3fifo"
	"cache_ext_lhd"
	"cache_ext_sampling"
)

WORKLOADS=(a b c d e f)
ALL_BENCHMARKS="ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f"

mkdir -p "$RESULTS_PATH"

# Refuse stale results unless resuming: the bench framework silently skips
# configs already present in the results file.
if [ "$RESUME" -eq 0 ]; then
	for f in "$RES" "$RES_LRU" "$RES_MGLRU"; do
		if [ -e "$f" ]; then
			echo "Error: $f already exists. Pass --resume to continue it, or remove it."
			exit 1
		fi
	done
fi

# Stale root-owned loader log breaks the harness's open("w") for new runs.
sudo rm -f /tmp/loader.log

# YCSB runs need the master branch: the twitter scripts leave the submodule on
# leveldb-latency, whose binary silently reports all latencies as zero. -f
# discards the in-tree config YAML edits the harness makes at runtime.
# (reproduce_eval.sh already does this before calling us; harmless no-op then.)
if [ "$(cd "$YCSB_PATH" && git rev-parse --abbrev-ref HEAD)" != "master" ]; then
	echo "==> Switching My-YCSB to master branch and rebuilding..."
	(cd "$YCSB_PATH" && git checkout -f master)
	(cd "$YCSB_PATH/build" && cmake .. && make clean && make -j run_leveldb)
elif [ ! -x "$YCSB_PATH/build/run_leveldb" ]; then
	echo "==> Building My-YCSB run_leveldb..."
	(cd "$YCSB_PATH/build" && cmake .. && make -j run_leveldb)
fi

# Always restore MGLRU (machine default: enabled), even on failure/interrupt.
restore_mglru() {
	echo "==> Restoring MGLRU..."
	"$BASE_DIR/utils/enable-mglru.sh" || true
	echo "lru_gen enabled now: $(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null)"
}
trap restore_mglru EXIT

echo "==> Disabling MGLRU for cache_ext policy runs..."
"$BASE_DIR/utils/disable-mglru.sh"
echo "lru_gen enabled now: $(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null)"

run_policy() { # run_policy <policy> -- all 6 workloads in one batched call
	local POLICY="$1"
	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RES" \
		--leveldb-db "$DB_PATH" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--cgroup-memory "$CGROUP_MEMORY" \
		--cache-ext-only \
		--benchmark "$ALL_BENCHMARKS"
}

# Classical cache_ext policies, cgroup only (--cache-ext-only); the kernel-reclaim
# baselines are separate --default-only passes below, so we don't re-run a
# baseline once per policy. No model needed, so each policy sweeps all 6
# workloads in a single bench call (the matched-model policies, which must wire a
# per-workload --model-file, live in run_ml_sampling_eval.sh).
for POLICY in "${POLICIES[@]}"; do
	echo "==> policy: $POLICY (all workloads)"
	run_policy "$POLICY"
done

# baseline_pass <results_file> -- a plain-Linux (--default-only) run over all
# workloads. The Linux-LRU and MGLRU passes have IDENTICAL config dicts (the
# MGLRU on/off state isn't in the dict), so they MUST go to separate files or
# they checkpoint-collide.
baseline_pass() {
	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/cache_ext_fifo.out" \
		--results-file "$1" \
		--leveldb-db "$DB_PATH" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--cgroup-memory "$CGROUP_MEMORY" \
		--benchmark "$ALL_BENCHMARKS" \
		--default-only
}

# Linux classic active/inactive LRU = plain-Linux baseline with MGLRU still OFF
# (the paper's "Default (Linux)"). Runs while MGLRU is disabled from above.
echo "==> Running Linux-LRU baseline (MGLRU off, --default-only)..."
baseline_pass "$RES_LRU"

echo "==> Running kernel-MGLRU baseline (MGLRU on, --default-only)..."
# Intentional hard stop under set -e: enable-mglru.sh fails if MGLRU didn't
# actually turn on, in which case the MGLRU baseline below would be invalid.
# The EXIT trap still restores MGLRU.
"$BASE_DIR/utils/enable-mglru.sh"
baseline_pass "$RES_MGLRU"

echo ""
echo "==> Heuristic eval complete."
echo "Results: $RES         (5 classical cache_ext policies)"
echo "         $RES_LRU   (Linux-LRU baseline)"
echo "         $RES_MGLRU (kernel-MGLRU baseline)"
echo "(For the model policies + full sweep + manifest, use reproduce_eval.sh.)"
