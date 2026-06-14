#!/bin/bash
# Twitter-trace evaluation of the heuristic (no-model) policies: the upstream
# cache_ext baselines plus the two Linux kernel-reclaim baselines.
#
# This script needs NO model directory -- the model policies (ml_protect and the
# ml_sampling sweep) live entirely in run_ml_sampling_eval.sh. Splitting along
# "needs a model or not" keeps each script's inputs honest. Twitter counterpart
# of lc-eval/ycsb/run_model_eval.sh, heuristic half:
#   - 5 classical cache_ext policies (mru, fifo, s3fifo, lhd, sampling). fifo_lc
#     (now collect_traces.sh's job) and the BPF-mglru reimpl (not in the figure)
#     are dropped.
#   - per-cluster DBs (leveldb_twitter_cluster<N>_db), so we loop clusters; the
#     cluster is in the bench config dict, so all clusters share one file per
#     pass (twitter_eval_*.json), exactly like the ycsb files hold all workloads.
#   - cgroup sized per cluster from cgroup_sizes.sh (size-pct of the DB + floor),
#     not a fixed --cgroup-memory. That shared table is also used by
#     run_ml_sampling_eval.sh, so the heuristic/model comparison is at the same
#     memory size.
#   - My-YCSB built from the leveldb-latency branch (per-op latency disabled --
#     the arrays would dwarf the tiny 70-470 MiB cgroups), so results are
#     throughput-only.
#
# Results: results/twitter_eval_results.json  (5 classical cache_ext policies)
#          results/twitter_eval_lru.json       (Linux-LRU baseline, MGLRU off)
#          results/twitter_eval_mglru.json     (kernel-MGLRU baseline, MGLRU on)
# MGLRU is disabled during the cache_ext + Linux-LRU runs and ALWAYS restored to
# enabled on exit (machine default).
set -eu -o pipefail

usage() {
	echo "Usage: $0 [--clusters \"17 18 24 34 52\"] [--iterations <n>] [--resume]"
	echo ""
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --iterations       iterations per policy/cluster (default: 1)"
	echo "  --resume           allow existing results files (completed configs checkpoint-skip)"
	echo ""
	echo "Per-cluster cgroup sizing (size-pct + floor-mib) lives in cgroup_sizes.sh,"
	echo "shared with collect_traces.sh and run_ml_sampling_eval.sh for parity."
	echo ""
	echo "Expects /mydata/leveldb_twitter_cluster<N>_db and /mydata/twitter-traces"
	echo "(see download_twitter_dbs.sh). No model directory required -- the model"
	echo "policies live in run_ml_sampling_eval.sh."
	exit 1
}

CLUSTERS="17 18 24 34 52"
ITERATIONS=1
RESUME=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--clusters)   CLUSTERS="$2";  shift 2 ;;
		--iterations) ITERATIONS="$2"; shift 2 ;;
		--resume)     RESUME=1;        shift   ;;
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

# Per-cluster cgroup sizing (shared with collect_traces.sh + run_ml_sampling_eval.sh).
source "$(dirname "$SCRIPT_PATH")/cgroup_sizes.sh"

RES="$RESULTS_PATH/twitter_eval_results.json"
RES_LRU="$RESULTS_PATH/twitter_eval_lru.json"
RES_MGLRU="$RESULTS_PATH/twitter_eval_mglru.json"

# Baseline cache_ext policies, in reference-figure order (matches the ycsb
# script). cache_ext_sampling is the figure's "LFU (cache_ext)". fifo_lc (now
# collect_traces.sh's job) and the BPF mglru reimpl (not in the figure) are
# dropped.
POLICIES=(
	"cache_ext_mru"
	"cache_ext_fifo"
	"cache_ext_s3fifo"
	"cache_ext_lhd"
	"cache_ext_sampling"
)

# Cluster DBs present?
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

# Build My-YCSB on the leveldb-latency branch (throughput-only). Rebuild only
# when the checkout has to change; -f discards the in-tree config YAML edits the
# harness makes at runtime.
if [ "$(cd "$YCSB_PATH" && git rev-parse --abbrev-ref HEAD)" != "leveldb-latency" ]; then
	echo "==> Switching My-YCSB to leveldb-latency branch and rebuilding..."
	(cd "$YCSB_PATH" && git checkout -f leveldb-latency)
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

run_one() { # run_one <policy> <cluster> <results_file> [extra args...]
	local POLICY="$1" CLUSTER="$2" RESULTS="$3"
	shift 3
	local SIZE_PCT FLOOR_MIB
	read -r SIZE_PCT FLOOR_MIB <<< "${CGROUP_BY_CLUSTER[$CLUSTER]}"
	python3 "$BENCH_PATH/bench_twitter_trace.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RESULTS" \
		--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--twitter-traces-dir "$DB_DIRS/twitter-traces" \
		--iterations "$ITERATIONS" \
		--cgroup-size-pct "$SIZE_PCT" \
		--cgroup-floor-mib "$FLOOR_MIB" \
		--benchmark "twitter_cluster${CLUSTER}_bench" \
		"$@"
}

# Classical cache_ext policies, cgroup only (--cache-ext-only); the kernel-reclaim
# baselines are separate --default-only passes below, so we don't re-run a
# baseline once per policy.
for POLICY in "${POLICIES[@]}"; do
	for CLUSTER in $CLUSTERS; do
		echo "==> [cluster $CLUSTER] policy: $POLICY"
		run_one "$POLICY" "$CLUSTER" "$RES" --cache-ext-only
	done
done

# baseline_pass <results_file> -- plain-Linux (--default-only) runs, one per
# cluster, all appended to one file. The Linux-LRU and MGLRU passes have
# IDENTICAL config dicts (the MGLRU on/off state isn't in the dict), so they
# MUST go to separate files or they checkpoint-collide.
baseline_pass() {
	local RESULTS="$1"
	for CLUSTER in $CLUSTERS; do
		echo "==> [cluster $CLUSTER] baseline (--default-only)"
		run_one "cache_ext_fifo" "$CLUSTER" "$RESULTS" --default-only
	done
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
