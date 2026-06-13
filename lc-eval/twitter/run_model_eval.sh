#!/bin/bash
# Twitter-trace evaluation of cache_ext_fifo_ml_protect (matched model per
# cluster) against the upstream cache_ext baseline policies.
#
# Benchmarking ONLY -- the tracer (cache_ext_fifo_lc) and its training-data
# collection now live entirely in collect_traces.sh, so this script no longer
# doubles as a data-collection pass. Twitter counterpart of
# lc-eval/ycsb/run_model_eval.sh:
#   - 5 classical policies + ml_protect (per-cluster matched model); fifo_lc and
#     the BPF-mglru reimpl are dropped (mirrors the ycsb script).
#   - per-cluster DBs (leveldb_twitter_cluster<N>_db), so we loop clusters; the
#     cluster is in the bench config dict, so all clusters share one file per
#     pass (twitter_eval_*.json), exactly like the ycsb files hold all workloads.
#   - cgroup sized per cluster at --cgroup-size-pct of the DB (paper: 10%), not a
#     fixed --cgroup-memory.
#   - My-YCSB built from the leveldb-latency branch (per-op latency disabled --
#     the arrays would dwarf the tiny 70-470 MiB cgroups), so results are
#     throughput-only.
#
# Results: results/twitter_eval_results.json  (classical policies + ml_protect)
#          results/twitter_eval_lru.json       (Linux-LRU baseline, MGLRU off)
#          results/twitter_eval_mglru.json     (kernel-MGLRU baseline, MGLRU on)
#          results/twitter_eval_meta.json      (cluster<->model mapping)
# MGLRU is disabled during the cache_ext + Linux-LRU runs and ALWAYS restored to
# enabled on exit (machine default).
set -eu -o pipefail

usage() {
	echo "Usage: $0 [--model-dir <dir>] [--clusters \"17 18 24 34 52\"] [--iterations <n>] [--cgroup-size-pct <n>] [--resume]"
	echo ""
	echo "  --model-dir        dir with twitter_cluster<N>_bench/model_weights.json per cluster (default: /mydata/models-jun-11)"
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --iterations       iterations per policy/cluster (default: 3)"
	echo "  --cgroup-size-pct  cgroup memory as percent of cluster DB size (default: 10)"
	echo "  --resume           allow existing results files (completed configs checkpoint-skip)"
	echo ""
	echo "Expects /mydata/leveldb_twitter_cluster<N>_db and /mydata/twitter-traces"
	echo "(see download_twitter_dbs.sh) and a matched model per cluster under --model-dir."
	exit 1
}

# MODEL_DIR honors an exported env var (reproduce_eval.sh sets it) before the
# /mydata default; an explicit --model-dir flag overrides both.
MODEL_DIR="${MODEL_DIR:-/mydata/models-jun-11}"
CLUSTERS="17 18 24 34 52"
ITERATIONS=3
CGROUP_SIZE_PCT=10
RESUME=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-dir)       MODEL_DIR="$2";       shift 2 ;;
		--clusters)        CLUSTERS="$2";         shift 2 ;;
		--iterations)      ITERATIONS="$2";       shift 2 ;;
		--cgroup-size-pct) CGROUP_SIZE_PCT="$2";  shift 2 ;;
		--resume)          RESUME=1;              shift   ;;
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

RES="$RESULTS_PATH/twitter_eval_results.json"
RES_LRU="$RESULTS_PATH/twitter_eval_lru.json"
RES_MGLRU="$RESULTS_PATH/twitter_eval_mglru.json"
META="$RESULTS_PATH/twitter_eval_meta.json"

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

# Matched model present for every cluster? Hard-fail (mirrors the ycsb script):
# train/upload per-cluster models before evaluating ml_protect.
for CLUSTER in $CLUSTERS; do
	if [ ! -f "$MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json" ]; then
		echo "Error: missing model $MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json"
		echo "Collect traces (collect_traces.sh), train a per-cluster model, or pass --model-dir."
		exit 1
	fi
done

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

# Record which model file maps to which cluster: model_file is not part of the
# bench config dicts, so the results JSON alone cannot attribute ml_protect rows.
python3 - "$META" "$MODEL_DIR" "$CGROUP_SIZE_PCT" "$CLUSTERS" <<'EOF'
import json, sys, os, subprocess
out, model_dir, pct, clusters = sys.argv[1:5]
meta = {
    "kernel": subprocess.check_output(["uname", "-r"]).decode().strip(),
    "cgroup_size_pct": int(pct),
    "models": {},
}
for c in clusters.split():
    base = os.path.join(model_dir, f"twitter_cluster{c}_bench")
    entry = {"model_file": os.path.join(base, "model_weights.json")}
    mpath = os.path.join(base, "metrics.json")
    if os.path.exists(mpath):
        with open(mpath) as f:
            entry["metrics"] = json.load(f)
    meta["models"][f"twitter_cluster{c}_bench"] = entry
with open(out, "w") as f:
    json.dump(meta, f, indent=2)
print(f"Wrote {out}")
EOF

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
	python3 "$BENCH_PATH/bench_twitter_trace.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RESULTS" \
		--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--twitter-traces-dir "$DB_DIRS/twitter-traces" \
		--iterations "$ITERATIONS" \
		--cgroup-size-pct "$CGROUP_SIZE_PCT" \
		--benchmark "twitter_cluster${CLUSTER}_bench" \
		"$@"
}

# Classical policies + ml_protect, cache_ext cgroup only (--cache-ext-only); the
# kernel-reclaim baselines are separate --default-only passes below, so we don't
# re-run a baseline once per policy.
for POLICY in "${POLICIES[@]}"; do
	for CLUSTER in $CLUSTERS; do
		echo "==> [cluster $CLUSTER] policy: $POLICY"
		run_one "$POLICY" "$CLUSTER" "$RES" --cache-ext-only
	done
done

for CLUSTER in $CLUSTERS; do
	echo "==> [cluster $CLUSTER] policy: cache_ext_fifo_ml_protect (model: twitter_cluster${CLUSTER}_bench)"
	run_one "cache_ext_fifo_ml_protect" "$CLUSTER" "$RES" \
		--cache-ext-only \
		--model-file "$MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json"
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
echo "==> Classical + ml_protect eval complete."
echo "Results: $RES"
echo "         $RES_LRU   (Linux-LRU baseline)"
echo "         $RES_MGLRU (kernel-MGLRU baseline)"
echo "         $META   (cluster<->model mapping)"
echo "(For the full sweep incl. ML-rank factors + manifest, use reproduce_eval.sh.)"
