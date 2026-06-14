#!/bin/bash
# Twitter-trace evaluation of the MODEL policies (everything that needs a matched
# per-cluster model): cache_ext_fifo_ml_protect plus the cache_ext_ml_sampling
# oversampling-factor sweep. Counterpart split of the heuristic (no-model)
# policies, which live in run_heuristic_eval.sh.
#
# This is the half that takes a --model-dir. It:
#   - runs cache_ext_fifo_ml_protect once per cluster (matched per-cluster model)
#     -> results/twitter_eval_protect.json
#   - sweeps cache_ext_ml_sampling over --factors, one file per factor
#     (twitter_eval_ml<F>.json). The factor is NOT in the bench config dict, so
#     each factor MUST be its own file or they checkpoint-collide; the filename
#     is derived from the factor in this loop so a file<->factor mismatch is
#     impossible.
#   - writes the cluster<->model mapping -> results/twitter_eval_meta.json
#     (model_file is not in the bench config dicts, so the results JSON alone
#     cannot attribute the model rows).
#
# Per-cluster DBs (leveldb_twitter_cluster<N>_db), so we loop clusters; the
# cgroup is sized per cluster from cgroup_sizes.sh (size-pct of each DB + floor),
# the same shared table run_heuristic_eval.sh and collect_traces.sh use -- so the
# heuristic/model comparison is at one memory size AND the floor matches the floor
# each per-cluster model was trained at (train/serve parity). My-YCSB is built
# from the leveldb-latency branch (throughput-only). MGLRU is disabled for the
# duration and ALWAYS restored.
set -eu -o pipefail

usage() {
	echo "Usage: $0 [--model-dir <dir>] [--clusters \"17 18 24 34 52\"] [--iterations <n>] \\"
	echo "          [--factors \"10 20 30 40\"] [--resume]"
	echo ""
	echo "  --model-dir        dir with twitter_cluster<N>_bench/model_weights.json per cluster (default: /mydata/models-jun-11)"
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --iterations       iterations per policy/cluster (default: 1)"
	echo "  --factors          ML-rank oversampling factors to sweep (default: \"10 20 30 40\")"
	echo "  --resume           allow existing results files (completed configs checkpoint-skip)"
	echo ""
	echo "Per-cluster cgroup sizing (size-pct + floor-mib) lives in cgroup_sizes.sh,"
	echo "shared with collect_traces.sh and run_heuristic_eval.sh. The floor there must"
	echo "match the floor each per-cluster model was trained at (train/serve parity)."
	echo ""
	echo "Expects /mydata/leveldb_twitter_cluster<N>_db and /mydata/twitter-traces"
	echo "(see download_twitter_dbs.sh) and a matched model per cluster under --model-dir."
	exit 1
}

# MODEL_DIR honors an exported env var (reproduce_eval.sh sets it) before the
# /mydata default; an explicit --model-dir flag overrides both.
MODEL_DIR="${MODEL_DIR:-/mydata/models-jun-11}"
CLUSTERS="17 18 24 34 52"
ITERATIONS=1
FACTORS="10 20 30 40"
RESUME=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-dir)  MODEL_DIR="$2";  shift 2 ;;
		--clusters)   CLUSTERS="$2";   shift 2 ;;
		--iterations) ITERATIONS="$2"; shift 2 ;;
		--factors)    FACTORS="$2";    shift 2 ;;
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

# Per-cluster cgroup sizing (shared with collect_traces.sh + run_heuristic_eval.sh).
source "$(dirname "$SCRIPT_PATH")/cgroup_sizes.sh"

RES_PROTECT="$RESULTS_PATH/twitter_eval_protect.json"
META="$RESULTS_PATH/twitter_eval_meta.json"
LOADER_LOG_DIR="$RESULTS_PATH/loader_logs"

# Cluster DBs + matched models present for every cluster? Hard-fail (mirrors the
# ycsb script): train/upload per-cluster models before evaluating the model
# policies.
for CLUSTER in $CLUSTERS; do
	if [ ! -d "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" ]; then
		echo "Error: cluster $CLUSTER database not found at $DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db"
		echo "Run ./download_twitter_dbs.sh first."
		exit 1
	fi
	if [ ! -f "$MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json" ]; then
		echo "Error: missing model $MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json"
		echo "Collect traces (collect_traces.sh), train a per-cluster model, or pass --model-dir."
		exit 1
	fi
done

# Every requested cluster must have a cgroup-sizing entry (fail before setup).
require_cluster_cgroups $CLUSTERS

mkdir -p "$RESULTS_PATH" "$LOADER_LOG_DIR"

# Refuse stale results unless resuming: the bench framework silently skips
# configs already present in the results file. meta.json is rewritten in full
# each run, so it is not guarded.
if [ "$RESUME" -eq 0 ]; then
	GUARD=("$RES_PROTECT")
	for F in $FACTORS; do GUARD+=("$RESULTS_PATH/twitter_eval_ml${F}.json"); done
	for f in "${GUARD[@]}"; do
		if [ -e "$f" ]; then
			echo "Error: $f already exists. Pass --resume to continue it, or remove it."
			exit 1
		fi
	done
fi

# Stale root-owned loader log breaks the harness's open("w") for new runs.
sudo rm -f /tmp/loader.log

# Build My-YCSB on the leveldb-latency branch (throughput-only). Rebuild only
# when the checkout has to change; reproduce_eval.sh already does this, so this
# is a no-op when invoked through it. -f discards the in-tree config YAML edits
# the harness makes at runtime.
if [ "$(cd "$YCSB_PATH" && git rev-parse --abbrev-ref HEAD)" != "leveldb-latency" ]; then
	echo "==> Switching My-YCSB to leveldb-latency branch and rebuilding..."
	(cd "$YCSB_PATH" && git checkout -f leveldb-latency)
	(cd "$YCSB_PATH/build" && cmake .. && make clean && make -j run_leveldb)
elif [ ! -x "$YCSB_PATH/build/run_leveldb" ]; then
	echo "==> Building My-YCSB run_leveldb..."
	(cd "$YCSB_PATH/build" && cmake .. && make -j run_leveldb)
fi

# Record which model file maps to which cluster: model_file is not part of the
# bench config dicts, so the results JSON alone cannot attribute the model rows.
python3 - "$META" "$MODEL_DIR" "$(cgroup_table_tokens $CLUSTERS)" "$CLUSTERS" <<'EOF'
import json, sys, os, subprocess
out, model_dir, cgroup_tokens, clusters = sys.argv[1:5]
# "<cluster>:<pct>:<floor>" tokens -> per-cluster cgroup sizing (from cgroup_sizes.sh).
cgroup = {}
for tok in cgroup_tokens.split():
    c, pct, floor = tok.split(":")
    cgroup[f"twitter_cluster{c}_bench"] = {"size_pct": int(pct), "floor_mib": int(floor)}
meta = {
    "kernel": subprocess.check_output(["uname", "-r"]).decode().strip(),
    "cgroup_sizing": cgroup,
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

run_model() { # run_model <policy> <cluster> <results_file> <log_tag> [extra args...]
	local POLICY="$1" CLUSTER="$2" RESULTS="$3" LOG_TAG="$4"
	shift 4
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
		--cache-ext-only \
		--benchmark "twitter_cluster${CLUSTER}_bench" \
		--model-file "$MODEL_DIR/twitter_cluster${CLUSTER}_bench/model_weights.json" \
		"$@"
	cp /tmp/loader.log "$LOADER_LOG_DIR/${LOG_TAG}_twitter_cluster${CLUSTER}.log" 2>/dev/null || true
}

# 1) cache_ext_fifo_ml_protect (skip-in-place reuse classifier), one row per
#    cluster -> twitter_eval_protect.json.
for CLUSTER in $CLUSTERS; do
	echo "==> [cluster $CLUSTER] cache_ext_fifo_ml_protect (model: twitter_cluster${CLUSTER}_bench)"
	run_model "cache_ext_fifo_ml_protect" "$CLUSTER" "$RES_PROTECT" "ml_protect"
done

# 2) cache_ext_ml_sampling oversampling sweep. Every factor to its OWN file,
#    derived from the factor in this loop so the file<->factor binding cannot
#    drift.
for F in $FACTORS; do
	RES_ML="$RESULTS_PATH/twitter_eval_ml${F}.json"
	echo "==> [ml-rank] factor ${F}x -> $(basename "$RES_ML")"
	for CLUSTER in $CLUSTERS; do
		echo "==> [cluster $CLUSTER] cache_ext_ml_sampling (model: twitter_cluster${CLUSTER}_bench, sample_size: $F)"
		run_model "cache_ext_ml_sampling" "$CLUSTER" "$RES_ML" "ml_sampling_${F}" \
			--policy-extra-args "--sample_size $F"
	done
done

echo ""
echo "==> Model-policy eval complete."
echo "Results: $RES_PROTECT  (cache_ext_fifo_ml_protect)"
for F in $FACTORS; do
	echo "         $RESULTS_PATH/twitter_eval_ml${F}.json  (ml_sampling, ${F}x)"
done
echo "         $META  (cluster<->model mapping)"
