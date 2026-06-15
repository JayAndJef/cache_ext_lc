#!/bin/bash
# Reproduce the ENTIRE Twitter-cluster model evaluation with one command.
# Twitter counterpart of lc-eval/ycsb/reproduce_eval.sh.
#
# Sequences the two eval halves and owns every fragile binding so nothing drifts:
#   - run_heuristic_eval.sh   -> 5 classical cache_ext policies (no model)
#                                + Linux-LRU baseline + kernel-MGLRU baseline
#   - run_ml_sampling_eval.sh -> the model policies: ml_protect (matched per-
#     cluster models) + the ml_sampling oversampling sweep (one twitter_eval_
#     ml<F>.json per factor) + the cluster<->model meta. The factor is NOT in the
#     bench config dict, so each factor lands in its own file.
#   - a manifest recording the file->factor/baseline map that otherwise lives
#     only in filenames
#
# The split is along "needs a model or not": the heuristic half takes no
# --model-dir, the model half owns every model input. The notebook
# (visualizations/results.ipynb) is the consumer of the result files this
# produces.
#
# Output files in results/:
#   twitter_eval_results.json    5 classical cache_ext policies (heuristic, no model)
#   twitter_eval_protect.json    cache_ext_fifo_ml_protect (matched per-cluster models)
#   twitter_eval_ml{10,20,30,40}.json   ML-rank, one oversampling factor each
#   twitter_eval_lru.json        Linux classic LRU baseline (MGLRU off)
#   twitter_eval_mglru.json      kernel MGLRU baseline (MGLRU on)
#   twitter_eval_meta.json       cluster<->model mapping + per-model metrics.json
#   twitter_eval_manifest.json   provenance: file->factor/baseline, git commit, args
set -eu -o pipefail

usage() {
	echo "Usage: $0 [--model-dir <dir>] [--clusters \"17 18 24 34 52\"] [--iterations <n>] [--factors \"10 20 30 40\"] [--fresh]"
	echo ""
	echo "  --model-dir        dir with twitter_cluster<N>_bench/model_weights.json per cluster (default: /mydata/models-jun-11)"
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --iterations       iterations per policy/cluster (default: 1)"
	echo "  --factors          ML-rank oversampling factors to sweep (default: \"10 20 30 40\")"
	echo "  --fresh            delete existing eval result files first (full recompute);"
	echo "                     default keeps them so completed configs checkpoint-skip"
	echo ""
	echo "Per-cluster cgroup sizing (size-pct + floor-mib) lives in cgroup_sizes.sh,"
	echo "shared by all the Twitter eval/collection scripts."
	exit 1
}

MODEL_DIR="/mydata/models-jun-11"
CLUSTERS="17 18 24 34 52"
ITERATIONS=1
FACTORS="10 20 30 40"
FRESH=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-dir)  MODEL_DIR="$2";  shift 2 ;;
		--clusters)   CLUSTERS="$2";   shift 2 ;;
		--iterations) ITERATIONS="$2"; shift 2 ;;
		--factors)    FACTORS="$2";    shift 2 ;;
		--fresh)      FRESH=1;         shift   ;;
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
EVAL_DIR="$BASE_DIR/lc-eval/twitter"
YCSB_PATH="$BASE_DIR/My-YCSB"
DB_DIRS=$(realpath "$BASE_DIR/../")
RESULTS_PATH="$BASE_DIR/results"

# Per-cluster cgroup sizing (shared table; recorded into the manifest below).
source "$EVAL_DIR/cgroup_sizes.sh"

RES="$RESULTS_PATH/twitter_eval_results.json"
RES_PROTECT="$RESULTS_PATH/twitter_eval_protect.json"
RES_LRU="$RESULTS_PATH/twitter_eval_lru.json"
RES_MGLRU="$RESULTS_PATH/twitter_eval_mglru.json"
META="$RESULTS_PATH/twitter_eval_meta.json"
MANIFEST="$RESULTS_PATH/twitter_eval_manifest.json"

mkdir -p "$RESULTS_PATH"

# Preflight: cluster DBs + matched models present for every cluster.
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

# Every requested cluster must have a cgroup-sizing entry in cgroup_sizes.sh.
require_cluster_cgroups $CLUSTERS

if [ "$FRESH" -eq 1 ]; then
	echo "==> --fresh: removing existing eval result files for a clean recompute..."
	rm -f "$RES" "$RES_PROTECT" "$RES_LRU" "$RES_MGLRU" "$META" "$MANIFEST"
	for F in $FACTORS; do rm -f "$RESULTS_PATH/twitter_eval_ml${F}.json"; done
fi

# Build My-YCSB on the leveldb-latency branch (throughput-only) once, so the
# sub-scripts no-op their build step. -f discards the in-tree config YAML edits
# the harness makes at runtime.
if [ "$(cd "$YCSB_PATH" && git rev-parse --abbrev-ref HEAD)" != "leveldb-latency" ]; then
	echo "==> Switching My-YCSB to leveldb-latency branch and rebuilding..."
	(cd "$YCSB_PATH" && git checkout -f leveldb-latency)
	(cd "$YCSB_PATH/build" && cmake .. && make clean && make -j run_leveldb)
elif [ ! -x "$YCSB_PATH/build/run_leveldb" ]; then
	echo "==> Building My-YCSB run_leveldb..."
	(cd "$YCSB_PATH/build" && cmake .. && make -j run_leveldb)
fi

# Stale root-owned loader log breaks the harness's open("w") for new runs.
sudo rm -f /tmp/loader.log

# 1) Model policies: ml_protect (matched per-cluster models) + the ml_sampling
# oversampling sweep (one twitter_eval_ml<F>.json per factor) + the cluster<->
# model meta. The script owns the per-factor file derivation internally, so the
# file<->factor binding cannot drift.
echo "==> [1/3] Model policies: ml_protect + ml_sampling sweep (factors $FACTORS)..."
"$EVAL_DIR/run_ml_sampling_eval.sh" \
	--model-dir "$MODEL_DIR" --clusters "$CLUSTERS" \
	--iterations "$ITERATIONS" --factors "$FACTORS" --resume

# 2) Heuristic (no-model) policies: 5 classical cache_ext + Linux-LRU + kernel-MGLRU.
echo "==> [2/3] Heuristic policies (5 classical) + LRU/MGLRU baselines..."
"$EVAL_DIR/run_heuristic_eval.sh" \
	--clusters "$CLUSTERS" \
	--iterations "$ITERATIONS" --resume

# 3) Manifest: the authoritative file->factor/baseline map (today this lives
# only in filenames), plus run provenance.
echo "==> [3/3] Writing manifest..."
GIT_COMMIT=$(cd "$BASE_DIR" && git rev-parse HEAD 2>/dev/null || echo "unknown")
python3 - "$MANIFEST" "$MODEL_DIR" "$(cgroup_table_tokens $CLUSTERS)" "$ITERATIONS" "$FACTORS" "$CLUSTERS" "$GIT_COMMIT" <<'EOF'
import json, sys, os, subprocess
manifest, model_dir, cgroup_tokens, iters, factors_str, clusters_str, commit = sys.argv[1:8]
factors = [int(x) for x in factors_str.split()]
clusters = clusters_str.split()
# "<cluster>:<pct>:<floor>" tokens -> per-cluster cgroup sizing (from cgroup_sizes.sh).
cgroup = {}
for tok in cgroup_tokens.split():
    c, pct, floor = tok.split(":")
    cgroup[f"twitter_cluster{c}_bench"] = {"size_pct": int(pct), "floor_mib": int(floor)}
files = {
    "twitter_eval_results.json": {
        "policies": ["cache_ext_mru", "cache_ext_fifo", "cache_ext_s3fifo",
                     "cache_ext_lhd", "cache_ext_sampling"],
        "note": "5 classical cache_ext heuristic policies (no model)",
    },
    "twitter_eval_protect.json": {
        "policy_loader": "cache_ext_fifo_ml_protect.out",
        "note": "skip-in-place reuse classifier (matched per-cluster models)",
    },
    "twitter_eval_lru.json":   {"baseline": "Linux LRU (MGLRU off)", "policy_loader": None},
    "twitter_eval_mglru.json": {"baseline": "kernel MGLRU (MGLRU on)", "policy_loader": None},
    "twitter_eval_meta.json":  {"contents": "cluster<->model mapping + per-model metrics.json"},
}
for f in factors:
    files[f"twitter_eval_ml{f}.json"] = {
        "policy_loader": "cache_ext_ml_sampling.out",
        "sample_size": f,
        "note": f"ML-rank, {f}x oversampling (factor not recorded in config dict)",
    }
out = {
    "generated_by": "lc-eval/twitter/reproduce_eval.sh",
    "git_commit": commit,
    "kernel": subprocess.check_output(["uname", "-r"]).decode().strip(),
    "clusters": clusters,
    "model_dir": model_dir,
    "cgroup_sizing": cgroup,
    "iterations": int(iters),
    "factors": factors,
    "files": files,
    "models": {f"twitter_cluster{c}_bench": os.path.join(model_dir, f"twitter_cluster{c}_bench", "model_weights.json")
               for c in clusters},
}
json.dump(out, open(manifest, "w"), indent=2)
print(f"Wrote {manifest}")
EOF

echo ""
echo "==> Reproduce complete. Result files in $RESULTS_PATH:"
ls -1 "$RESULTS_PATH"/twitter_eval_*.json 2>/dev/null | sed 's/^/    /'
echo ""
echo "Render figures by running the notebook:"
echo "  jupyter nbconvert --to notebook --execute --inplace visualizations/results.ipynb"
echo "  (or open visualizations/results.ipynb interactively)"
