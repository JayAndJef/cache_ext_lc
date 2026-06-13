#!/bin/bash
# Reproduce the ENTIRE Twitter-cluster model evaluation with one command.
# Twitter counterpart of lc-eval/ycsb/reproduce_eval.sh.
#
# Sequences the eval scripts and owns every fragile binding so nothing drifts:
#   - run_model_eval.sh       -> classical policies + ml_protect (matched models)
#                                + Linux-LRU baseline + kernel-MGLRU baseline
#   - run_ml_sampling_eval.sh, looped per factor -> one twitter_eval_ml<F>.json
#     each (the oversampling factor is NOT in the bench config dict, so each
#     factor MUST be its own file; deriving the filename from the factor here
#     makes a file<->factor mismatch impossible)
#   - a normalize step that strips any ml_sampling rows from the main file
#   - a manifest recording the file->factor/baseline map that otherwise lives
#     only in filenames
#
# The notebook (visualizations/results.ipynb) is the consumer of the result
# files this produces.
#
# Output files in results/:
#   twitter_eval_results.json    5 classical policies + ml_protect (matched models)
#   twitter_eval_ml{10,20,30,40}.json   ML-rank, one oversampling factor each
#   twitter_eval_lru.json        Linux classic LRU baseline (MGLRU off)
#   twitter_eval_mglru.json      kernel MGLRU baseline (MGLRU on)
#   twitter_eval_meta.json       cluster<->model mapping + per-model metrics.json
#   twitter_eval_manifest.json   provenance: file->factor/baseline, git commit, args
set -eu -o pipefail

usage() {
	echo "Usage: $0 [--model-dir <dir>] [--clusters \"17 18 24 34 52\"] [--cgroup-size-pct <n>] [--iterations <n>] [--factors \"10 20 30 40\"] [--fresh]"
	echo ""
	echo "  --model-dir        dir with twitter_cluster<N>_bench/model_weights.json per cluster (default: /mydata/models-jun-11)"
	echo "  --clusters         space-separated Twitter cluster IDs (default: 17 18 24 34 52)"
	echo "  --cgroup-size-pct  cgroup memory as percent of cluster DB size (default: 10)"
	echo "  --iterations       iterations per policy/cluster (default: 3)"
	echo "  --factors          ML-rank oversampling factors to sweep (default: \"10 20 30 40\")"
	echo "  --fresh            delete existing eval result files first (full recompute);"
	echo "                     default keeps them so completed configs checkpoint-skip"
	exit 1
}

MODEL_DIR="/mydata/models-jun-11"
CLUSTERS="17 18 24 34 52"
CGROUP_SIZE_PCT=10
ITERATIONS=3
FACTORS="10 20 30 40"
FRESH=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-dir)       MODEL_DIR="$2";       shift 2 ;;
		--clusters)        CLUSTERS="$2";         shift 2 ;;
		--cgroup-size-pct) CGROUP_SIZE_PCT="$2";  shift 2 ;;
		--iterations)      ITERATIONS="$2";       shift 2 ;;
		--factors)         FACTORS="$2";          shift 2 ;;
		--fresh)           FRESH=1;               shift   ;;
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

RES="$RESULTS_PATH/twitter_eval_results.json"
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

if [ "$FRESH" -eq 1 ]; then
	echo "==> --fresh: removing existing eval result files for a clean recompute..."
	rm -f "$RES" "$RES_LRU" "$RES_MGLRU" "$META" "$MANIFEST"
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

# 1) Classical policies + ml_protect + Linux-LRU baseline + kernel-MGLRU baseline.
echo "==> [1/4] Classical policies + ml_protect + LRU/MGLRU baselines..."
"$EVAL_DIR/run_model_eval.sh" \
	--model-dir "$MODEL_DIR" --clusters "$CLUSTERS" \
	--cgroup-size-pct "$CGROUP_SIZE_PCT" --iterations "$ITERATIONS" --resume

# 2) Normalize the main results file: strip any ml_sampling rows (we keep every
# factor in its own twitter_eval_ml<F>.json). Idempotent (no-op when none).
echo "==> [2/4] Normalizing main results file (drop ml_sampling rows)..."
python3 - "$RES" <<'EOF'
import json, sys, os
path = sys.argv[1]
if not os.path.exists(path):
    sys.exit(0)
rows = json.load(open(path))
kept = [r for r in rows
        if r.get("config", {}).get("policy_loader") != "cache_ext_ml_sampling.out"]
dropped = len(rows) - len(kept)
if dropped:
    json.dump(kept, open(path, "w"), indent=2)
    print(f"  dropped {dropped} ml_sampling row(s) from {os.path.basename(path)}")
else:
    print("  no ml_sampling rows in main file (already normalized)")
EOF

# 3) ML-rank sweep. Every factor to its OWN file, derived from the factor in
# this loop so the file<->factor binding cannot drift.
echo "==> [3/4] ML-rank oversampling sweep: factors $FACTORS"
for F in $FACTORS; do
	echo "==> [ml-rank] factor ${F}x -> twitter_eval_ml${F}.json"
	"$EVAL_DIR/run_ml_sampling_eval.sh" \
		--sample-size "$F" \
		--results-file "$RESULTS_PATH/twitter_eval_ml${F}.json" \
		--log-suffix "_$F" \
		--model-dir "$MODEL_DIR" --clusters "$CLUSTERS" \
		--cgroup-size-pct "$CGROUP_SIZE_PCT" --iterations "$ITERATIONS"
done

# 4) Manifest: the authoritative file->factor/baseline map (today this lives
# only in filenames), plus run provenance.
echo "==> [4/4] Writing manifest..."
GIT_COMMIT=$(cd "$BASE_DIR" && git rev-parse HEAD 2>/dev/null || echo "unknown")
python3 - "$MANIFEST" "$MODEL_DIR" "$CGROUP_SIZE_PCT" "$ITERATIONS" "$FACTORS" "$CLUSTERS" "$GIT_COMMIT" <<'EOF'
import json, sys, os, subprocess
manifest, model_dir, pct, iters, factors_str, clusters_str, commit = sys.argv[1:8]
factors = [int(x) for x in factors_str.split()]
clusters = clusters_str.split()
files = {
    "twitter_eval_results.json": {
        "policies": ["cache_ext_mru", "cache_ext_fifo", "cache_ext_s3fifo",
                     "cache_ext_lhd", "cache_ext_sampling",
                     "cache_ext_fifo_ml_protect"],
        "note": "classical cache_ext policies + ml_protect (matched per-cluster models)",
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
    "cgroup_size_pct": int(pct),
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
