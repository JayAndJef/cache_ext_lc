#!/bin/bash
# Reproduce the ENTIRE YCSB model evaluation with one command.
#
# Sequences the two eval halves and owns every fragile binding so nothing drifts
# (mirrors lc-eval/twitter/reproduce_eval.sh, minus the per-cluster cgroup sizing
# -- ycsb uses a fixed 10G):
#   - run_ml_sampling_eval.sh -> the model policies: ml_protect (matched per-
#     workload models) + the ml_sampling oversampling sweep (one ycsb_eval_
#     ml<F>.json per factor) + the workload<->model meta. The factor is NOT in
#     the bench config dict, so each factor lands in its own file.
#   - run_heuristic_eval.sh   -> 5 classical cache_ext policies (no model)
#                                + Linux-LRU baseline + kernel-MGLRU baseline
#   - a manifest recording the file->factor/baseline map that otherwise lives
#     only in filenames
#
# The split is along "needs a model or not": the heuristic half takes no
# --model-dir, the model half owns every model input. The notebook
# (visualizations/results.ipynb) is the consumer of the result files this
# produces -- there is no separate summarize script.
#
# Output files in results/:
#   ycsb_eval_results.json   5 classical cache_ext policies (heuristic, no model)
#   ycsb_eval_protect.json   cache_ext_fifo_ml_protect (matched per-workload models)
#   ycsb_eval_ml{10,20,30,40}.json   ML-rank, one oversampling factor each
#   ycsb_eval_lru.json       Linux classic LRU baseline (MGLRU off)
#   ycsb_eval_mglru.json     kernel MGLRU baseline (MGLRU on)
#   ycsb_eval_meta.json      model<->workload mapping + per-model metrics.json
#   ycsb_eval_manifest.json  provenance: file->factor/baseline, git commit, args
set -eu -o pipefail

usage() {
	echo "Usage: $0 <leveldb_db_path> [--model-dir <dir>] [--iterations <n>] [--factors \"10 20 30 40\"] [--fresh]"
	echo ""
	echo "  --model-dir       dir with ycsb_<w>/model_weights.json per workload (default: /mydata/models-jun-11)"
	echo "  --iterations      iterations per policy/workload (default: 1)"
	echo "  --factors         ML-rank oversampling factors to sweep (default: \"10 20 30 40\")"
	echo "  --fresh           delete existing eval result files first (full recompute);"
	echo "                    default keeps them so completed configs checkpoint-skip"
	echo ""
	echo "The cgroup limit is a fixed 10G (no per-workload sizing, unlike the"
	echo "twitter harness)."
	exit 1
}

if [ "$#" -lt 1 ]; then usage; fi

DB_PATH="$1"
shift

MODEL_DIR="/mydata/models-jun-11"
ITERATIONS=1
FACTORS="10 20 30 40"
FRESH=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-dir)  MODEL_DIR="$2";  shift 2 ;;
		--iterations) ITERATIONS="$2"; shift 2 ;;
		--factors)    FACTORS="$2";    shift 2 ;;
		--fresh)      FRESH=1;         shift   ;;
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
EVAL_DIR="$BASE_DIR/lc-eval/ycsb"
YCSB_PATH="$BASE_DIR/My-YCSB"
RESULTS_PATH="$BASE_DIR/results"

RES="$RESULTS_PATH/ycsb_eval_results.json"
RES_PROTECT="$RESULTS_PATH/ycsb_eval_protect.json"
RES_LRU="$RESULTS_PATH/ycsb_eval_lru.json"
RES_MGLRU="$RESULTS_PATH/ycsb_eval_mglru.json"
META="$RESULTS_PATH/ycsb_eval_meta.json"
MANIFEST="$RESULTS_PATH/ycsb_eval_manifest.json"

mkdir -p "$RESULTS_PATH"

# Preflight: matched models present for every workload.
for W in a b c d e f; do
	if [ ! -f "$MODEL_DIR/ycsb_$W/model_weights.json" ]; then
		echo "Error: missing model $MODEL_DIR/ycsb_$W/model_weights.json"
		exit 1
	fi
done

if [ "$FRESH" -eq 1 ]; then
	echo "==> --fresh: removing existing eval result files for a clean recompute..."
	rm -f "$RES" "$RES_PROTECT" "$RES_LRU" "$RES_MGLRU" "$META" "$MANIFEST"
	for F in $FACTORS; do rm -f "$RESULTS_PATH/ycsb_eval_ml${F}.json"; done
fi

# Build My-YCSB on the master branch once, so the sub-scripts no-op their build
# step. The twitter scripts leave the submodule on leveldb-latency, whose binary
# reports all latencies as zero. -f discards the in-tree config YAML edits the
# harness makes at runtime.
if [ "$(cd "$YCSB_PATH" && git rev-parse --abbrev-ref HEAD)" != "master" ]; then
	echo "==> Switching My-YCSB to master branch and rebuilding..."
	(cd "$YCSB_PATH" && git checkout -f master)
	(cd "$YCSB_PATH/build" && cmake .. && make clean && make -j run_leveldb)
elif [ ! -x "$YCSB_PATH/build/run_leveldb" ]; then
	echo "==> Building My-YCSB run_leveldb..."
	(cd "$YCSB_PATH/build" && cmake .. && make -j run_leveldb)
fi

# Stale root-owned loader log breaks the harness's open("w") for new runs.
sudo rm -f /tmp/loader.log

# 1) Model policies: ml_protect (matched per-workload models) + the ml_sampling
# oversampling sweep (one ycsb_eval_ml<F>.json per factor) + the workload<->model
# meta. The script owns the per-factor file derivation internally, so the
# file<->factor binding cannot drift.
echo "==> [1/3] Model policies: ml_protect + ml_sampling sweep (factors $FACTORS)..."
"$EVAL_DIR/run_ml_sampling_eval.sh" \
	"$DB_PATH" --model-dir "$MODEL_DIR" \
	--iterations "$ITERATIONS" --factors "$FACTORS" --resume

# 2) Heuristic (no-model) policies: 5 classical cache_ext + Linux-LRU + kernel-MGLRU.
echo "==> [2/3] Heuristic policies (5 classical) + LRU/MGLRU baselines..."
"$EVAL_DIR/run_heuristic_eval.sh" \
	"$DB_PATH" --iterations "$ITERATIONS" --resume

# 3) Manifest: the authoritative file->factor/baseline map (today this lives
# only in filenames), plus run provenance.
echo "==> [3/3] Writing manifest..."
GIT_COMMIT=$(cd "$BASE_DIR" && git rev-parse HEAD 2>/dev/null || echo "unknown")
python3 - "$MANIFEST" "$DB_PATH" "$MODEL_DIR" "$ITERATIONS" "$FACTORS" "$GIT_COMMIT" <<'EOF'
import json, sys, os, subprocess
manifest, db, model_dir, iters, factors_str, commit = sys.argv[1:7]
factors = [int(x) for x in factors_str.split()]
files = {
    "ycsb_eval_results.json": {
        "policies": ["cache_ext_mru", "cache_ext_fifo", "cache_ext_s3fifo",
                     "cache_ext_lhd", "cache_ext_sampling"],
        "note": "5 classical cache_ext heuristic policies (no model)",
    },
    "ycsb_eval_protect.json": {
        "policy_loader": "cache_ext_fifo_ml_protect.out",
        "note": "skip-in-place reuse classifier (matched per-workload models)",
    },
    "ycsb_eval_lru.json":   {"baseline": "Linux LRU (MGLRU off)", "policy_loader": None},
    "ycsb_eval_mglru.json": {"baseline": "kernel MGLRU (MGLRU on)", "policy_loader": None},
    "ycsb_eval_meta.json":  {"contents": "model<->workload mapping + per-model metrics.json"},
}
for f in factors:
    files[f"ycsb_eval_ml{f}.json"] = {
        "policy_loader": "cache_ext_ml_sampling.out",
        "sample_size": f,
        "note": f"ML-rank, {f}x oversampling (factor not recorded in config dict)",
    }
out = {
    "generated_by": "lc-eval/ycsb/reproduce_eval.sh",
    "git_commit": commit,
    "kernel": subprocess.check_output(["uname", "-r"]).decode().strip(),
    "db_path": db,
    "model_dir": model_dir,
    "cgroup_memory": "10G",
    "iterations": int(iters),
    "factors": factors,
    "files": files,
    "models": {f"ycsb_{w}": os.path.join(model_dir, f"ycsb_{w}", "model_weights.json")
               for w in "abcdef"},
}
json.dump(out, open(manifest, "w"), indent=2)
print(f"Wrote {manifest}")
EOF

echo ""
echo "==> Reproduce complete. Result files in $RESULTS_PATH:"
ls -1 "$RESULTS_PATH"/ycsb_eval_*.json 2>/dev/null | sed 's/^/    /'
echo ""
echo "Render figures/tables by running the notebook:"
echo "  jupyter nbconvert --to notebook --execute --inplace visualizations/results.ipynb"
echo "  (or open visualizations/results.ipynb interactively)"
