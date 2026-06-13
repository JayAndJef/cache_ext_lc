#!/bin/bash
# Reproduce the ENTIRE YCSB model evaluation with one command.
#
# Sequences the existing eval scripts and owns every fragile binding so nothing
# can drift:
#   - run_model_eval.sh  -> classical policies + ml_protect (matched models)
#                           + Linux-LRU baseline + kernel-MGLRU baseline
#   - run_ml_sampling_eval.sh, looped per factor -> one ycsb_eval_ml<F>.json each
#     (the oversampling factor is NOT in the bench config dict, so each factor
#      MUST be its own file; deriving the filename from the factor here makes a
#      file<->factor mismatch impossible)
#   - a normalize step that strips legacy ml_sampling rows from the main file
#   - a manifest recording the file->factor/baseline map that otherwise lives
#     only in filenames
#
# The notebook (visualizations/results.ipynb) is the consumer of the result
# files this produces — there is no separate summarize script.
#
# Output files in results/:
#   ycsb_eval_results.json   5 classical policies + ml_protect (matched models)
#   ycsb_eval_ml{10,20,30,40}.json   ML-rank, one oversampling factor each
#   ycsb_eval_lru.json       Linux classic LRU baseline (MGLRU off)
#   ycsb_eval_mglru.json     kernel MGLRU baseline (MGLRU on)
#   ycsb_eval_meta.json      model<->workload mapping + per-model metrics.json
#   ycsb_eval_manifest.json  provenance: file->factor/baseline, git commit, args
set -eu -o pipefail

usage() {
	echo "Usage: $0 <leveldb_db_path> [--model-dir <dir>] [--cgroup-memory <size>] [--factors \"10 20 30 40\"] [--fresh]"
	echo ""
	echo "  --model-dir       dir with ycsb_<w>/model_weights.json per workload (default: /mydata/models-jun-11)"
	echo "  --cgroup-memory   cgroup memory limit (default: 10G)"
	echo "  --factors         ML-rank oversampling factors to sweep (default: \"10 20 30 40\")"
	echo "  --fresh           delete existing eval result files first (full recompute);"
	echo "                    default keeps them so completed configs checkpoint-skip"
	exit 1
}

if [ "$#" -lt 1 ]; then usage; fi

DB_PATH="$1"
shift

MODEL_DIR="/mydata/models-jun-11"
CGROUP_MEMORY="10G"
FACTORS="10 20 30 40"
FRESH=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-dir)     MODEL_DIR="$2";     shift 2 ;;
		--cgroup-memory) CGROUP_MEMORY="$2"; shift 2 ;;
		--factors)       FACTORS="$2";       shift 2 ;;
		--fresh)         FRESH=1;            shift   ;;
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
BENCH_PATH="$BASE_DIR/lc-bench"
YCSB_PATH="$BASE_DIR/My-YCSB"
RESULTS_PATH="$BASE_DIR/results"

RES="$RESULTS_PATH/ycsb_eval_results.json"
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
	rm -f "$RES" "$RES_LRU" "$RES_MGLRU" "$META" "$MANIFEST"
	for F in $FACTORS; do rm -f "$RESULTS_PATH/ycsb_eval_ml${F}.json"; done
fi

# My-YCSB must be on the master branch: the twitter scripts leave the submodule
# on leveldb-latency, whose binary reports all latencies as zero. -f discards
# the in-tree config YAML edits the harness makes at runtime.
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

# Pass --model-dir through to the sub-scripts (they honor a MODEL_DIR env var).
export MODEL_DIR

# 1) Classical policies + ml_protect + Linux-LRU baseline + kernel-MGLRU baseline.
echo "==> [1/4] Classical policies + ml_protect + LRU/MGLRU baselines..."
"$EVAL_DIR/run_model_eval.sh" "$DB_PATH" --resume --cgroup-memory "$CGROUP_MEMORY"

# 2) Normalize the main results file: strip any ml_sampling rows. The old
# scheme wrote ML-rank factor 20 into the main file; we now keep every factor
# (incl. 20) in its own ycsb_eval_ml<F>.json, so the main file is exactly the
# classical policies + ml_protect. Idempotent (no-op when none present).
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
    print(f"  dropped {dropped} legacy ml_sampling row(s) from {os.path.basename(path)}")
else:
    print("  no ml_sampling rows in main file (already normalized)")
EOF

# 3) ML-rank sweep. Every factor (incl. 20) to its OWN file, derived from the
# factor in this loop so the file<->factor binding cannot drift.
echo "==> [3/4] ML-rank oversampling sweep: factors $FACTORS"
for F in $FACTORS; do
	echo "==> [ml-rank] factor ${F}x -> ycsb_eval_ml${F}.json"
	"$EVAL_DIR/run_ml_sampling_eval.sh" \
		"$DB_PATH" "$CGROUP_MEMORY" \
		"$RESULTS_PATH/ycsb_eval_ml${F}.json" "_$F" "$F"
done

# 4) Manifest: the authoritative file->factor/baseline map (today this lives
# only in filenames), plus run provenance.
echo "==> [4/4] Writing manifest..."
GIT_COMMIT=$(cd "$BASE_DIR" && git rev-parse HEAD 2>/dev/null || echo "unknown")
python3 - "$MANIFEST" "$DB_PATH" "$MODEL_DIR" "$CGROUP_MEMORY" "$FACTORS" "$GIT_COMMIT" <<'EOF'
import json, sys, os, subprocess
manifest, db, model_dir, mem, factors_str, commit = sys.argv[1:7]
factors = [int(x) for x in factors_str.split()]
files = {
    "ycsb_eval_results.json": {
        "policies": ["cache_ext_mru", "cache_ext_fifo", "cache_ext_s3fifo",
                     "cache_ext_lhd", "cache_ext_sampling",
                     "cache_ext_fifo_ml_protect"],
        "note": "classical cache_ext policies + ml_protect (matched per-workload models)",
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
    "cgroup_memory": mem,
    "iterations": 1,
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
