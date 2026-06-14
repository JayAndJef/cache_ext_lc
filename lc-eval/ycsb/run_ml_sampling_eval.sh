#!/bin/bash
# YCSB+LevelDB evaluation of the MODEL policies (everything that needs a matched
# per-workload model): cache_ext_fifo_ml_protect plus the cache_ext_ml_sampling
# oversampling-factor sweep. Counterpart split of the heuristic (no-model)
# policies, which live in run_heuristic_eval.sh. Mirrors the Twitter counterpart
# lc-eval/twitter/run_ml_sampling_eval.sh, minus the per-cluster cgroup sizing
# (ycsb uses a fixed 10G).
#
# This is the half that takes a --model-dir. It:
#   - runs cache_ext_fifo_ml_protect once per workload (matched per-workload model)
#     -> results/ycsb_eval_protect.json
#   - sweeps cache_ext_ml_sampling over --factors, one file per factor
#     (ycsb_eval_ml<F>.json). The factor is NOT in the bench config dict, so each
#     factor MUST be its own file or they checkpoint-collide; the filename is
#     derived from the factor in this loop so a file<->factor mismatch is
#     impossible.
#   - writes the workload<->model mapping -> results/ycsb_eval_meta.json
#     (model_file is not in the bench config dicts, so the results JSON alone
#     cannot attribute the model rows).
#
# One DB shared by all 6 workloads, fixed 10G cgroup. My-YCSB is built from the
# master branch (per-op latency enabled). MGLRU is disabled for the duration and
# ALWAYS restored.
set -eu -o pipefail

usage() {
	echo "Usage: $0 <leveldb_db_path> [--model-dir <dir>] [--iterations <n>] \\"
	echo "          [--factors \"10 20 30 40\"] [--resume]"
	echo ""
	echo "  --model-dir        dir with ycsb_<w>/model_weights.json per workload (default: /mydata/models-jun-11)"
	echo "  --iterations       iterations per policy/workload (default: 1)"
	echo "  --factors          ML-rank oversampling factors to sweep (default: \"10 20 30 40\")"
	echo "  --resume           allow existing results files (completed configs checkpoint-skip)"
	echo ""
	echo "Needs a matched model per workload under --model-dir; hard-fails if any"
	echo "is missing. Usually invoked via reproduce_eval.sh."
	exit 1
}

if [ "$#" -lt 1 ]; then usage; fi

DB_PATH="$1"
shift

# MODEL_DIR honors an exported env var (reproduce_eval.sh sets it) before the
# /mydata default; an explicit --model-dir flag overrides both.
MODEL_DIR="${MODEL_DIR:-/mydata/models-jun-11}"
ITERATIONS=1
FACTORS="10 20 30 40"
RESUME=0
CGROUP_MEMORY="10G"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--model-dir)  MODEL_DIR="$2";  shift 2 ;;
		--iterations) ITERATIONS="$2"; shift 2 ;;
		--factors)    FACTORS="$2";    shift 2 ;;
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

RES_PROTECT="$RESULTS_PATH/ycsb_eval_protect.json"
META="$RESULTS_PATH/ycsb_eval_meta.json"
LOADER_LOG_DIR="$RESULTS_PATH/loader_logs"

WORKLOADS=(a b c d e f)

# Matched models present for every workload? Hard-fail (mirrors the twitter
# script): train/upload per-workload models before evaluating the model policies.
for W in "${WORKLOADS[@]}"; do
	if [ ! -f "$MODEL_DIR/ycsb_$W/model_weights.json" ]; then
		echo "Error: missing model $MODEL_DIR/ycsb_$W/model_weights.json"
		echo "Collect traces (collect_traces.sh), train a per-workload model, or pass --model-dir."
		exit 1
	fi
done

mkdir -p "$RESULTS_PATH" "$LOADER_LOG_DIR"

# Refuse stale results unless resuming: the bench framework silently skips
# configs already present in the results file. meta.json is rewritten in full
# each run, so it is not guarded.
if [ "$RESUME" -eq 0 ]; then
	GUARD=("$RES_PROTECT")
	for F in $FACTORS; do GUARD+=("$RESULTS_PATH/ycsb_eval_ml${F}.json"); done
	for f in "${GUARD[@]}"; do
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

# Record which model file maps to which workload: model_file is not part of the
# bench config dicts, so the results JSON alone cannot attribute the model rows.
python3 - "$META" "$MODEL_DIR" "$CGROUP_MEMORY" "$ITERATIONS" <<'EOF'
import json, sys, os, subprocess
out, model_dir, mem, iters = sys.argv[1:5]
meta = {
    "kernel": subprocess.check_output(["uname", "-r"]).decode().strip(),
    "cgroup_memory": mem,
    "iterations": int(iters),
    "models": {},
}
for w in "abcdef":
    base = os.path.join(model_dir, f"ycsb_{w}")
    entry = {"model_file": os.path.join(base, "model_weights.json")}
    mpath = os.path.join(base, "metrics.json")
    if os.path.exists(mpath):
        with open(mpath) as f:
            entry["metrics"] = json.load(f)
    meta["models"][f"ycsb_{w}"] = entry
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

run_model() { # run_model <policy> <workload> <results_file> <log_tag> [extra args...]
	local POLICY="$1" W="$2" RESULTS="$3" LOG_TAG="$4"
	shift 4
	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RESULTS" \
		--leveldb-db "$DB_PATH" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--cgroup-memory "$CGROUP_MEMORY" \
		--cache-ext-only \
		--benchmark "ycsb_$W" \
		--model-file "$MODEL_DIR/ycsb_$W/model_weights.json" \
		"$@"
	cp /tmp/loader.log "$LOADER_LOG_DIR/${LOG_TAG}_ycsb_$W.log" 2>/dev/null || true
}

# 1) cache_ext_fifo_ml_protect (skip-in-place reuse classifier), one row per
#    workload -> ycsb_eval_protect.json.
for W in "${WORKLOADS[@]}"; do
	echo "==> [ycsb_$W] cache_ext_fifo_ml_protect (model: ycsb_$W)"
	run_model "cache_ext_fifo_ml_protect" "$W" "$RES_PROTECT" "ml_protect"
done

# 2) cache_ext_ml_sampling oversampling sweep. Every factor to its OWN file,
#    derived from the factor in this loop so the file<->factor binding cannot
#    drift.
for F in $FACTORS; do
	RES_ML="$RESULTS_PATH/ycsb_eval_ml${F}.json"
	echo "==> [ml-rank] factor ${F}x -> $(basename "$RES_ML")"
	for W in "${WORKLOADS[@]}"; do
		echo "==> [ycsb_$W] cache_ext_ml_sampling (model: ycsb_$W, sample_size: $F)"
		run_model "cache_ext_ml_sampling" "$W" "$RES_ML" "ml_sampling_${F}" \
			--policy-extra-args "--sample_size $F"
	done
done

echo ""
echo "==> Model-policy eval complete."
echo "Results: $RES_PROTECT  (cache_ext_fifo_ml_protect)"
for F in $FACTORS; do
	echo "         $RESULTS_PATH/ycsb_eval_ml${F}.json  (ml_sampling, ${F}x)"
done
echo "         $META  (workload<->model mapping)"
