#!/bin/bash
# Staged YCSB+LevelDB evaluation of cache_ext_fifo_ml_protect (matched model
# per workload) against the upstream cache_ext baseline policies.
#
# Derived from run.sh, with: 1 iteration; 6 YCSB workloads (no uniform);
# fifo_lc and the BPF-mglru policy dropped; ml_protect run per-workload with
# its matching model from MODEL_DIR; and a manual stage gate:
#   --stage 1            run ycsb_a only (6 configs), print gate report, exit
#   --stage 2 --resume   run all workloads (ycsb_a checkpoint-skips) + the
#                        kernel-MGLRU baseline pass
#
# Results: results/ycsb_eval_results.json  (cache_ext policies + ML)
#          results/ycsb_eval_mglru.json    (kernel MGLRU baseline)
# MGLRU is disabled during cache_ext runs and ALWAYS restored to enabled on
# exit (machine default), unlike run.sh which leaves it disabled.
set -eu -o pipefail

usage() {
	echo "Usage: $0 <leveldb_db_path> --stage <1|2> [--resume] [--cgroup-memory <size>]"
	echo ""
	echo "  --stage 1         run ycsb_a only, print gate report, exit (review point)"
	echo "  --stage 2         run all 6 workloads + kernel-MGLRU pass (use with --resume)"
	echo "  --resume          allow existing results files (completed configs skip)"
	echo "  --cgroup-memory   cgroup memory limit (default: 10G)"
	exit 1
}

if [ "$#" -lt 1 ]; then usage; fi

DB_PATH="$1"
shift

STAGE=""
RESUME=0
CGROUP_MEMORY="10G"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--stage)         STAGE="$2";         shift 2 ;;
		--resume)        RESUME=1;           shift   ;;
		--cgroup-memory) CGROUP_MEMORY="$2"; shift 2 ;;
		*) echo "Unknown argument: $1"; usage ;;
	esac
done

if [ "$STAGE" != "1" ] && [ "$STAGE" != "2" ]; then
	echo "Error: --stage must be 1 or 2"
	usage
fi

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

MODEL_DIR="/mydata/models-jun-11"
RES="$RESULTS_PATH/ycsb_eval_results.json"
RES_MGLRU="$RESULTS_PATH/ycsb_eval_mglru.json"

# Baseline cache_ext policies, in reference-figure order. cache_ext_sampling
# is the figure's "LFU (cache_ext)" (bpf_lfu_score_fn). fifo_lc (tracer-log
# disk blowup) and the BPF mglru reimpl (not in the figure) are dropped.
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
	for f in "$RES" "$RES_MGLRU"; do
		if [ -e "$f" ]; then
			echo "Error: $f already exists. Pass --resume to continue it, or remove it."
			exit 1
		fi
	done
fi

# Stale root-owned loader log breaks the harness's open("w") for new runs.
sudo rm -f /tmp/loader.log

if [ ! -x "$YCSB_PATH/build/run_leveldb" ]; then
	echo "Error: $YCSB_PATH/build/run_leveldb not found; build My-YCSB first."
	exit 1
fi

for W in "${WORKLOADS[@]}"; do
	if [ ! -f "$MODEL_DIR/ycsb_$W/model_weights.json" ]; then
		echo "Error: missing model $MODEL_DIR/ycsb_$W/model_weights.json"
		exit 1
	fi
done

# Record which model file maps to which workload: model_file is not part of
# the bench config dicts, so the results JSON alone cannot attribute ML rows.
python3 - "$RESULTS_PATH/ycsb_eval_meta.json" "$MODEL_DIR" "$CGROUP_MEMORY" <<'EOF'
import json, sys, os, subprocess
out, model_dir, mem = sys.argv[1:4]
meta = {
    "kernel": subprocess.check_output(["uname", "-r"]).decode().strip(),
    "cgroup_memory": mem,
    "iterations": 1,
    "models": {},
}
for w in "abcdef":
    path = os.path.join(model_dir, f"ycsb_{w}", "model_weights.json")
    entry = {"model_file": path}
    mpath = os.path.join(model_dir, f"ycsb_{w}", "metrics.json")
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

run_bench() { # run_bench <policy> <benchmark_csv> [extra args...]
	local POLICY="$1" BENCH="$2"
	shift 2
	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RES" \
		--leveldb-db "$DB_PATH" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--fadvise-hints "" \
		--iterations 1 \
		--cgroup-memory "$CGROUP_MEMORY" \
		--cache-ext-only \
		--benchmark "$BENCH" \
		"$@"
}

run_workload() { # run_workload <a|b|...|f>
	local W="$1"
	for POLICY in "${POLICIES[@]}"; do
		echo "==> [ycsb_$W] policy: $POLICY"
		run_bench "$POLICY" "ycsb_$W"
	done
	echo "==> [ycsb_$W] policy: cache_ext_fifo_ml_protect (model: ycsb_$W)"
	run_bench "cache_ext_fifo_ml_protect" "ycsb_$W" \
		--model-file "$MODEL_DIR/ycsb_$W/model_weights.json"
}

if [ "$STAGE" = "1" ]; then
	run_workload a
	echo ""
	echo "==> Stage 1 complete. Gate report:"
	python3 "$BASE_DIR/lc-eval/ycsb/check_eval_results.py" "$RES" ycsb_a || true
	echo ""
	echo "Review the table above. To continue with the remaining workloads:"
	echo "  $0 $DB_PATH --stage 2 --resume"
	exit 0
fi

# --stage 2: all workloads (completed ycsb_a configs checkpoint-skip), then
# the kernel-MGLRU baseline pass.
for W in "${WORKLOADS[@]}"; do
	run_workload "$W"
done

echo "==> Running kernel-MGLRU baseline (--default-only)..."
"$BASE_DIR/utils/enable-mglru.sh"
python3 "$BENCH_PATH/bench_leveldb.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_fifo.out" \
	--results-file "$RES_MGLRU" \
	--leveldb-db "$DB_PATH" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--fadvise-hints "" \
	--iterations 1 \
	--cgroup-memory "$CGROUP_MEMORY" \
	--benchmark "$ALL_BENCHMARKS" \
	--default-only

echo ""
echo "==> Evaluation complete."
echo "Results: $RES"
echo "         $RES_MGLRU"
echo "Summarize with: python3 lc-eval/ycsb/summarize_results.py"
