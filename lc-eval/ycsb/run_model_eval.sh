#!/bin/bash
# YCSB+LevelDB evaluation of cache_ext_fifo_ml_protect (matched model per
# workload) against the upstream cache_ext baseline policies.
#
# 1 iteration; 6 YCSB workloads (no uniform); fifo_lc and the BPF-mglru policy
# dropped; ml_protect run per-workload with its matching model from MODEL_DIR.
# Runs all 6 workloads then the kernel-MGLRU baseline pass. The ML-rank sweep
# (cache_ext_ml_sampling) is a separate step — see run_ml_sampling_eval.sh /
# reproduce_eval.sh.
#
# Results: results/ycsb_eval_results.json  (classical policies + ml_protect)
#          results/ycsb_eval_mglru.json    (kernel MGLRU baseline)
# MGLRU is disabled during cache_ext runs and ALWAYS restored to enabled on
# exit (machine default).
set -eu -o pipefail

usage() {
	echo "Usage: $0 <leveldb_db_path> [--resume] [--cgroup-memory <size>]"
	echo ""
	echo "  --resume          allow an existing results file (completed configs skip)"
	echo "  --cgroup-memory   cgroup memory limit (default: 10G)"
	echo ""
	echo "Runs all 6 YCSB workloads (5 classical policies + ml_protect with matched"
	echo "models) then the kernel-MGLRU baseline pass. Usually invoked via"
	echo "reproduce_eval.sh; the ML-rank sweep is a separate step (run_ml_sampling_eval.sh)."
	exit 1
}

if [ "$#" -lt 1 ]; then usage; fi

DB_PATH="$1"
shift

RESUME=0
CGROUP_MEMORY="10G"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--resume)        RESUME=1;           shift   ;;
		--cgroup-memory) CGROUP_MEMORY="$2"; shift 2 ;;
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

# reproduce_eval.sh exports MODEL_DIR to pass through --model-dir; default
# matches the standalone usage.
MODEL_DIR="${MODEL_DIR:-/mydata/models-jun-11}"
RES="$RESULTS_PATH/ycsb_eval_results.json"
RES_MGLRU="$RESULTS_PATH/ycsb_eval_mglru.json"
RES_LRU="$RESULTS_PATH/ycsb_eval_lru.json"

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
	for f in "$RES" "$RES_MGLRU" "$RES_LRU"; do
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

# All workloads (any completed configs checkpoint-skip), then the two
# kernel-reclaim baseline passes (Linux LRU with MGLRU off, then MGLRU on).
for W in "${WORKLOADS[@]}"; do
	run_workload "$W"
done

# baseline_pass <results_file> -- a plain-Linux (--default-only) run. The two
# baseline passes have IDENTICAL config dicts (the MGLRU on/off state isn't in
# the dict), so they MUST go to separate files or they checkpoint-collide.
baseline_pass() {
	python3 "$BENCH_PATH/bench_leveldb.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/cache_ext_fifo.out" \
		--results-file "$1" \
		--leveldb-db "$DB_PATH" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--fadvise-hints "" \
		--iterations 1 \
		--cgroup-memory "$CGROUP_MEMORY" \
		--benchmark "$ALL_BENCHMARKS" \
		--default-only
}

# Linux classic active/inactive LRU = plain-Linux baseline with MGLRU still
# OFF (the paper's "Default (Linux)"). Runs while MGLRU is disabled from the
# cache_ext policy loop above.
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
echo "         $RES_LRU   (Linux LRU baseline)"
echo "         $RES_MGLRU (kernel MGLRU baseline)"
echo "(For the full sweep incl. ML-rank factors + manifest, use reproduce_eval.sh.)"
