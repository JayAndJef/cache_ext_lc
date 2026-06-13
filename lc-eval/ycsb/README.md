# YCSB+LevelDB Benchmark (LearnedCache)

Scripts for the full LearnedCache YCSB pipeline: collect tracer training data,
evaluate the trained ML policies against the classical cache_ext baselines,
and measure eviction-decision overhead. All of them drive
`lc-bench/bench_leveldb.py` directly.

(The former `run.sh` generic full-sweep runner was removed — every result in
`results/` was produced by the scripts below. Its Twitter-side equivalent
lives on as `lc-eval/twitter/run.sh`.)

## Prerequisites

1. Running the custom `cache-ext` kernel (`./setup_phase1.sh` + `./setup_phase2.sh`)
2. Policies built: `./build_policies.sh`
3. The LevelDB database at `/mydata/leveldb` (`./download_dbs.sh`)
4. My-YCSB built on the **master** branch (the scripts check/rebuild this
   themselves; the twitter scripts leave the submodule on `leveldb-latency`,
   whose binary reports all latencies as zero)

## Reproducing our results, in order

### 1. Tracer training data — `collect_traces.sh`

```sh
lc-eval/ycsb/collect_traces.sh /mydata/leveldb            # ycsb_a..f, 1 iter
```

Runs only the `cache_ext_fifo_lc` tracer (`--cache-ext-only`, no baseline
pass) with MGLRU disabled — the eviction log stays 0 bytes while MGLRU is
enabled. **Clears `/mydata/cache_ext_logs/*` first.** Binary logs land in
`/mydata/cache_ext_logs/<benchmark>/iter_<N>/` as
`mglru_lc_{access,insertion,eviction}_<unix_ts>.bin` (~1.6–2 GiB per
workload-iteration); parse with `policies/read_binary_logs.py`.

### 2. Train models (off-box)

Train one classifier per workload with `python -m evict_classifier train` in
the `learnedcache` repo, then place the artifacts on this machine as
`<model_dir>/ycsb_<w>/model_weights.json` (our run: `/mydata/models-jun-11`).
Sanity-check a file with `lc-eval/ycsb/validate_model_json.py`.

### 3. ML-protect vs classical baselines — `run_model_eval.sh`

```sh
lc-eval/ycsb/run_model_eval.sh /mydata/leveldb --stage 1            # gate: ycsb_a only
lc-eval/ycsb/run_model_eval.sh /mydata/leveldb --stage 2 --resume   # remaining workloads + kernel MGLRU
```

Per workload: 5 classical policies (mru, fifo, s3fifo, lhd, sampling/LFU) +
`cache_ext_fifo_ml_protect` with its **matched** per-workload model
(`MODEL_DIR` is set in the script). Stage 1 prints a gate report
(`check_eval_results.py`) and exits for review. Outputs:

- `results/ycsb_eval_results.json` — all cache_ext policies + ML
- `results/ycsb_eval_mglru.json` — kernel-MGLRU baseline (`--default-only`)
- `results/ycsb_eval_meta.json` — model-file → workload mapping (the bench
  config dicts don't record `--model-file`, so this is the attribution record)

### 4. ML-rank (sampled, model-scored eviction) — `run_ml_sampling_eval.sh`

```sh
# args: <db> <cgroup_mem> <results_override> <log_suffix> <sample_size>
lc-eval/ycsb/run_ml_sampling_eval.sh /mydata/leveldb 10G "" "" ""                                # default factor (20)
lc-eval/ycsb/run_ml_sampling_eval.sh /mydata/leveldb 10G results/ycsb_eval_ml30.json _30 30      # factor 30
```

Runs `cache_ext_ml_sampling` on all 6 workloads with matched models. The
oversampling factor is not in the bench config dicts, so **each factor needs
its own results file** or completed configs checkpoint-collide. Our runs:
factor 20 appended to `ycsb_eval_results.json`; factors 10/30/40 are
`results/ycsb_eval_ml{10,30,40}.json`.

### 5. Eviction-decision latency — `collect_evict_latency.sh`

```sh
lc-eval/ycsb/collect_evict_latency.sh /mydata/leveldb
python3 lc-eval/ycsb/summarize_evict_latency.py
```

Captures raw per-call `evict_folios` durations (bpf_printk → trace_pipe) for
every policy on short ycsb_a runs; one policy at a time. Raw samples and the
summary table go to `results/evict_latency/` (`<tag>_samples.csv`,
`evict_latency.{md,csv}`). Subset reruns: `ONLY="ml20 ml30" lc-eval/ycsb/collect_evict_latency.sh`.

### 6. Summarize & visualize

```sh
python3 lc-eval/ycsb/summarize_results.py    # -> results/ycsb_eval_summary.csv
# figures: run visualizations/results.ipynb (reads the results/*.json above)
```

The consolidated write-up of our runs is `results/ycsb_eval_report.md`.

## Conventions that bite

- **Checkpointing**: the bench framework silently skips configs already
  present in a results file, keyed on the config dict only. Loader-only args
  (`--model-file`, `--sample_size`) are NOT in the dict — runs differing only
  in those must use separate results files.
- **MGLRU**: must be disabled for cache_ext runs (the scripts handle this and
  restore it on exit); the kernel-MGLRU baseline pass re-enables it.
- Workload parameters: 240 s timed + 45 s warmup per config, 10 GiB cgroup
  default (`--cgroup-memory`).
