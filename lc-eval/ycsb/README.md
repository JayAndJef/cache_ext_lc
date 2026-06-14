# YCSB+LevelDB Benchmark (LearnedCache)

Scripts for the full LearnedCache YCSB pipeline: collect tracer training data,
evaluate the trained ML policies against the classical cache_ext baselines and
the two Linux kernel baselines, and measure eviction-decision overhead. They
all drive `lc-bench/bench_leveldb.py` directly. The notebook
`visualizations/results.ipynb` is the single consumer of the result files —
there is no separate summarize script.

The benchmarking is split along *needs a model or not* (mirrors the
[`lc-eval/twitter/`](../twitter/) harness): heuristic policies
(`run_heuristic_eval.sh`, no model) and model policies
(`run_ml_sampling_eval.sh`), tied together by `reproduce_eval.sh`. Unlike
Twitter, every workload shares one DB and a **fixed 10G cgroup**, so there is no
per-workload cgroup-sizing table.

## Reproduce everything in one command

```sh
lc-eval/ycsb/reproduce_eval.sh /mydata/leveldb
```

This is the one-command entrypoint. From a pre-trained model set it produces
every result file deterministically, owning all the fragile bindings so they
can't drift:

- `run_ml_sampling_eval.sh` → the **model** policies:
  `cache_ext_fifo_ml_protect` with its matched per-workload model →
  `ycsb_eval_protect.json`, plus the **ML-rank sweep**
  (`cache_ext_ml_sampling`), one `ycsb_eval_ml<F>.json` per oversampling factor
  (the factor is *not* in the bench config dict, so each factor must be its own
  file — see "Conventions" below; the script derives each filename from the
  factor in its loop so a mismatch is impossible), and the workload↔model map
  `ycsb_eval_meta.json`.
- `run_heuristic_eval.sh` → the **no-model** policies: 5 classical policies
  (MRU, FIFO, S3-FIFO, LHD, LFU/sampling), plus the two Linux kernel baselines:
  **Linux LRU** (classic active/inactive LRU, MGLRU off) and **kernel MGLRU**
  (MGLRU on).
- a **manifest** (`results/ycsb_eval_manifest.json`) recording the
  file→factor/baseline map (otherwise only encoded in filenames), the git
  commit, kernel, and run args.

Options: `--model-dir <dir>` (default `/mydata/models-jun-11`),
`--iterations <n>` (default 1), `--factors "10 20 30 40"`,
`--fresh` (delete existing result files first for a clean from-scratch
recompute, ~6–7 h; default keeps them so completed configs checkpoint-skip).
The cgroup limit is a fixed 10G (no `--cgroup-memory` flag).

Output files in `results/`:

| file | contents |
|---|---|
| `ycsb_eval_results.json` | 5 classical policies (heuristic, no model) |
| `ycsb_eval_protect.json` | `cache_ext_fifo_ml_protect` (matched per-workload models) |
| `ycsb_eval_ml{10,20,30,40}.json` | ML-rank, one oversampling factor each |
| `ycsb_eval_lru.json` | Linux classic LRU baseline (MGLRU off) |
| `ycsb_eval_mglru.json` | kernel MGLRU baseline (MGLRU on) |
| `ycsb_eval_meta.json` | model→workload mapping + per-model `metrics.json` (if present) |
| `ycsb_eval_manifest.json` | provenance: file→factor/baseline, git commit, args |

Then render figures (the notebook reads all of the above directly):

```sh
jupyter nbconvert --to notebook --execute --inplace visualizations/results.ipynb
# or open visualizations/results.ipynb interactively
```

## Prerequisites

1. Running the custom `cache-ext` kernel (`./setup_phase1.sh` + `./setup_phase2.sh`)
2. Policies built: `./build_policies.sh`
3. The LevelDB database at `/mydata/leveldb` (`./download_dbs.sh`)
4. Trained models at `<model-dir>/ycsb_<w>/model_weights.json` for a–f (see
   step 2 below). `reproduce_eval.sh` builds My-YCSB on the **master** branch
   itself (the twitter scripts leave the submodule on `leveldb-latency`, whose
   binary reports all latencies as zero).

## The individual steps (what reproduce_eval.sh sequences)

### 1. Tracer training data — `collect_traces.sh`

```sh
lc-eval/ycsb/collect_traces.sh /mydata/leveldb            # ycsb_a..f, 1 iter
```

Runs only the `cache_ext_fifo_lc` tracer (`--cache-ext-only`, no baseline
pass) with MGLRU disabled — the eviction log stays 0 bytes while MGLRU is
enabled. **Clears `/mydata/cache_ext_logs/*` first.** Binary logs land in
`/mydata/cache_ext_logs/<benchmark>/iter_<N>/` as
`mglru_lc_{access,insertion,eviction}_<unix_ts>.bin` (~1.6–2 GiB per
workload-iteration). Same fixed 10G cgroup as the eval (train/serve parity).

### 2. Train models (off-box)

Train one classifier per workload with `python -m evict_classifier train` in
the `learnedcache` repo, then place the artifacts on this machine as
`<model_dir>/ycsb_<w>/model_weights.json` (our run: `/mydata/models-jun-11`).

### 3. Heuristic (no-model) policies + Linux baselines — `run_heuristic_eval.sh`

```sh
lc-eval/ycsb/run_heuristic_eval.sh /mydata/leveldb [--iterations 1] [--resume]
```

The 5 classical cache_ext policies (each sweeps all 6 workloads in one batched
call, no model needed), then the Linux-LRU baseline (MGLRU off) and the
kernel-MGLRU baseline (MGLRU on). No `--model-dir`. Outputs
`ycsb_eval_results.json`, `ycsb_eval_lru.json`, `ycsb_eval_mglru.json`.
`--resume` allows existing results files (completed configs skip).

### 4. Model policies — `run_ml_sampling_eval.sh`

```sh
lc-eval/ycsb/run_ml_sampling_eval.sh /mydata/leveldb \
    [--model-dir <dir>] [--iterations 1] [--factors "10 20 30 40"] [--resume]
```

The half that takes a `--model-dir` (hard-fails if any workload's model is
missing). `cache_ext_fifo_ml_protect` per workload with its matched model →
`ycsb_eval_protect.json`, then the `cache_ext_ml_sampling` oversampling sweep
(one `ycsb_eval_ml<F>.json` per factor — the factor isn't in the config dict, so
each needs its own file; the filename is derived from the factor in the loop)
and the workload↔model map `ycsb_eval_meta.json`. Usually called via
`reproduce_eval.sh`.

### 5. Eviction-decision latency — `collect_evict_latency.sh`

```sh
lc-eval/ycsb/collect_evict_latency.sh /mydata/leveldb
```

Captures raw per-call `evict_folios` durations (bpf_printk → trace_pipe) for
every policy on short ycsb_a runs; one policy at a time. Raw per-tag `.trace`
files go to `results/evict_latency/`. The notebook (fig8–10) parses these
`.trace` files directly. Subset reruns: `ONLY="ml20 ml30" lc-eval/ycsb/collect_evict_latency.sh`.
YCSB-only (no Twitter counterpart).

## Conventions that bite

- **Checkpointing**: the bench framework silently skips configs already present
  in a results file, keyed on the config dict only. Loader-only args
  (`--model-file`, `--sample_size`) and the kernel MGLRU on/off state are NOT
  in the dict — runs differing only in those must use separate results files.
  This is why every ML-rank factor and each Linux baseline has its own file,
  and why `ml_protect` lives in `ycsb_eval_protect.json` rather than the shared
  results file. Each output file is owned by exactly one script.
- **First run after the heuristic/model split**: use `--fresh` (or delete the
  old `ycsb_eval_results.json`). A pre-split results file still carries
  `ml_protect` rows; with the new `ycsb_eval_protect.json` also loaded, a
  non-fresh run would double-count `ml_protect` in the notebook.
- **MGLRU**: must be disabled for cache_ext runs and the Linux-LRU baseline
  (the scripts handle this and restore it on exit); the kernel-MGLRU baseline
  pass re-enables it.
- Workload parameters: 240 s timed + 45 s warmup per config, **fixed 10 GiB
  cgroup** (no `--cgroup-memory` flag; `bench_leveldb.py` still accepts one for
  direct invocation).
