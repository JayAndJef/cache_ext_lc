# YCSB+LevelDB Benchmark (LearnedCache)

Scripts for the full LearnedCache YCSB pipeline: collect tracer training data,
evaluate the trained ML policies against the classical cache_ext baselines and
the two Linux kernel baselines, and measure eviction-decision overhead. They
all drive `lc-bench/bench_leveldb.py` directly. The notebook
`visualizations/results.ipynb` is the single consumer of the result files —
there is no separate summarize script.

## Reproduce everything in one command

```sh
lc-eval/ycsb/reproduce_eval.sh /mydata/leveldb
```

This is the one-command entrypoint. From a pre-trained model set it produces
every result file deterministically, owning all the fragile bindings so they
can't drift:

- `run_model_eval.sh` → 5 classical policies (MRU, FIFO, S3-FIFO, LHD,
  LFU/sampling) + `ml_protect` with matched per-workload models, plus the two
  Linux kernel baselines: **Linux LRU** (classic active/inactive LRU, MGLRU
  off) and **kernel MGLRU** (MGLRU on).
- the **ML-rank sweep**, looped per oversampling factor, each factor to its own
  `ycsb_eval_ml<F>.json` (the factor is *not* in the bench config dict, so each
  factor must be its own file — see "Conventions" below; the orchestrator
  derives the filename from the factor so a mismatch is impossible).
- a **normalize** step that strips any legacy `ml_sampling` rows from the main
  results file (older runs wrote factor 20 there; now every factor incl. 20
  lives in its own file).
- a **manifest** (`results/ycsb_eval_manifest.json`) recording the
  file→factor/baseline map (otherwise only encoded in filenames), the git
  commit, kernel, and run args.

Options: `--model-dir <dir>` (default `/mydata/models-jun-11`),
`--cgroup-memory <size>` (default 10G), `--factors "10 20 30 40"`,
`--fresh` (delete existing result files first for a clean from-scratch
recompute, ~6–7 h; default keeps them so completed configs checkpoint-skip).

Output files in `results/`:

| file | contents |
|---|---|
| `ycsb_eval_results.json` | 5 classical policies + `ml_protect` (matched models) |
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
workload-iteration); parse with `policies/read_binary_logs.py`.

### 2. Train models (off-box)

Train one classifier per workload with `python -m evict_classifier train` in
the `learnedcache` repo, then place the artifacts on this machine as
`<model_dir>/ycsb_<w>/model_weights.json` (our run: `/mydata/models-jun-11`).

### 3. ML-protect + classical baselines + Linux baselines — `run_model_eval.sh`

```sh
lc-eval/ycsb/run_model_eval.sh /mydata/leveldb            # single pass
```

Per workload: 5 classical policies + `cache_ext_fifo_ml_protect` with its
matched per-workload model (`MODEL_DIR` env var, default `/mydata/models-jun-11`),
then the Linux-LRU baseline (MGLRU off) and the kernel-MGLRU baseline (MGLRU
on). `--resume` allows an existing results file (completed configs skip).
Outputs `ycsb_eval_results.json`, `ycsb_eval_lru.json`, `ycsb_eval_mglru.json`,
`ycsb_eval_meta.json`.

### 4. ML-rank sweep — `run_ml_sampling_eval.sh`

```sh
# args: <db> <cgroup_mem> <results_file> <log_suffix> <sample_size>
lc-eval/ycsb/run_ml_sampling_eval.sh /mydata/leveldb 10G results/ycsb_eval_ml30.json _30 30
```

Runs `cache_ext_ml_sampling` on all 6 workloads with matched models for ONE
oversampling factor. **Prefer `reproduce_eval.sh`**, which loops the factors
and derives each filename — here the results file (`$3`) and the factor (`$5`)
are independent positional args and can be mismatched.

### 5. Eviction-decision latency — `collect_evict_latency.sh`

```sh
lc-eval/ycsb/collect_evict_latency.sh /mydata/leveldb
```

Captures raw per-call `evict_folios` durations (bpf_printk → trace_pipe) for
every policy on short ycsb_a runs; one policy at a time. Raw per-tag `.trace`
files go to `results/evict_latency/`. The notebook (fig8–10) parses these
`.trace` files directly. Subset reruns: `ONLY="ml20 ml30" lc-eval/ycsb/collect_evict_latency.sh`.

## Conventions that bite

- **Checkpointing**: the bench framework silently skips configs already present
  in a results file, keyed on the config dict only. Loader-only args
  (`--model-file`, `--sample_size`) and the kernel MGLRU on/off state are NOT
  in the dict — runs differing only in those must use separate results files.
  This is why every ML-rank factor and each Linux baseline has its own file.
- **MGLRU**: must be disabled for cache_ext runs and the Linux-LRU baseline
  (the scripts handle this and restore it on exit); the kernel-MGLRU baseline
  pass re-enables it.
- Workload parameters: 240 s timed + 45 s warmup per config, 10 GiB cgroup
  default (`--cgroup-memory`).
