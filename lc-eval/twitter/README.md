# Twitter cache-trace benchmarks (LearnedCache)

Twitter production cache traces (cache_ext paper Fig 8): clusters 17, 18, 24,
34, 52 replayed against per-cluster LevelDB databases via My-YCSB's trace
replay. LC counterpart of `lc-eval/ycsb/` — same split between tracer **data
collection** (`collect_traces.sh`) and **model benchmarking**
(`run_model_eval.sh` / `run_ml_sampling_eval.sh` / `reproduce_eval.sh`), driven
by `lc-bench/bench_twitter_trace.py`. Both halves sweep the same cluster set so
the per-cluster training traces line up with the per-cluster eval.

## Artifacts

`./download_twitter_dbs.sh` (repo root; also run by `setup_phase2.sh`)
stream-extracts from the public GCS bucket into `/mydata`:

- `/mydata/twitter-traces/cluster<N>_{init,bench,summary}.txt` — trace files
  (`bench` format: `<get|insert|update> <key>` per line; ~7 GiB total)
- `/mydata/leveldb_twitter_cluster<N>_db/` — pre-initialized LevelDB databases
  (0.15–5.9 GiB each; no `init_leveldb` step needed)

## Models

Eval (`run_model_eval.sh`, `run_ml_sampling_eval.sh`, `reproduce_eval.sh`) needs
a **matched model per cluster** at
`<model-dir>/twitter_cluster<N>/model_weights.json` (default `--model-dir`:
`/mydata/models-jun-11`). The scripts **hard-error** if any cluster's model is
missing. Produce them first: `collect_traces.sh` → train per cluster with
`learnedcache/evict_classifier` → drop `model_weights.json` (and optional
`metrics.json`) under `twitter_cluster<N>/`.

## Scripts

Mirrors the ycsb harness. All eval scripts loop clusters (each has its own DB)
but accumulate into one consolidated file per pass — the bench framework reuses
the `--results-file` by default, so distinct per-cluster configs all append
(same mechanism that lands every ycsb workload in one file).

- `collect_traces.sh [--clusters ...] [--iterations 1] [--cgroup-size-pct 10]`
  — **data collection.** `cache_ext_fifo_lc` tracer only (`--cache-ext-only`),
  for training data. Clears `/mydata/cache_ext_logs/*` first; binary logs land
  in `/mydata/cache_ext_logs/twitter_cluster<N>_bench/iter_<I>/` (throughput
  reference in `results/twitter_results_tracer.json`) — parse logs with
  `policies/read_binary_logs.py`.
- `run_model_eval.sh [--model-dir <dir>] [--clusters ...] [--iterations 3]
  [--cgroup-size-pct 10] [--resume]` — **model benchmarking.** 5 classical
  policies + `cache_ext_fifo_ml_protect` (per-cluster matched model), MGLRU off,
  then a Linux-LRU baseline (MGLRU off) and a kernel-MGLRU baseline (MGLRU on).
  Outputs `results/twitter_eval_results.json`, `..._lru.json`, `..._mglru.json`,
  `..._meta.json` (cluster↔model map). `fifo_lc` and the BPF-mglru reimpl are
  dropped (collection is `collect_traces.sh`'s job now).
- `run_ml_sampling_eval.sh --sample-size <F> [--results-file <path>] ...` —
  **model benchmarking (ML-rank).** `cache_ext_ml_sampling` at one oversampling
  factor, per-cluster matched models. Defaults the output to
  `results/twitter_eval_ml<F>.json` (the factor isn't in the config dict, so
  each factor needs its own file). Usually called via `reproduce_eval.sh`.
- `reproduce_eval.sh [--model-dir <dir>] [--clusters ...] [--cgroup-size-pct 10]
  [--iterations 3] [--factors "10 20 30 40"] [--fresh]` — **one-command
  orchestrator.** Sequences `run_model_eval.sh` + the ML-rank factor sweep (one
  `twitter_eval_ml<F>.json` per factor) + `twitter_eval_manifest.json`
  provenance.

The notebook `visualizations/results.ipynb` is the consumer of the
`twitter_eval_*.json` files (throughput-only figures; cells skip gracefully
until the files exist).

## Differences vs the ycsb harness

- **Cgroup sizing**: not a fixed `--cgroup-memory`. Per the paper, the limit is
  computed per config as `--cgroup-size-pct` (default 10%) of the cluster DB's
  size, plus 20 MiB, floored at 70 MiB. The trace file is `cat`-preloaded into
  the page cache outside the test cgroup so trace reads aren't charged to it.
- **Throughput-only results**: the Twitter scripts build My-YCSB's
  `leveldb-latency` branch (per-op latency tracking disabled — the latency
  arrays would dwarf the tiny 70–470 MiB cgroups, as in the upstream
  `eval/twitter/run.sh`). Latency fields in the results JSON are zeros, so the
  notebook's Twitter section has no p99 panel. The ycsb scripts switch the
  submodule back to `master`; branch switches use `git checkout -f` because the
  harness edits config YAMLs in-tree at runtime.
