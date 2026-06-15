# Twitter cache-trace benchmarks (LearnedCache)

Twitter production cache traces (cache_ext paper Fig 8): clusters 17, 18, 24,
34, 52 replayed against per-cluster LevelDB databases via My-YCSB's trace
replay. LC counterpart of `lc-eval/ycsb/` — same split between tracer **data
collection** (`collect_traces.sh`) and **benchmarking**, with the benchmarking
itself split along *needs a model or not*: heuristic policies
(`run_heuristic_eval.sh`, no model) and model policies
(`run_ml_sampling_eval.sh`), tied together by `reproduce_eval.sh` and driven by
`lc-bench/bench_twitter_trace.py`. All halves sweep the same cluster set so the
per-cluster training traces line up with the per-cluster eval.

## Artifacts

`./download_twitter_dbs.sh` (repo root; also run by `setup_phase2.sh`)
stream-extracts from the public GCS bucket into `/mydata`:

- `/mydata/twitter-traces/cluster<N>_{init,bench,summary}.txt` — trace files
  (`bench` format: `<get|insert|update> <key>` per line; ~7 GiB total)
- `/mydata/leveldb_twitter_cluster<N>_db/` — pre-initialized LevelDB databases
  (0.15–5.9 GiB each; no `init_leveldb` step needed)

## Models

The model policies (`run_ml_sampling_eval.sh`, and `reproduce_eval.sh` which
calls it) need a **matched model per cluster** at
`<model-dir>/twitter_cluster<N>_bench/model_weights.json` (the dir is keyed by
the benchmark name, like ycsb's `ycsb_a/`; default `--model-dir`:
`/mydata/models-jun-11`) and **hard-error** if any cluster's model is missing.
`run_heuristic_eval.sh` needs no model directory. Produce the models first:
`collect_traces.sh` → train per cluster with `learnedcache/evict_classifier` →
drop `model_weights.json` (and optional `metrics.json`) under
`twitter_cluster<N>_bench/`.

## Scripts

Mirrors the ycsb harness. All eval scripts loop clusters (each has its own DB)
but accumulate into one consolidated file per pass — the bench framework reuses
the `--results-file` by default, so distinct per-cluster configs all append
(same mechanism that lands every ycsb workload in one file).

Per-cluster **cgroup sizing is not a CLI flag** — it lives in
[`cgroup_sizes.sh`](cgroup_sizes.sh) (one `"<size-pct> <floor-mib>"` pair per
cluster), sourced by all four scripts so collection and eval size every cluster
identically (train/serve parity + a fair heuristic-vs-model comparison). Edit a
cluster's pair there to change its memory; a requested cluster with no entry is a
hard error.

- `collect_traces.sh [--clusters ...] [--iterations 1]` — **data collection.**
  `cache_ext_fifo_lc` tracer only (`--cache-ext-only`),
  for training data. Clears `/mydata/cache_ext_logs/*` first; binary logs land
  in `/mydata/cache_ext_logs/twitter_cluster<N>_bench/iter_<I>/` (throughput
  reference in `results/twitter_results_tracer.json`).
- `run_heuristic_eval.sh [--clusters ...] [--iterations 1] [--resume]` —
  **heuristic benchmarking (no model).**
  5 classical cache_ext policies, MGLRU off, then a Linux-LRU baseline (MGLRU
  off) and a kernel-MGLRU baseline (MGLRU on). Outputs
  `results/twitter_eval_results.json`, `..._lru.json`, `..._mglru.json`.
  `fifo_lc` and the BPF-mglru reimpl are dropped (collection is
  `collect_traces.sh`'s job now).
- `run_ml_sampling_eval.sh [--model-dir <dir>] [--clusters ...] [--iterations 1]
  [--factors "10 20 30 40"] [--resume]` — **model benchmarking.**
  `cache_ext_fifo_ml_protect` (per-cluster
  matched models) → `results/twitter_eval_protect.json`, plus the
  `cache_ext_ml_sampling` oversampling sweep (one
  `results/twitter_eval_ml<F>.json` per factor — the factor isn't in the config
  dict, so each needs its own file) and the cluster↔model map `..._meta.json`.
  Usually called via `reproduce_eval.sh`.
- `reproduce_eval.sh [--model-dir <dir>] [--clusters ...] [--iterations 1]
  [--factors "10 20 30 40"] [--fresh]`
  — **one-command orchestrator.** Sequences `run_ml_sampling_eval.sh` (ml_protect +
  the ML-rank factor sweep, one `twitter_eval_ml<F>.json` per factor) →
  `run_heuristic_eval.sh` (heuristics + LRU/MGLRU baselines) →
  `twitter_eval_manifest.json` provenance.

The notebook `visualizations/results.ipynb` is the consumer of the
`twitter_eval_*.json` files (throughput-only figures; cells skip gracefully
until the files exist).

## Differences vs the ycsb harness

- **Cgroup sizing**: not a fixed `--cgroup-memory`. The limit is computed per
  config as a **per-cluster** size-pct of the cluster DB's size, plus 20 MiB,
  floored at a **per-cluster** floor — both read from
  [`cgroup_sizes.sh`](cgroup_sizes.sh) (`CGROUP_BY_CLUSTER[<cluster>]="<pct>
  <floor-mib>"`), which is the single source of truth shared by all four
  scripts. The paper used a uniform 10% / 70 MiB, but that floor put clusters
  17/18/24 into a permanent reclaim-thrash regime that livelocked the ML sampler
  and exposed a kernel sampling-eviction UAF, so the table now defaults to
  15% / 192 MiB and per-cluster floors let small clusters (e.g. 18, ~151 MiB DB,
  which the 192 MiB floor would cache whole) be tuned down to see real eviction
  pressure. The same table drives tracer collection and eval, for train/serve
  parity. The trace file is `cat`-preloaded into the page cache outside the test
  cgroup so trace reads aren't charged to it.
- **Throughput-only results**: the Twitter scripts build My-YCSB's
  `leveldb-latency` branch (per-op latency tracking disabled — the latency
  arrays would dwarf the small 192 MiB–~1.2 GiB cgroups, as in the upstream
  `eval/twitter/run.sh`). Latency fields in the results JSON are zeros, so the
  notebook's Twitter section has no p99 panel. The ycsb scripts switch the
  submodule back to `master`; branch switches use `git checkout -f` because the
  harness edits config YAMLs in-tree at runtime.
