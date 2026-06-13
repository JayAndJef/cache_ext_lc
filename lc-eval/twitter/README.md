# Twitter cache-trace benchmarks (LearnedCache)

Twitter production cache traces (cache_ext paper Fig 8): clusters 17, 18, 24,
34, 52 replayed against per-cluster LevelDB databases via My-YCSB's trace
replay. LC counterpart of `lc-eval/ycsb/` — same policy sweep, tracer data
collection, and ML-policy support, driven by `lc-bench/bench_twitter_trace.py`.

## Artifacts

`./download_twitter_dbs.sh` (repo root; also run by `setup_phase2.sh`)
stream-extracts from the public GCS bucket into `/mydata`:

- `/mydata/twitter-traces/cluster<N>_{init,bench,summary}.txt` — trace files
  (`bench` format: `<get|insert|update> <key>` per line; ~7 GiB total)
- `/mydata/leveldb_twitter_cluster<N>_db/` — pre-initialized LevelDB databases
  (0.15–5.9 GiB each; no `init_leveldb` step needed)

## Scripts

- `run.sh [--model-file <json>] [--clusters "17 18 24 34 52"] [--iterations 3]
  [--cgroup-size-pct 10]` — full sweep: plain-Linux baseline + all cache_ext
  policies (+ `cache_ext_fifo_ml_protect` when `--model-file` is given) with
  MGLRU disabled, then an MGLRU baseline pass. One results file per cluster:
  `results/twitter_results_<N>.json` and `results/twitter_results_<N>_mglru.json`
  (per-cluster DBs force a cluster loop, unlike the shared-DB ycsb script).
- `collect_traces.sh [--clusters ...] [--iterations 1] [--cgroup-size-pct 10]`
  — `cache_ext_fifo_lc` tracer only (`--cache-ext-only`), for training data.
  Clears `/mydata/cache_ext_logs/*` first; binary logs land in
  `/mydata/cache_ext_logs/twitter_cluster<N>_bench/iter_<I>/` — parse with
  `policies/read_binary_logs.py`.

## Differences vs the ycsb harness

- **Cgroup sizing**: not a fixed `--cgroup-memory`. Per the paper, the limit is
  computed per config as `--cgroup-size-pct` (default 10%) of the cluster DB's
  size, plus 20 MiB, floored at 70 MiB. The trace file is `cat`-preloaded into
  the page cache outside the test cgroup so trace reads aren't charged to it.
- **Throughput-only results**: both scripts build My-YCSB's `leveldb-latency`
  branch (per-op latency tracking disabled — the latency arrays would dwarf the
  tiny 70–470 MiB cgroups, as in the upstream `eval/twitter/run.sh`). Latency
  fields in the results JSON are zeros. The ycsb scripts switch the submodule
  back to `master`; branch switches use `git checkout -f` because the harness
  edits config YAMLs in-tree at runtime.
