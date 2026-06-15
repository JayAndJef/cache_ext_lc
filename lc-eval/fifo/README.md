# lc-eval/fifo — FIFO-LC Tracer Collection

> **BROKEN — `bench_fifo_lc.py` has been removed from `lc-bench/`.** This directory is superseded by `lc-eval/ycsb/`, which runs the `cache_ext_fifo_lc` policy under YCSB+LevelDB and is the current data-collection path.

## What this was

`run.sh` drove `lc-bench/bench_fifo_lc.py` (now deleted) to run the `cache_ext_fifo_lc` tracer policy against a filebench workload. It wrote binary access/insertion/eviction logs to `/mydata/cache_ext_logs/` and results to `results/fifo_lc_results.json`.

## What to use instead

`lc-eval/ycsb/collect_traces.sh <leveldb_db_path>` runs the `cache_ext_fifo_lc` tracer (there is also a Twitter variant, `lc-eval/twitter/collect_traces.sh`). Logs are written to a per-workload, per-iteration directory:

```
/mydata/cache_ext_logs/<benchmark>/iter_<N>/mglru_lc_access_<ts>.bin
/mydata/cache_ext_logs/<benchmark>/iter_<N>/mglru_lc_insertion_<ts>.bin
/mydata/cache_ext_logs/<benchmark>/iter_<N>/mglru_lc_eviction_<ts>.bin
```

The top-level `run_workloads.sh` in the research root is also wired to this old path — see `Vagrantfile` `run-tracers` provisioner, which still calls `lc-eval/fifo/run.sh`.
