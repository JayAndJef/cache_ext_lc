# lc-eval/fifo — FIFO-LC Tracer Collection

> **BROKEN — `bench_fifo_lc.py` has been removed from `lc-bench/`.** This directory is superseded by `lc-eval/ycsb/`, which runs the `cache_ext_fifo_lc` policy under YCSB+LevelDB and is the current data-collection path.

## What this was

`run.sh` drove `lc-bench/bench_fifo_lc.py` (now deleted) to run the `cache_ext_fifo_lc` tracer policy against a filebench workload. It wrote binary access/insertion/eviction logs to `/var/log/cache_ext/` and results to `results/fifo_lc_results.json`.

## What to use instead

`lc-eval/ycsb/run.sh <leveldb_db_path>` runs `cache_ext_fifo_lc` as one of the benchmark policies. Logs are written to a per-workload, per-iteration directory:

```
/var/log/cache_ext/<benchmark>/iter_<N>/mglru_lc_access_<ts>.bin
/var/log/cache_ext/<benchmark>/iter_<N>/mglru_lc_insertion_<ts>.bin
/var/log/cache_ext/<benchmark>/iter_<N>/mglru_lc_eviction_<ts>.bin
```

Parse with:

```sh
policies/read_binary_logs.py --type access  <bin_file>
policies/read_binary_logs.py --type insertion <bin_file>
policies/read_binary_logs.py --type eviction  <bin_file>
```

The top-level `run_workloads.sh` in the research root is also wired to this old path — see `Vagrantfile` `run-tracers` provisioner, which still calls `lc-eval/fifo/run.sh`.
