# lc-eval/fifo-ml — FIFO-ML Evaluation

> **BROKEN — `bench_fifo_ml.py` has been removed from `lc-bench/`.** This directory is superseded by `lc-eval/ycsb/`, which runs the `cache_ext_fifo_ml` policy under YCSB+LevelDB and is the current ML evaluation path.

## What this was

`run.sh` drove `lc-bench/bench_fifo_ml.py` (now deleted) to run the `cache_ext_fifo_ml` policy against a filebench workload with a JSON model file. It wrote results to `results/fifo_ml_results.json`.

## What to use instead

`lc-eval/ycsb/run.sh <leveldb_db_path> --model-file <model.json>` includes `cache_ext_fifo_ml` as a benchmark policy when `--model-file` is provided.

Model files are in `lc-eval/fifo-ml/example-models/` — this directory still serves as model storage.

The top-level `run_model_workloads.sh` in the research root is also wired to this old path — see `Vagrantfile` `run-tracers-ml` provisioner, which still calls `lc-eval/fifo-ml/run.sh`.
