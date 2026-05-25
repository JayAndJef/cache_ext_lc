# YCSB+LevelDB Benchmark

Runs YCSB workloads against LevelDB under all cache_ext policies, the FIFO-LC tracer, and optionally the FIFO-ML policy.

## Prerequisites

1. Running the custom `cache-ext` kernel (see repo root `install_kernel.sh`)
2. Policies built: `./build_policies.sh` from the repo root
3. A pre-populated LevelDB database at a known path (see `download_dbs.sh`)
4. For the ML policy: a trained model weights JSON file (examples in `lc-eval/fifo-ml/example-models/`)

My-YCSB is built automatically by the script.

## Usage

```sh
# Run all policies except fifo_ml (tracer data collection + comparison)
lc-eval/ycsb/run.sh <leveldb_db_path>

# Include the ML policy
lc-eval/ycsb/run.sh <leveldb_db_path> --model-file <model.json>

# Override memory limit (default 10G)
lc-eval/ycsb/run.sh <leveldb_db_path> --model-file <model.json> --cgroup-memory 4G
```

## Policies run

| Policy | Description |
|---|---|
| `cache_ext_lhd` | LHD (Least Hit Density) |
| `cache_ext_s3fifo` | S3-FIFO |
| `cache_ext_sampling` | Sampling-based |
| `cache_ext_fifo` | Plain FIFO |
| `cache_ext_mru` | MRU |
| `cache_ext_mglru` | cache_ext MGLRU implementation |
| `cache_ext_fifo_lc` | FIFO-LC tracer (emits binary access logs to `/var/log/cache_ext`) |
| `cache_ext_fifo_ml` | FIFO-ML (requires `--model-file`) |
| baseline MGLRU | Linux built-in MGLRU, run with `--default-only` |

## Workloads

`ycsb_a`, `ycsb_b`, `ycsb_c`, `ycsb_d`, `ycsb_e`, `ycsb_f`, `uniform`, `uniform_read_write`

Runtime: 240 s per workload, 45 s warmup, 3 iterations each.

## Outputs

- `results/ycsb_results.json` — all cache_ext and LC policies
- `results/ycsb_results_mglru.json` — baseline MGLRU
- `/var/log/cache_ext/<benchmark>/iter_<N>/` — binary access/insertion/eviction logs from `fifo_lc` runs, one directory per workload per iteration (e.g. `ycsb_a/iter_1/`). Parse with `policies/read_binary_logs.py`.
