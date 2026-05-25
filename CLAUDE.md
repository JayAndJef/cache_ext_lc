# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

LearnedCache: eBPF page-cache eviction policies built on top of `cache_ext` (SOSP '25). This is a fork of the upstream cache_ext repo with two added policies in `policies/` — `cache_ext_fifo_lc` (tracer / FIFO baseline that emits training data) and `cache_ext_fifo_ml` (FIFO variant that scores pages with a JSON-loaded model). LearnedCache-specific harnesses live in `lc-bench/` and `lc-eval/`. The original cache_ext experiments still live in `bench/` and `eval/` and are not the focus of this fork.

## Hard environmental requirement

All policy builds and runs must happen on the custom `cache-ext` Linux kernel. Both `build_policies.sh` and the `lc-eval/*/run.sh` scripts hard-fail if `uname -r` does not contain `cache-ext`. First-time setup is `./install_kernel.sh` followed by a reboot into "Ubuntu, with Linux 6.6.8-cache-ext+" (see README). Submodules (`linux/`, `leveldb/`, `rocksdb/`, `My-YCSB/`) must be initialized via `git submodule update --init --recursive` — the kernel fork lives in `linux/`.

## Common commands

- Build all BPF policies + userspace loaders: `./build_policies.sh` (wraps `make -C policies -j`). Outputs `policies/<name>.out` binaries. Clean with `make -C policies clean`.
- Regenerate `policies/vmlinux.h` (rare): delete it; the Makefile rebuilds it via `bpftool btf dump`.
- **YCSB+LevelDB (primary benchmark)**: `lc-eval/ycsb/run.sh <leveldb_db_path> [--model-file <model.json>] [--cgroup-memory 10G]`. Runs all cache_ext policies + `fifo_lc` tracer. Adds `fifo_ml` only when `--model-file` is given; errors if that flag is passed to a non-ML invocation. Results go to `results/ycsb_results.json` and `results/ycsb_results_mglru.json`. See `lc-eval/ycsb/README.md` for full details.
- **filebench tracer** (raw data collection): `lc-eval/fifo/run.sh <workload.f> [cgroup_memory]` — binary logs to `/var/log/cache_ext/`. `lc-eval/fifo-ml/run.sh <workload.f> <model.json> [cgroup_memory]` — ML policy. Workloads in `lc-eval/filebench-workloads/` (sizing notes in `workload-usages.txt`); example models in `lc-eval/fifo-ml/example-models/`.
- **Parse tracer binary logs to CSV**: `policies/read_binary_logs.py`. The struct layouts at the top of that file (`FORMAT = '<QQQQQIIQQI4xQII'`) must stay in sync with `struct cache_access_fields` in both the `.bpf.c` and `.c` for each policy — if you change one, change all three.
- **Run YCSB bench directly**: `python3 lc-bench/bench_leveldb.py --policy-loader policies/<policy>.out --leveldb-db <db> --bench-binary-dir My-YCSB/build --benchmark ycsb_a,... [--model-file <json>] [--cgroup-memory 10G]`. Pass `--model-file` only with `cache_ext_fifo_ml.out`.

## Policy code architecture

Each policy is a pair of files in `policies/`:

- `cache_ext_<name>.bpf.c` — kernel-side eBPF program. Implements the `cache_ext_ops` struct_ops (eviction/insertion/access callbacks) that the cache_ext kernel calls from the page-cache hot path. Includes `cache_ext_lib.bpf.h` (shared helpers/macros, including `BPF_STRUCT_OPS`) and `dir_watcher.bpf.h` (filters events to pages whose inode is under the configured watch directory).
- `cache_ext_<name>.c` — userspace loader. Opens the generated `<name>.skel.h`, sets `skel->rodata->watch_dir_path`, attaches struct_ops to a cgroup fd, populates `inode_watchlist` via `initialize_watch_dir_map` (from `dir_watcher.h`), and (for tracer/ML variants) polls ring buffers and writes binary event logs.

The Makefile pipeline is: `clang -target bpf` produces `<name>.bpf.o`, `bpftool gen skeleton` produces `<name>.skel.h`, then `<name>.c` is compiled and linked against `libbpf` (and `libjson-c` for the `_ml` variant — see the explicit Makefile rule for `cache_ext_fifo_ml.out`). BPF caps the watch directory path at 128 chars.

The two LearnedCache policies share infrastructure with the upstream policies (mglru, lhd, mru, s3fifo, sampling, get_scan) — when changing shared helpers in `cache_ext_lib.bpf.h` or `dir_watcher.*`, verify all `.bpf.c` files still build.

## Benchmark harness architecture

`lc-bench/bench_lib.py` is the single shared library for all LC benchmarks. It is the upstream `bench/bench_lib.py` plus two additions: `MiB` constant and `parse_memory_string()`. The `CacheExtPolicy` class accepts an optional `model_file=None` fourth argument — when set, it passes `--model_file` to the policy loader subprocess. `stop()` sends SIGINT to the sudo process and waits, matching upstream behavior. `bench_lib_ml.py` (the old ML-only fork) is kept for the filebench harnesses but should not be used for new code.

`lc-bench/bench_leveldb.py` is the single YCSB+LevelDB benchmark script for all policies. Key behaviors vs the upstream `bench/bench_leveldb.py`:
- `--cgroup-memory` replaces the hardcoded `10 * GiB` (default still 10G)
- `--model-file` is optional; only needed for `cache_ext_fifo_ml.out` — the `CacheExtPolicy` forwards it to the loader
- `--fadvise-hints` and `--default-only` are preserved for baseline comparison
- s3fifo special case (passes `cgroup_size` to loader) is preserved

The framework flow per config: rsync original DB → temp copy, drop page cache, disable swap/SMT, recreate cgroup, start policy loader (10 s sleep for attach), run `cgexec … run_leveldb`, stop loader (SIGINT + wait), checkpoint JSON results.

Known wart: the filebench `lc-eval/fifo/run.sh` and `lc-eval/fifo-ml/run.sh` end with `sudo rm /home/vagrant/cache_ext_lc/results/*.json` — a hardcoded vagrant path.
