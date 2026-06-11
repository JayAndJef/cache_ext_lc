# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

LearnedCache: eBPF page-cache eviction policies built on top of `cache_ext` (SOSP '25). This is a fork of the upstream cache_ext repo with two added policies in `policies/` — `cache_ext_fifo_lc` (the tracer that emits training data and serves as the LFU-ish baseline) and `cache_ext_fifo_ml_protect` (the model policy: skip-in-place eviction driven by a binary reuse classifier — predicted-reused folios are protected and rotate to the back of the list; the rest are evicted stalest-first). The earlier Gen-5 pairwise ranker policy (`cache_ext_fifo_ml`) has been removed. LearnedCache-specific harnesses live in `lc-bench/` and `lc-eval/`. The original cache_ext experiments still live in `bench/` and `eval/` and are not the focus of this fork.

## Hard environmental requirement

All policy builds and runs must happen on the custom `cache-ext` Linux kernel. Both `build_policies.sh` and the `lc-eval/*/run.sh` scripts hard-fail if `uname -r` does not contain `cache-ext`. First-time setup is two manual scripts (no cron): `./setup_phase1.sh` installs the kernel and reboots, then after the reboot you run `./setup_phase2.sh` to perform all remaining install steps (see README). To run individual steps manually, see the `install_*.sh` scripts. Submodules (`linux/`, `leveldb/`, `rocksdb/`, `My-YCSB/`) must be initialized via `git submodule update --init --recursive` — the kernel fork lives in `linux/`. On cloud machines, `/mydata` is typically root-owned — run `sudo chown -R $USER:$(id -gn) /mydata` before cloning.

## Common commands

- **Setup (two manual scripts, no cron)**: `./setup_phase1.sh` (no cache-ext kernel yet) installs the kernel, selects it via `grub-reboot`, and reboots. After the reboot, `./setup_phase2.sh` runs `install_misc.sh`, `download_dbs.sh`, `install_leveldb.sh`, `install_ycsb.sh`, `build_policies.sh` in order (hard-fails if not on the cache-ext kernel).
- Build all BPF policies + userspace loaders: `./build_policies.sh` (wraps `make -C policies -j`). Outputs `policies/<name>.out` binaries. Clean with `make -C policies clean`.
- Regenerate `policies/vmlinux.h` (rare): delete it; the Makefile rebuilds it via `bpftool btf dump`.
- **YCSB+LevelDB (primary benchmark)**: `lc-eval/ycsb/run.sh <leveldb_db_path> [--model-file <model.json>] [--cgroup-memory 10G]`. Runs all cache_ext policies + `fifo_lc` tracer. Adds `fifo_ml_protect` only when `--model-file` is given. Results go to `results/ycsb_results.json` and `results/ycsb_results_mglru.json`. Binary logs from `fifo_lc` go to `/mydata/cache_ext_logs/<benchmark>/iter_<N>/` with three files per iteration, named `mglru_lc_{access,insertion,eviction}_{unix_ts}.bin`. Read with `policies/read_binary_logs.py` (struct layouts must match). See `lc-eval/ycsb/README.md` for full details.
- **filebench tracer** (`lc-eval/fifo/`): legacy/broken — the bench scripts it depended on were removed (and the ranker-era `lc-eval/fifo-ml/` harness was deleted). Use `lc-eval/ycsb/` instead.
- **Parse tracer binary logs to CSV**: `policies/read_binary_logs.py`. The struct layouts at the top of that file (`FORMAT = '<QQQQQIIQQI4xQII'`) must stay in sync with `struct cache_access_fields` in both the `.bpf.c` and `.c` for each policy — if you change one, change all three.
- **Run YCSB bench directly**: `python3 lc-bench/bench_leveldb.py --policy-loader policies/<policy>.out --leveldb-db <db> --bench-binary-dir My-YCSB/build --benchmark ycsb_a,... [--model-file <json>] [--cgroup-memory 10G]`. Pass `--model-file` only with `cache_ext_fifo_ml_protect.out` (the `CacheExtPolicy` forwards it to the loader); `lc-eval/ycsb/run.sh` wires this up automatically when `--model-file` is given.

### Running the tracer for training data (resume notes)

To collect `cache_ext_fifo_lc` training logs without the full 8-policy `run.sh`
sweep, run the tracer alone via `bench_leveldb.py` — but `run.sh` is the only
path that disables MGLRU, and **the eviction log stays 0 bytes while MGLRU is
enabled** (cgroup reclaim takes the MGLRU path and never reaches cache_ext's
`evict_folios`). So a manual direct run must wrap the bench with the mglru
toggles:

```bash
sudo rm -rf /mydata/cache_ext_logs/*          # avoid mixing prior runs into training data
utils/disable-mglru.sh                         # /sys/.../lru_gen/enabled -> 0x0000
python3 lc-bench/bench_leveldb.py \
    --cpu 8 --policy-loader policies/cache_ext_fifo_lc.out \
    --results-file results/ycsb_results_tracer.json \
    --leveldb-db /mydata/leveldb --bench-binary-dir My-YCSB/build \
    --fadvise-hints "" --iterations 1 --cgroup-memory 10G \
    --benchmark "ycsb_c,ycsb_b,ycsb_e"
utils/enable-mglru.sh                          # restore default -> 0x0007
```

- **Workloads run so far:** `ycsb_c,ycsb_b,ycsb_e` (read/scan subset). Full set is
  `ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f,uniform,uniform_read_write` — extend
  by adding to `--benchmark` (skip workloads already collected to save disk).
- **Disk budget:** ~1.6–2 GiB of logs per workload-iteration; `/mydata` had ~44
  GiB free, so the full 8 workloads × 3 iters (~48 GiB) does NOT fit — use 1
  iteration and/or a subset. Logs land in
  `/mydata/cache_ext_logs/<benchmark>/iter_<N>/` (three `mglru_lc_{access,
  insertion,eviction}_*.bin` per dir). Parse with `policies/read_binary_logs.py`.
- These steps mirror what `lc-eval/ycsb/run.sh` does around its policy loop; the
  full debugging history that made this work is in `SETUP_PHASE2_NOTES.md`.
- **Baseline phase is wasted work for tracing — skip it next time.** Without
  `--default-only`, `generate_configs` (`bench_leveldb.py:191-211`) pairs *two*
  configs per workload: a `baseline_test` (plain-Linux, no `policy_loader`) and
  the `cache_ext_test` (the tracer). The baseline produces **no** `.bin` trace
  files — only throughput numbers in the results JSON we don't need for training
  — so it just ~doubles wall-clock. There is no built-in "cache-ext-only" flag
  (`--default-only` is the opposite, baseline-only). To collect traces faster,
  add a small harness option (e.g. only emit `DEFAULT_CACHE_EXT_CGROUP` in the
  `else` branch) so future tracer runs skip the baseline pass entirely.
- **Temp DB lifecycle:** `reset_database` (`bench_leveldb.py:16`, called per-config
  from `benchmark_prepare`) does `rm -rf "$TEMP"; cp -al ...` at the *start* of
  every config, so `<db>_temp` is wiped/recreated before each workload and never
  accumulates. Nothing deletes it at the *end* of a run — the last config's temp
  lingers, but as a `cp -al` hardlink clone it costs only ~376 MB real (shared
  `.ldb` inodes), not 109 GiB. Remove with `sudo rm -rf /mydata/leveldb_temp`
  only if you want that back immediately; the next run resets it regardless.

## Policy code architecture

Each policy is a pair of files in `policies/`:

- `cache_ext_<name>.bpf.c` — kernel-side eBPF program. Implements the `cache_ext_ops` struct_ops (eviction/insertion/access callbacks) that the cache_ext kernel calls from the page-cache hot path. Includes `cache_ext_lib.bpf.h` (shared helpers/macros, including `BPF_STRUCT_OPS`) and `dir_watcher.bpf.h` (filters events to pages whose inode is under the configured watch directory).
- `cache_ext_<name>.c` — userspace loader. Opens the generated `<name>.skel.h`, sets `skel->rodata->watch_dir_path`, attaches struct_ops to a cgroup fd, populates `inode_watchlist` via `initialize_watch_dir_map` (from `dir_watcher.h`), and (for tracer/ML variants) polls ring buffers and writes binary event logs.

The Makefile pipeline is: `clang -target bpf` produces `<name>.bpf.o`, `bpftool gen skeleton` produces `<name>.skel.h`, then `<name>.c` is compiled and linked against `libbpf` (and `libjson-c` for the model policy — see the explicit Makefile rule for `cache_ext_fifo_ml_protect.out`). BPF caps the watch directory path at 128 chars.

The LearnedCache policies share infrastructure with the upstream policies (mglru, lhd, mru, s3fifo, sampling, get_scan) — when changing shared helpers in `cache_ext_lib.bpf.h` or `dir_watcher.*`, verify all `.bpf.c` files still build.

### Kernel list-eviction kfuncs (read before designing an evict callback)

From `linux/mm/cache_ext_ds.c` — these semantics are non-obvious and shape policy design:

- `bpf_cache_ext_list_iterate_extended` (what `fifo_ml_protect` uses): walks the list **head-first** (oldest first), calling the callback per node; the callback returns `CACHE_EXT_EVICT_NODE` / `CACHE_EXT_SKIP_NODE` / `CACHE_EXT_CONTINUE_ITER` / `CACHE_EXT_STOP_ITER`, and `cache_ext_iterate_opts` says where each class of node moves (e.g. skip → tail = rotate in place). A scan is capped at **4096 nodes** (`max_iter`) and **32 victims** (the eviction ctx array); the callback cannot see the eviction ctx, so any stop-at-quota condition must live in policy globals (see the s3fifo multi-pass pattern).
- `bpf_cache_ext_list_sample` (used by the upstream sampling policies): pops `request_nr × sample_size` folios from the front, selects the **min-score of each consecutive `sample_size` group** (no global ordering), puts all sampled nodes back at the tail. `S64_MAX` is not a skip sentinel — a whole-`S64_MAX` group still yields a victim (reclaim re-validates downstream). Negative scores are fine.

### cache_ext_fifo_ml_protect (binary reuse classifier, skip-in-place)

Single FIFO list; no model at insertion. Eviction is a head-first scan via `bpf_cache_ext_list_iterate_extended` — no oversampling; the scan stops as soon as `request_nr_folios_to_evict` victims are gathered (`evict_target`/`evict_count` globals, since the callback can't see the ctx):

- not evictable (dirty/locked/etc.) → `CONTINUE` (rotated to the tail like everything else scanned)
- predicted reused (`logit + bias > threshold` via `compute_feature_score`/`discretize_feature`) → `SKIP` (rotated to the tail — CLOCK-style second chance)
- predicted not reused → `EVICT` (head-first order = stalest-in-rotation first; no score shaping or TSA tiebreak needed)
- untracked (never accessed since insertion — state is created only at `folio_accessed` — or lost to per_folio_map LRU overflow) → never protected, so evicted on first encounter (the model never scores pages without access history)

If pass 1 exhausts its 4096-node scan budget before filling the quota (nearly everything predicted-reused), a **fallback pass** evicts head-first ignoring the model, so reclaim always makes progress.

`bias_int`/`threshold_int` come from the model JSON (top-level fields the classifier exporter adds; the loader puts them in `model_meta_map[0]`). Models are trained by `learnedcache/evict_classifier` (`python -m evict_classifier train`); see `learnedcache/evict_classifier/KNOWN_ISSUES.md` for documented train/serve feature skews (inode-level features are read at eviction time but were trained as-of the page's last access).

### Insertion/eviction-independent feature state (both LC policies)

In `cache_ext_fifo_lc` AND `cache_ext_fifo_ml_protect`, the feature maps (`per_folio_map`, `per_file_map`) are written **only at `folio_accessed`**:

- `folio_added` mutates no maps (the tracer still logs the insertion event to `rb_insertion`; the protect policy just appends to its list).
- `folio_evicted` mutates no maps — a page's access history persists across evictions, so a re-inserted page's `pd`/`fq`/... reflect its real access gaps. Long-idle entries are forgotten by the maps' LRU eviction.

This makes every feature a pure function of the access stream, decoupling both the logged training data and runtime scoring from insertion dynamics (readahead, evict/re-insert cycles of whichever policy ran). **Parity rule:** the `track_folio_access` state machine must stay identical between the two `.bpf.c` files — train/serve parity lives entirely in that shared logic; if you change one copy, change the other. **Trace provenance:** traces collected before this purge (e.g. `tracer-bundle-may-28`) carry feature fields computed under the old insertion-coupled semantics — retrain on freshly collected traces for honest models.

## Benchmark harness architecture

`lc-bench/bench_lib.py` is the single shared library for all LC benchmarks. It is the upstream `bench/bench_lib.py` plus two additions: `MiB` constant and `parse_memory_string()`. The `CacheExtPolicy` class accepts an optional `model_file=None` fourth argument — when set, it passes `--model_file` to the policy loader subprocess. `start()` accepts an optional `log_dir` argument — when set, passes `--log_dir` to the loader; only `cache_ext_fifo_lc.out` supports this flag. `stop()` sends SIGINT to the sudo process and waits, matching upstream behavior.

`lc-bench/bench_leveldb.py` is the single YCSB+LevelDB benchmark script for all policies. Key behaviors vs the upstream `bench/bench_leveldb.py`:
- `--cgroup-memory` replaces the hardcoded `10 * GiB` (default still 10G)
- `--model-file` is optional; only needed for `cache_ext_fifo_ml_protect.out` — the `CacheExtPolicy` forwards it to the loader
- `--fadvise-hints` and `--default-only` are preserved for baseline comparison
- s3fifo special case (passes `cgroup_size` to loader) is preserved

The framework flow per config: rsync original DB → temp copy, drop page cache, disable swap/SMT, recreate cgroup, start policy loader (10 s sleep for attach), run `cgexec … run_leveldb`, stop loader (SIGINT + wait), checkpoint JSON results. For `cache_ext_fifo_lc.out` specifically, `benchmark_prepare` also creates `/mydata/cache_ext_logs/<benchmark>/iter_<N>/` and passes it as `--log_dir`, so each workload+iteration gets its own log directory.
