import argparse
import logging
import os
import re
import subprocess
from time import sleep
from typing import Dict, List

from bench_lib import *
from bench_leveldb import parse_leveldb_bench_results, reset_database


log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []


def dir_size(path: str) -> int:
    if not os.path.exists(path):
        raise Exception("Directory not found: %s" % path)
    if not os.path.isdir(path):
        raise Exception("Not a directory: %s" % path)
    cmd = ["du", "-sb", path]
    result = check_output(cmd)
    return int(result.split()[0])


def file_size(path: str) -> int:
    if not os.path.exists(path):
        raise Exception("File not found: %s" % path)
    if not os.path.isfile(path):
        raise Exception("Not a file: %s" % path)
    return os.path.getsize(path)


class LevelDBTwitterTraceBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("leveldb_twitter_trace_benchmark", benchresults_cls, cli_args)
        if self.args.leveldb_temp_db is None:
            self.args.leveldb_temp_db = self.args.leveldb_db + "_temp"
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP,
            self.args.policy_loader,
            self.args.leveldb_temp_db,
            self.args.model_file,
            extra_args=self.args.policy_extra_args,
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--leveldb-db",
            type=str,
            required=True,
            help="Specify the directory to watch for cache_ext",
        )
        parser.add_argument(
            "--leveldb-temp-db",
            type=str,
            default=None,
            help="Specify the temporary directory for LevelDB benchmarking. Default is <leveldb-db>_temp",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--bench-binary-dir",
            type=str,
            required=True,
            help="Specify the directory containing the benchmark binary",
        )
        parser.add_argument(
            "--benchmark",
            type=str,
            required=True,
            help="Specify the benchmark to run, e.g., 'twitter_cluster17_bench,twitter_cluster18_bench'",
        )
        parser.add_argument(
            "--twitter-traces-dir",
            type=str,
            required=True,
            help="Specify the directory containing Twitter trace files (cluster<N>_bench.txt)",
        )
        parser.add_argument(
            "--cgroup-size-pct",
            type=int,
            default=10,
            help="Cgroup memory limit as a percent of the cluster DB size (default: 10, as in the paper)",
        )
        parser.add_argument(
            "--cgroup-floor-mib",
            type=int,
            default=192,
            help="Minimum cgroup memory limit in MiB (default: 192). The original "
            "70 MiB floor livelocked the ML sampler and exposed the kernel "
            "sampling UAF, so the floor was raised to keep the small clusters "
            "above that pathological regime.",
        )
        parser.add_argument(
            "--model-file",
            type=str,
            default=None,
            help="Path to model weights JSON file (required for the ML policies)",
        )
        parser.add_argument(
            "--runtime-seconds",
            type=int,
            default=240,
            help="Timed benchmark duration per config (default: 240). Short runs "
            "are useful for smoke tests and overhead measurements.",
        )
        parser.add_argument(
            "--policy-extra-args",
            type=str,
            default="",
            help="Extra CLI args passed through to the policy loader verbatim, "
            "e.g. '--sample_size 30' for cache_ext_ml_sampling.",
        )
        parser.add_argument(
            "--cache-ext-only",
            action="store_true",
            default=False,
            help="Run only the cache_ext config, skipping the baseline pass. Mirror of "
            "--default-only; useful for tracer data collection where the baseline "
            "produces no trace logs and just doubles wall-clock.",
        )

    def trace_file_for(self, benchmark: str) -> str:
        # e.g. "twitter_cluster17_bench" -> <traces-dir>/cluster17_bench.txt
        cluster_match = re.search(r"cluster(\d+)", benchmark)
        if not cluster_match:
            raise Exception(
                "Could not extract cluster number from benchmark name: %s" % benchmark
            )
        return os.path.join(
            self.args.twitter_traces_dir,
            "cluster%s_bench.txt" % cluster_match.group(1),
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("enable_mmap", [False], configs)
        configs = add_config_option("runtime_seconds", [self.args.runtime_seconds], configs)
        configs = add_config_option("warmup_runtime_seconds", [45], configs)
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        configs = add_config_option(
            "cgroup_size_pct", [self.args.cgroup_size_pct], configs
        )
        configs = add_config_option(
            "cgroup_floor_mib", [self.args.cgroup_floor_mib], configs
        )
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )
        elif self.args.cache_ext_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_CACHE_EXT_CGROUP], configs
            )
        else:
            configs = add_config_option(
                "cgroup_name",
                [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP],
                configs,
            )

        policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
        for config in configs:
            if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                config["policy_loader"] = policy_loader_name

        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def benchmark_prepare(self, config):
        reset_database(self.args.leveldb_db, self.args.leveldb_temp_db)
        drop_page_cache()
        disable_swap()
        disable_smt()
        # The cgroup is sized per config as a percent of the cluster's DB plus a
        # small slack, then floored. The paper used 10% / 70 MiB, but that floor
        # put clusters 17/18/24 into a permanent reclaim-thrash regime that
        # livelocked the ML sampler and exposed the kernel sampling UAF, so both
        # the percent (--cgroup-size-pct) and the floor (--cgroup-floor-mib) are
        # now flags with relaxed defaults. The same values are used for tracer
        # collection and eval (train/serve parity on cgroup pressure).
        db_size = dir_size(self.args.leveldb_temp_db)
        cgroup_size = int(db_size * config["cgroup_size_pct"] / 100)
        cgroup_size += 20 * MiB
        cgroup_size = max(cgroup_size, self.args.cgroup_floor_mib * MiB)

        # Load the trace file into the page cache outside the test cgroup so
        # the benchmark's trace reads aren't charged against the tiny limit.
        trace_file = self.trace_file_for(config["benchmark"])
        trace_file_size = file_size(trace_file)
        run(["cat", trace_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        log.info(
            "DB size: %s, trace file size: %s, cgroup size: %s",
            format_bytes_str(db_size),
            format_bytes_str(trace_file_size),
            format_bytes_str(cgroup_size),
        )

        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=cgroup_size)

            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_fifo_lc.out":
                log_dir = "/mydata/cache_ext_logs/%s/iter_%d" % (
                    config["benchmark"], config["iteration"])
                run(["sudo", "mkdir", "-p", log_dir])
                # The bench process (non-root) opens loader.log in this dir;
                # sudo mkdir leaves it root-owned, so hand it to the bench user.
                run(["sudo", "chown", "%d:%d" % (os.getuid(), os.getgid()), log_dir])
                self.cache_ext_policy.start(log_dir=log_dir)
            elif policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=cgroup_size)
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=cgroup_size)

    def benchmark_cmd(self, config):
        bench_binary_dir = self.args.bench_binary_dir
        leveldb_temp_db_dir = self.args.leveldb_temp_db
        bench_binary = os.path.join(bench_binary_dir, "run_leveldb")
        bench_file = "../leveldb/config/%s.yaml" % config["benchmark"]
        bench_file = os.path.abspath(os.path.join(bench_binary_dir, bench_file))
        if not os.path.exists(bench_file):
            raise Exception("Benchmark file not found: %s" % bench_file)
        with edit_yaml_file(bench_file) as bench_config:
            bench_config["leveldb"]["data_dir"] = leveldb_temp_db_dir
            bench_config["workload"]["runtime_seconds"] = config["runtime_seconds"]
            bench_config["workload"]["warmup_runtime_seconds"] = config[
                "warmup_runtime_seconds"
            ]
            bench_config["workload"]["trace_file"] = self.trace_file_for(
                config["benchmark"]
            )
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            bench_binary,
            bench_file,
        ]
        return cmd

    def cmd_extra_envs(self, config):
        extra_envs = {}
        if config["enable_mmap"]:
            extra_envs["LEVELDB_MAX_MMAPS"] = "10000"
        return extra_envs

    def after_benchmark(self, config):
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_leveldb_bench_results(stdout)
        return BenchResults(results)


def main():
    global log
    twitter_bench = LevelDBTwitterTraceBenchmark()
    set_sysctl("vm.dirty_background_ratio", 1)
    set_sysctl("vm.dirty_ratio", 30)
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_background_ratio", 10))
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_ratio", 20))
    if not os.path.exists(twitter_bench.args.leveldb_db):
        raise Exception(
            "LevelDB DB directory not found: %s" % twitter_bench.args.leveldb_db
        )
    if not os.path.exists(twitter_bench.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s"
            % twitter_bench.args.bench_binary_dir
        )
    if not os.path.isdir(twitter_bench.args.twitter_traces_dir):
        raise Exception(
            "Twitter traces directory not found: %s"
            % twitter_bench.args.twitter_traces_dir
        )
    if twitter_bench.args.model_file and not os.path.exists(twitter_bench.args.model_file):
        raise Exception(
            "Model file not found: %s" % twitter_bench.args.model_file
        )
    log.info("LevelDB DB directory: %s", twitter_bench.args.leveldb_db)
    log.info("LevelDB temp DB directory: %s", twitter_bench.args.leveldb_temp_db)
    twitter_bench.benchmark()

    set_sysctl("vm.dirty_background_ratio", 10)
    set_sysctl("vm.dirty_ratio", 20)


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e
