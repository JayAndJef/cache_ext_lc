import logging
import os
from time import time
from typing import List, Dict

from bench_lib import *

log = logging.getLogger(__name__)

# These only run on error
CLEANUP_TASKS = []


class MGLRULCBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("mglru_lc_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.watch_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--watch-dir",
            type=str,
            required=True,
            help="Directory to watch for cache_ext",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--filebench-workload",
            type=str,
            required=True,
            help="Specify the path to the filebench workload file",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("passes", [10], configs)
        configs = add_config_option("cgroup_size", [1 * GiB], configs)
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )

        else:
            configs = add_config_option(
                "cgroup_name",
                [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP],
                configs,
            )

        configs = add_config_option("benchmark", ["mglru_lc"], configs)
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def before_benchmark(self, config):
        drop_page_cache()
        disable_swap()
        disable_smt()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
            self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])
        self.start_time = time()

    def benchmark_cmd(self, config):
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            "filebench",
            "-f",
            self.args.filebench_workload,
        ]
        return cmd

    def after_benchmark(self, config):
        self.end_time = time()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = {"runtime_sec": self.end_time - self.start_time}
        return BenchResults(results)


def main():
    global log
    logging.basicConfig(level=logging.DEBUG)
    global log
    # To ensure that writeback keeps up with the benchmark
    mglru_lc_bench = MGLRULCBenchmark()
    # Check that watch dir exists
    if not os.path.exists(mglru_lc_bench.args.watch_dir):
        raise Exception(
            "Watch directory not found: %s" % mglru_lc_bench.args.watch_dir
        )
    log.info("Watch directory: %s", mglru_lc_bench.args.watch_dir)
    mglru_lc_bench.benchmark()


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
