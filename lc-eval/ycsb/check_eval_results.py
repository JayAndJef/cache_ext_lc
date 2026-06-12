#!/usr/bin/env python3
"""Stage-1 gate report for the model-policy evaluation.

Reads the eval results JSON, prints the per-policy table for one workload and
checks for anomalies:
  - expected number of cache_ext entries with the expected policy loaders
  - all throughput_avg finite and > 0
  - ml_protect's rank among the policies (flagged if worst)

Exit codes: 0 = clean and ml_protect not worst, 1 = anomalies or ml worst.

Usage: check_eval_results.py <results.json> <benchmark> [--quiet]
"""

import json
import math
import sys

EXPECTED_LOADERS = [
    "cache_ext_mru.out",
    "cache_ext_fifo.out",
    "cache_ext_s3fifo.out",
    "cache_ext_lhd.out",
    "cache_ext_sampling.out",
    "cache_ext_fifo_ml_protect.out",
]

LABELS = {
    "cache_ext_mru.out": "MRU (cache_ext)",
    "cache_ext_fifo.out": "FIFO (cache_ext)",
    "cache_ext_s3fifo.out": "S3-FIFO (cache_ext)",
    "cache_ext_lhd.out": "LHD (cache_ext)",
    "cache_ext_sampling.out": "LFU (cache_ext)",
    "cache_ext_fifo_ml_protect.out": "ML (ours)",
}

ML = "cache_ext_fifo_ml_protect.out"


def latency_p99(results):
    # READ p99 is 0.0 on scan-only workloads (ycsb_e); fall back to scan p99.
    lat = results.get("latency_p99") or 0.0
    if lat == 0.0:
        lat = results.get("scan_latency_p99") or 0.0
    return lat


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    path, benchmark = sys.argv[1], sys.argv[2]

    with open(path) as f:
        entries = json.load(f)

    rows = {}
    problems = []
    for e in entries:
        cfg, res = e["config"], e["results"]
        if cfg.get("benchmark") != benchmark:
            continue
        if cfg.get("cgroup_name") != "cache_ext_test":
            continue
        loader = cfg.get("policy_loader")
        if loader in rows:
            problems.append(f"duplicate entry for {loader}")
        rows[loader] = res

    missing = [l for l in EXPECTED_LOADERS if l not in rows]
    unexpected = [l for l in rows if l not in EXPECTED_LOADERS]
    if missing:
        problems.append(f"missing policies for {benchmark}: {', '.join(missing)}")
    if unexpected:
        problems.append(f"unexpected policies for {benchmark}: {', '.join(unexpected)}")

    for loader, res in rows.items():
        tput = res.get("throughput_avg")
        if tput is None or not math.isfinite(tput) or tput <= 0:
            problems.append(f"{loader}: bad throughput_avg = {tput}")

    # Table
    print(f"\n=== {benchmark} ===")
    print(f"{'policy':<22} {'tput (ops/s)':>14} {'p99 lat (ms)':>14}")
    order = sorted(rows, key=lambda l: -(rows[l].get("throughput_avg") or 0))
    for loader in order:
        res = rows[loader]
        tput = res.get("throughput_avg") or 0
        lat = latency_p99(res) / 1e6  # ns -> ms
        mark = " <-- ML" if loader == ML else ""
        print(f"{LABELS.get(loader, loader):<22} {tput:>14,.0f} {lat:>14.2f}{mark}")

    # Verdict
    ok = not problems
    if ML in rows and len(rows) > 1:
        tputs = {l: rows[l].get("throughput_avg") or 0 for l in rows}
        others = [v for l, v in tputs.items() if l != ML]
        rank = 1 + sum(1 for v in tputs.values() if v > tputs[ML])
        print(f"\nML rank: {rank}/{len(rows)} "
              f"({tputs[ML]:,.0f} ops/s vs best {max(tputs.values()):,.0f}, "
              f"worst-other {min(others):,.0f})")
        if tputs[ML] <= min(others):
            problems.append("ml_protect is the WORST policy on this workload")
            ok = False
    elif ML not in rows:
        ok = False

    for p in problems:
        print(f"WARN: {p}")
    print("\nGATE: " + ("PASS — ml_protect is not the worst; no anomalies."
                        if ok else "FAIL — see warnings above."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
