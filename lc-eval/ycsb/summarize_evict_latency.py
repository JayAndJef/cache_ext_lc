#!/usr/bin/env python3
"""Summarize raw eviction-decision latency samples captured by
collect_evict_latency.sh.

Parses "evict_lat_ns=<delta>" markers (plus the ftrace timestamp) from each
results/evict_latency/<tag>.trace file, writes the raw samples to
<tag>_samples.csv (timestamp_s, latency_ns), and prints/writes a summary
table (samples, mean, p50, p90, p99, max in microseconds).

Usage: summarize_evict_latency.py [--dir results/evict_latency]
"""

import argparse
import csv
import os
import re
import statistics
import sys

BASE = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))

TAGS = ["mru", "fifo", "s3fifo", "lhd", "sampling",
        "ml10", "ml20", "ml30", "ml40", "mlprotect"]
LABELS = {
    "mru": "MRU", "fifo": "FIFO", "s3fifo": "S3-FIFO", "lhd": "LHD",
    "sampling": "LFU (sampling 20x)",
    "ml10": "ML-rank 10x", "ml20": "ML-rank 20x",
    "ml30": "ML-rank 30x", "ml40": "ML-rank 40x",
    "mlprotect": "ML-protect",
}

# ftrace line: "<comm>-<pid> [cpu] flags <ts>: bpf_trace_printk: evict_lat_ns=123"
LINE_RE = re.compile(r"\s(\d+\.\d+):\s+\S+\s+evict_lat_ns=(\d+)")


def parse_trace(path):
    samples = []  # (timestamp_s, latency_ns)
    with open(path, errors="replace") as f:
        for line in f:
            m = LINE_RE.search(line)
            if m:
                samples.append((float(m.group(1)), int(m.group(2))))
    return samples


def pct(sorted_vals, p):
    if not sorted_vals:
        return None
    idx = min(len(sorted_vals) - 1, max(0, int(round(p / 100 * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(BASE, "results", "evict_latency"))
    args = ap.parse_args()

    rows = []
    for tag in TAGS:
        path = os.path.join(args.dir, f"{tag}.trace")
        if not os.path.exists(path):
            continue
        samples = parse_trace(path)
        csv_path = os.path.join(args.dir, f"{tag}_samples.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp_s", "latency_ns"])
            w.writerows(samples)
        if not samples:
            rows.append((LABELS[tag], 0, None, None, None, None, None))
            continue
        lats = sorted(ns for _, ns in samples)
        us = lambda v: v / 1000.0
        rows.append((LABELS[tag], len(lats), us(statistics.fmean(lats)),
                     us(pct(lats, 50)), us(pct(lats, 90)), us(pct(lats, 99)),
                     us(lats[-1])))

    hdr = "| policy | samples | mean µs | p50 µs | p90 µs | p99 µs | max µs |"
    sep = "|---|---:|---:|---:|---:|---:|---:|"
    fmt = lambda v: f"{v:,.1f}" if v is not None else "--"
    lines = [hdr, sep]
    for label, n, mean, p50, p90, p99, mx in rows:
        lines.append(f"| {label} | {n:,} | {fmt(mean)} | {fmt(p50)} | "
                     f"{fmt(p90)} | {fmt(p99)} | {fmt(mx)} |")
    table = "\n".join(lines)
    print(table)

    md_path = os.path.join(args.dir, "evict_latency.md")
    with open(md_path, "w") as f:
        f.write("# Eviction-decision latency (per evict_folios call)\n\n")
        f.write("Workload: ycsb_a, 10 GiB cgroup, 45 s warmup + 120 s timed. "
                "Raw samples in <tag>_samples.csv.\n\n")
        f.write(table + "\n")
    sum_csv = os.path.join(args.dir, "evict_latency.csv")
    with open(sum_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["policy", "samples", "mean_us", "p50_us", "p90_us", "p99_us", "max_us"])
        for r in rows:
            w.writerow(r)
    print(f"\nWrote {md_path}\nWrote {sum_csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
