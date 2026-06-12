#!/usr/bin/env python3
"""Summarize the model-policy evaluation results.

Reads results/ycsb_eval_results.json (cache_ext policies + ML) and
results/ycsb_eval_mglru.json (kernel MGLRU baseline), prints a per-workload
markdown table, writes results/ycsb_eval_summary.csv, and renders a grouped
bar chart (results/ycsb_eval_plot.png) matching the upstream cache_ext figure
layout: MGLRU (Linux), MRU, FIFO, S3-FIFO, LHD, LFU (cache_ext), ML (ours).

Usage: summarize_results.py [--results <json>] [--mglru <json>] [--no-plot]
Tolerates partial results (missing cells print as --).
"""

import argparse
import csv
import json
import os

BASE = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))

# (label, source, loader-or-None) in figure bar order. source selects the
# results file: "policies"/"ml30" share config shapes (sample_size is compiled
# in, not recorded), so variant runs live in separate files.
BARS = [
    ("MGLRU (Linux)", "mglru", None),
    ("MRU (cache_ext)", "policies", "cache_ext_mru.out"),
    ("FIFO (cache_ext)", "policies", "cache_ext_fifo.out"),
    ("S3-FIFO (cache_ext)", "policies", "cache_ext_s3fifo.out"),
    ("LHD (cache_ext)", "policies", "cache_ext_lhd.out"),
    ("LFU (cache_ext)", "policies", "cache_ext_sampling.out"),
    ("ML-protect (ours)", "policies", "cache_ext_fifo_ml_protect.out"),
    ("ML-rank 10x (ours)", "ml10", "cache_ext_ml_sampling.out"),
    ("ML-rank 20x (ours)", "policies", "cache_ext_ml_sampling.out"),
    ("ML-rank 30x (ours)", "ml30", "cache_ext_ml_sampling.out"),
    ("ML-rank 40x (ours)", "ml40", "cache_ext_ml_sampling.out"),
]
WORKLOADS = ["ycsb_a", "ycsb_b", "ycsb_c", "ycsb_d", "ycsb_e", "ycsb_f"]
# All ML variants are excluded from "best non-ML" normalization.
ML_LABELS = tuple(label for label, _, _ in BARS if "(ours)" in label)


def latency_p99(results):
    # READ p99 is 0.0 on scan-only workloads (ycsb_e); fall back to scan p99.
    lat = results.get("latency_p99") or 0.0
    if lat == 0.0:
        lat = results.get("scan_latency_p99") or 0.0
    return lat


def load(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def collect(results_path, mglru_path, variant_paths=None):
    """-> {workload: {label: {"tput": float, "p99_ms": float}}}
    variant_paths: {source_name: path} for sample-size variant files."""
    data = {w: {} for w in WORKLOADS}
    sources = {"policies": load(results_path)}
    for src_name, path in (variant_paths or {}).items():
        sources[src_name] = load(path)
    for src_name, entries in sources.items():
        for e in entries:
            cfg, res = e["config"], e["results"]
            w = cfg.get("benchmark")
            if w not in data or cfg.get("cgroup_name") != "cache_ext_test":
                continue
            for label, src, loader in BARS:
                if src == src_name and cfg.get("policy_loader") == loader:
                    data[w][label] = {"tput": res.get("throughput_avg"),
                                      "p99_ms": latency_p99(res) / 1e6}
    for e in load(mglru_path):
        cfg, res = e["config"], e["results"]
        w = cfg.get("benchmark")
        if w in data and cfg.get("cgroup_name") == "baseline_test":
            data[w]["MGLRU (Linux)"] = {"tput": res.get("throughput_avg"),
                                        "p99_ms": latency_p99(res) / 1e6}
    return data


def fmt(v, pat="{:,.0f}"):
    return pat.format(v) if v is not None else "--"


def workload_table_lines(data, w):
    labels = [b[0] for b in BARS]
    rows = data[w]
    best_non_ml = max((rows[l]["tput"] for l in rows
                       if l not in ML_LABELS + ("MGLRU (Linux)",)
                       and rows[l]["tput"]), default=None)
    mglru = rows.get("MGLRU (Linux)", {}).get("tput")
    lines = [f"\n### {w}\n",
             "| policy | tput (ops/s) | p99 lat (ms) | vs best non-ML | vs MGLRU |",
             "|---|---:|---:|---:|---:|"]
    for label in labels:
        if label not in rows:
            lines.append(f"| {label} | -- | -- | -- | -- |")
            continue
        t = rows[label]["tput"]
        rel_best = fmt(t / best_non_ml, "{:.2f}x") if t and best_non_ml else "--"
        rel_mglru = fmt(t / mglru, "{:.2f}x") if t and mglru else "--"
        lines.append(f"| {label} | {fmt(t)} | {fmt(rows[label]['p99_ms'], '{:,.2f}')} "
                     f"| {rel_best} | {rel_mglru} |")
    return lines


def ml_summary_lines(data):
    """Overall ML standing: rank and relative throughput per workload/variant."""
    lines = ["\n## ML policies — summary across workloads\n",
             "| workload | variant | tput (ops/s) | rank (of policies) | vs best non-ML | vs FIFO base | vs MGLRU |",
             "|---|---|---:|---:|---:|---:|---:|"]
    for w in WORKLOADS:
        rows = data[w]
        policy_tputs = {l: rows[l]["tput"] for l in rows
                        if l != "MGLRU (Linux)" and rows[l]["tput"]}
        non_ml = [v for l, v in policy_tputs.items() if l not in ML_LABELS]
        fifo = rows.get("FIFO (cache_ext)", {}).get("tput")
        mglru = rows.get("MGLRU (Linux)", {}).get("tput")
        for variant in ML_LABELS:
            ml = rows.get(variant, {}).get("tput")
            if not ml or not non_ml:
                lines.append(f"| {w} | {variant} | -- | -- | -- | -- | -- |")
                continue
            rank = 1 + sum(1 for v in policy_tputs.values() if v > ml)
            lines.append(f"| {w} | {variant} | {fmt(ml)} | {rank}/{len(policy_tputs)} "
                         f"| {fmt(ml / max(non_ml), '{:.2f}x')} "
                         f"| {fmt(ml / fifo, '{:.2f}x') if fifo else '--'} "
                         f"| {fmt(ml / mglru, '{:.2f}x') if mglru else '--'} |")
    return lines


def build_report(data, meta_path):
    import datetime
    lines = ["# LearnedCache ml_protect evaluation — YCSB A–F\n",
             f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}  "]
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        lines.append(f"Kernel: `{meta.get('kernel', '?')}` · cgroup memory: "
                     f"{meta.get('cgroup_memory', '?')} · iterations: {meta.get('iterations', '?')}\n")
        lines.append("\n## Setup\n")
        lines.append("- Policies: MGLRU (kernel baseline), MRU, FIFO, S3-FIFO, LHD, "
                     "LFU (`cache_ext_sampling`), ML-protect (`cache_ext_fifo_ml_protect`), "
                     "ML-rank (`cache_ext_ml_sampling`)")
        lines.append("- All ML variants use the same per-workload matched model "
                     "(binary reuse classifier). ML-protect: binary skip-in-place "
                     "protection over FIFO order. ML-rank: sampled eviction with "
                     "the model logit as the score (min-logit of each sample "
                     "group evicted), swept at 10x/20x/30x/40x oversampling.\n")
        lines.append("| workload | model | AUC | F1 |")
        lines.append("|---|---|---:|---:|")
        for w, entry in sorted(meta.get("models", {}).items()):
            m = entry.get("metrics", {})
            lines.append(f"| {w} | `{entry.get('model_file', '?')}` "
                         f"| {fmt(m.get('auc'), '{:.3f}')} | {fmt(m.get('f1'), '{:.3f}')} |")
    lines += ml_summary_lines(data)
    lines.append("\n## Per-workload results\n")
    lines.append("(`vs best non-ML` = ML throughput relative to the best classical "
                 "cache_ext policy; `vs MGLRU` = relative to the kernel MGLRU baseline.)")
    for w in WORKLOADS:
        if data[w]:
            lines += workload_table_lines(data, w)
    lines.append("\n## Figure\n")
    lines.append("![throughput by policy](ycsb_eval_plot.png)\n")
    lines.append("\n## Notes\n")
    lines.append("- 240 s timed run + 45 s warmup per config, 10 GiB cgroup, 8 CPUs, "
                 "MGLRU disabled during cache_ext policy runs.")
    lines.append("- ycsb_e p99 latency is the SCAN p99 (READ p99 is 0 on the scan-only workload).")
    lines.append("- Raw data: `ycsb_eval_results.json`, `ycsb_eval_mglru.json`, "
                 "`ycsb_eval_summary.csv`, model mapping in `ycsb_eval_meta.json`.")
    return "\n".join(lines) + "\n"


def print_tables(data):
    for w in WORKLOADS:
        if data[w]:
            print("\n".join(workload_table_lines(data, w)))


def write_csv(data, path):
    with open(path, "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["workload", "policy", "throughput_ops_s", "p99_latency_ms"])
        for w in WORKLOADS:
            for label, _, _ in BARS:
                cell = data[w].get(label)
                if cell:
                    wr.writerow([w, label, cell["tput"], round(cell["p99_ms"], 3)])
    print(f"\nWrote {path}")


def plot(data, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    labels = [b[0] for b in BARS]
    n_groups, n_bars = len(WORKLOADS), len(labels)
    x = np.arange(n_groups)
    width = 0.8 / n_bars
    colors = plt.cm.tab10(np.linspace(0, 1, n_bars))

    fig, ax = plt.subplots(figsize=(11, 6))
    for i, label in enumerate(labels):
        vals = [data[w].get(label, {}).get("tput") or 0 for w in WORKLOADS]
        pos = x - 0.4 + width * (i + 0.5)
        bars = ax.bar(pos, vals, width, label=label, color=colors[i])
        for rect, v in zip(bars, vals):
            if v > 0:
                ax.annotate(f"{v / 1000:.0f}K", (rect.get_x() + rect.get_width() / 2, v),
                            ha="center", va="bottom", fontsize=6, rotation=90,
                            xytext=(0, 1), textcoords="offset points")
    ax.set_ylabel("Throughput (ops/sec)")
    ax.set_xticks(x)
    ax.set_xticklabels([w.replace("ycsb_", "YCSB ").upper().replace("YCSB ", "YCSB\n")
                        for w in WORKLOADS])
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    print(f"Wrote {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.path.join(BASE, "results", "ycsb_eval_results.json"))
    ap.add_argument("--mglru", default=os.path.join(BASE, "results", "ycsb_eval_mglru.json"))
    ap.add_argument("--ml10", default=os.path.join(BASE, "results", "ycsb_eval_ml10.json"))
    ap.add_argument("--ml30", default=os.path.join(BASE, "results", "ycsb_eval_ml30.json"))
    ap.add_argument("--ml40", default=os.path.join(BASE, "results", "ycsb_eval_ml40.json"))
    ap.add_argument("--no-plot", action="store_true")
    ap.add_argument("--report-md",
                    default=os.path.join(BASE, "results", "ycsb_eval_report.md"),
                    help="Path for the consolidated markdown report")
    args = ap.parse_args()

    data = collect(args.results, args.mglru,
                   {"ml10": args.ml10, "ml30": args.ml30, "ml40": args.ml40})
    print_tables(data)
    write_csv(data, os.path.join(BASE, "results", "ycsb_eval_summary.csv"))
    if not args.no_plot:
        plot(data, os.path.join(BASE, "results", "ycsb_eval_plot.png"))
    report = build_report(data, os.path.join(BASE, "results", "ycsb_eval_meta.json"))
    with open(args.report_md, "w") as f:
        f.write(report)
    print(f"Wrote {args.report_md}")


if __name__ == "__main__":
    main()
